package packageupdaters

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	defaultRequirementFile = "requirements.txt"
	// Package names are case-insensitive with this prefix
	PythonPackageRegexPrefix = "(?i)"
	// Match all possible operators and versions syntax
	PythonPackageRegexSuffix = "\\s*(([\\=\\<\\>\\~]=)|([\\>\\<]))\\s*(\\.|\\d)*(\\d|(\\.\\*))(\\,\\s*(([\\=\\<\\>\\~]=)|([\\>\\<])).*\\s*(\\.|\\d)*(\\d|(\\.\\*)))?"
)

type PythonPackageUpdater struct {
	pipRequirementsFile string
	CommonPackageUpdater
}

func (py *PythonPackageUpdater) UpdateDependency(fixDetails *FixDetails) error {
	if fixDetails.IsDirectDependency {
		return py.updateDirectDependency(fixDetails)
	}

	return &ErrUnsupportedFix{
		PackageName:  fixDetails.ImpactedDependencyName,
		FixedVersion: fixDetails.SuggestedFixedVersion,
		ErrorType:    IndirectDependencyFixNotSupported,
	}
}

func (py *PythonPackageUpdater) updateDirectDependency(fixDetails *FixDetails) (err error) {
	switch fixDetails.Technology {
	case techutils.Poetry:
		return py.handlePoetry(fixDetails)
	case techutils.Pip:
		return py.handlePip(fixDetails)
	case techutils.Pipenv:
		return py.CommonPackageUpdater.UpdateDependency(fixDetails, fixDetails.Technology.GetPackageInstallationCommand())
	case techutils.Uv:
		return py.handleUv(fixDetails)
	default:
		return errors.New("unknown python package manager: " + fixDetails.Technology.GetPackageType())
	}
}

const (
	poetryLockFileName   = "poetry.lock"
	poetryPyprojectFile  = "pyproject.toml"
	poetryCommandTimeout = 5 * time.Minute
)

// handlePoetry fixes a direct dependency without going through 'poetry add', which rewrites
// whatever constraint form was declared (range, table-with-extras, group) into an exact pin,
// and without a bare 'poetry update', which is unscoped (drifts unrelated transitives) and,
// without --lock, installs into the environment. Renovate has the same problem today and
// hasn't solved it (github.com/renovatebot/renovate/discussions/41206): it runs
// 'poetry update --lock' against the constraint as-is, so it resolves to the newest version
// the constraint allows, not necessarily the fix version.
//
// Sequence, verified against Poetry 1.8.5 and 2.5.1:
//  1. Pin the dependency to the exact fix version in pyproject.toml, wherever its existing
//     declaration is (main dependencies, a [tool.poetry.group.*] table, table-form with
//     extras, or a PEP 621 native [project.dependencies] entry).
//  2. 'poetry update <pkg> --lock --no-interaction' - scoped, lock-only.
//  3. Restore pyproject.toml verbatim. If the original constraint admits the fix version,
//     this is enough: only poetry.lock changes, and the manifest stays byte-identical.
//  4. Re-sync the lock's content-hash without re-resolving ('poetry lock' on 2.x,
//     'poetry lock --no-update' on 1.x - the flag for "don't touch existing resolutions" was
//     inverted as poetry 2.0's new default).
//  5. Verify the locked version actually equals the fix version - restoring a constraint that
//     doesn't admit the fix version silently reverts the lock back to the old version, and
//     'poetry check --lock' still exits 0 in that case (verified: with jinja2 pinned "^2.11"
//     and a fix of 3.1.6, this exact sequence reverted to 2.11.3 with no error). When that
//     happens, re-apply the exact-pin from step 1 instead of the original constraint and
//     re-sync again - the pin form itself already admits the fix version by construction.
func (py *PythonPackageUpdater) handlePoetry(fixDetails *FixDetails) error {
	descriptorPaths := py.CollectVulnerabilityDescriptorPaths(fixDetails, []string{poetryPyprojectFile}, nil)
	if len(descriptorPaths) == 0 {
		return fmt.Errorf("no descriptor evidence was found for package %s", fixDetails.ImpactedDependencyName)
	}

	var joinedErr error
	var failingDescriptors []string
	for _, descriptorPath := range descriptorPaths {
		if fixErr := py.fixPoetryDependency(fixDetails, descriptorPath); fixErr != nil {
			var unsupported *ErrUnsupportedFix
			if errors.As(fixErr, &unsupported) {
				return fixErr
			}
			failedFixErrorMsg := fmt.Errorf("failed to fix '%s' in descriptor '%s': %w", fixDetails.ImpactedDependencyName, descriptorPath, fixErr)
			log.Warn(failedFixErrorMsg.Error())
			joinedErr = errors.Join(joinedErr, failedFixErrorMsg)
			failingDescriptors = append(failingDescriptors, descriptorPath)
		}
	}
	if joinedErr != nil {
		return fmt.Errorf("encountered errors while fixing '%s' vulnerability in descriptors [%s]: %w", fixDetails.ImpactedDependencyName, strings.Join(failingDescriptors, ", "), joinedErr)
	}
	return nil
}

func (py *PythonPackageUpdater) fixPoetryDependency(fixDetails *FixDetails, descriptorPath string) error {
	rootDir := filepath.Dir(descriptorPath)

	majorVersion, err := poetryMajorVersion(rootDir)
	if err != nil {
		return &ErrUnsupportedFix{
			PackageName:  fixDetails.ImpactedDependencyName,
			FixedVersion: fixDetails.SuggestedFixedVersion,
			ErrorType:    UnsupportedFixReason,
			Reason:       fmt.Sprintf("could not determine a usable poetry version for the project at '%s': %s", rootDir, err.Error()),
		}
	}
	if majorVersion != 1 && majorVersion != 2 {
		return &ErrUnsupportedFix{
			PackageName:  fixDetails.ImpactedDependencyName,
			FixedVersion: fixDetails.SuggestedFixedVersion,
			ErrorType:    UnsupportedFixReason,
			Reason:       fmt.Sprintf("poetry major version %d is not supported (only 1.x and 2.x are)", majorVersion),
		}
	}

	originalManifest, err := os.ReadFile(descriptorPath)
	if err != nil {
		return fmt.Errorf("failed to read '%s': %w", descriptorPath, err)
	}
	lockPath := filepath.Join(rootDir, poetryLockFileName)
	originalLock, lockExisted, err := readOptionalFile(lockPath)
	if err != nil {
		return fmt.Errorf("failed to read '%s': %w", lockPath, err)
	}

	pinnedManifest, err := pinPoetryDependency(string(originalManifest), fixDetails.ImpactedDependencyName, fixDetails.SuggestedFixedVersion)
	if err != nil {
		return err
	}

	rollback := func(cause error) error {
		var rollbackErr error
		//#nosec G306 -- 0644 is correct for a checked-out source file.
		if werr := os.WriteFile(descriptorPath, originalManifest, 0644); werr != nil {
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("failed to rollback '%s': %w", descriptorPath, werr))
		}
		if werr := restoreOptionalFile(lockPath, originalLock, lockExisted); werr != nil {
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("failed to rollback '%s': %w", lockPath, werr))
		}
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback after error: %w (original error: %v)", rollbackErr, cause)
		}
		return cause
	}

	//#nosec G306 -- 0644 is correct for a checked-out source file.
	if err = os.WriteFile(descriptorPath, []byte(pinnedManifest), 0644); err != nil {
		return fmt.Errorf("failed to write '%s': %w", descriptorPath, err)
	}
	if err = runPoetryCommand(rootDir, "update", fixDetails.ImpactedDependencyName, "--lock", "--no-interaction"); err != nil {
		return rollback(fmt.Errorf("'poetry update %s --lock' failed: %w", fixDetails.ImpactedDependencyName, err))
	}

	//#nosec G306 -- 0644 is correct for a checked-out source file.
	if err = os.WriteFile(descriptorPath, originalManifest, 0644); err != nil {
		return rollback(fmt.Errorf("failed to restore '%s' before re-syncing the lock hash: %w", descriptorPath, err))
	}
	if err = poetryLockSyncHash(rootDir, majorVersion); err != nil {
		return rollback(fmt.Errorf("failed to re-sync the lock hash: %w", err))
	}
	lockedVersion, err := lockedPackageVersion(lockPath, fixDetails.ImpactedDependencyName)
	if err != nil {
		return rollback(err)
	}

	if lockedVersion != fixDetails.SuggestedFixedVersion {
		//#nosec G306 -- 0644 is correct for a checked-out source file.
		if err = os.WriteFile(descriptorPath, []byte(pinnedManifest), 0644); err != nil {
			return rollback(fmt.Errorf("failed to re-apply the widened constraint to '%s': %w", descriptorPath, err))
		}
		if err = poetryLockSyncHash(rootDir, majorVersion); err != nil {
			return rollback(fmt.Errorf("failed to re-sync the lock hash after widening: %w", err))
		}
		if lockedVersion, err = lockedPackageVersion(lockPath, fixDetails.ImpactedDependencyName); err != nil {
			return rollback(err)
		}
		if lockedVersion != fixDetails.SuggestedFixedVersion {
			return rollback(fmt.Errorf("locked version '%s' does not match fix version '%s' even after widening the constraint", lockedVersion, fixDetails.SuggestedFixedVersion))
		}
	}

	log.Debug(fmt.Sprintf("Successfully updated '%s' from version '%s' to '%s' in descriptor '%s'", fixDetails.ImpactedDependencyName, fixDetails.ImpactedDependencyVersion, fixDetails.SuggestedFixedVersion, descriptorPath))
	return nil
}

// pinPoetryDependency rewrites name's existing declaration to an exact pin at fixedVersion,
// wherever it is: a bare string constraint, a table with extras (only the version= field is
// touched), or a PEP 621 native array entry (Poetry 2.x's [project.dependencies]).
func pinPoetryDependency(manifest, name, fixedVersion string) (string, error) {
	escapedName := regexp.QuoteMeta(name)
	quotedFixed := `"` + fixedVersion + `"`

	if tableRe := regexp.MustCompile(`(?im)^(\s*` + escapedName + `\s*=\s*\{[^}]*?version\s*=\s*)"[^"]*"`); tableRe.MatchString(manifest) {
		return tableRe.ReplaceAllString(manifest, "${1}"+quotedFixed), nil
	}
	if bareRe := regexp.MustCompile(`(?im)^(\s*` + escapedName + `\s*=\s*)"[^"]*"`); bareRe.MatchString(manifest) {
		return bareRe.ReplaceAllString(manifest, "${1}"+quotedFixed), nil
	}
	if arrayRe := regexp.MustCompile(PythonPackageRegexPrefix + pythonDependencyLeftBoundary + escapedName + PythonPackageRegexSuffix); arrayRe.MatchString(manifest) {
		fixedPackage := strings.ToLower(name) + "==" + fixedVersion
		return arrayRe.ReplaceAllString(manifest, "${1}"+fixedPackage), nil
	}
	return "", fmt.Errorf("impacted package %s not found in pyproject.toml, fix failed", name)
}

// lockedPackageVersion reads the version poetry.lock actually recorded for name, so the fix
// can be asserted directly rather than trusting 'poetry check --lock's exit code - that check
// only validates the lock is consistent with the manifest, not that it holds the fix version.
func lockedPackageVersion(lockPath, name string) (string, error) {
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return "", fmt.Errorf("failed to read '%s' to verify the locked version: %w", lockPath, err)
	}
	nameRe := regexp.MustCompile(`(?im)^name\s*=\s*"` + regexp.QuoteMeta(name) + `"\s*\n\s*version\s*=\s*"([^"]+)"`)
	match := nameRe.FindStringSubmatch(string(data))
	if match == nil {
		return "", fmt.Errorf("could not find package '%s' in '%s' to verify the fix", name, lockPath)
	}
	return match[1], nil
}

var poetryVersionRegex = regexp.MustCompile(`(\d+)\.\d+\.\d+`)

// poetryMajorVersion is required because the lock-hash-resync flag inverted meaning between
// major versions: 'poetry lock --no-update' on 1.x, plain 'poetry lock' on 2.x (--no-update
// was removed; --regenerate is 2.x's new opt-in for a full re-resolve).
func poetryMajorVersion(dir string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	//#nosec G204 -- False positive - poetry is a known package manager binary, not user-controlled input.
	cmd := exec.CommandContext(ctx, techutils.Poetry.GetExecCommandName(), "--version")
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("'poetry --version' failed: %w\nOutput: %s", err, output)
	}
	match := poetryVersionRegex.FindStringSubmatch(string(output))
	if match == nil {
		return 0, fmt.Errorf("could not parse a version out of 'poetry --version' output: %s", output)
	}
	major, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, fmt.Errorf("could not parse poetry major version '%s': %w", match[1], err)
	}
	return major, nil
}

func poetryLockSyncHash(dir string, majorVersion int) error {
	if majorVersion == 1 {
		return runPoetryCommand(dir, "lock", "--no-update")
	}
	return runPoetryCommand(dir, "lock")
}

// runPoetryCommand never sets cmd.Env: poetry needs to inherit the parent process's
// environment as-is for private-index credentials (which the customer's own CI already
// provides) to be picked up, rather than being supplied or overridden here.
func runPoetryCommand(dir string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), poetryCommandTimeout)
	defer cancel()
	fullCommand := "poetry " + strings.Join(args, " ")
	log.Debug(fmt.Sprintf("Running '%s' in '%s'", fullCommand, dir))
	//#nosec G204 -- False positive - the subprocess only runs after the user's approval.
	cmd := exec.CommandContext(ctx, techutils.Poetry.GetExecCommandName(), args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("'%s' timed out after %v", fullCommand, poetryCommandTimeout)
	}
	if err != nil {
		return fmt.Errorf("'%s' failed: %w\nOutput: %s", fullCommand, err, output)
	}
	return nil
}

func (py *PythonPackageUpdater) handlePip(fixDetails *FixDetails) (err error) {
	var fixedFile string
	fixedPackage := fixDetails.ImpactedDependencyName + "==" + fixDetails.SuggestedFixedVersion
	currentFile, err := py.tryGetRequirementFile()
	if err != nil {
		return errors.New("failed to read pip requirements file: " + err.Error())
	}
	re := regexp.MustCompile(PythonPackageRegexPrefix + "(" + fixDetails.ImpactedDependencyName + "|" + strings.ToLower(fixDetails.ImpactedDependencyName) + ")" + PythonPackageRegexSuffix)
	if packageToReplace := re.FindString(currentFile); packageToReplace != "" {
		fixedFile = strings.Replace(currentFile, packageToReplace, strings.ToLower(fixedPackage), 1)
	}
	if fixedFile == "" {
		return fmt.Errorf("impacted package %s not found, fix failed", fixDetails.ImpactedDependencyName)
	}
	//#nosec G703 -- False positive - the path is determined by internal file scanning, not user input, and was already validated by the preceding Stat call.
	if err = os.WriteFile(py.pipRequirementsFile, []byte(fixedFile), 0600); err != nil {
		err = fmt.Errorf("an error occurred while writing the fixed version of %s to the requirements file:\n%s", fixDetails.SuggestedFixedVersion, err.Error())
	}
	return
}

// pythonDependencyLeftBoundary requires a match to start at the beginning of a TOML
// array entry or the start of the file, not merely as a suffix of a longer name - without
// it, a fix for "attrs" would also match inside "cattrs".
const pythonDependencyLeftBoundary = `(^|[\s"'\[,])`

func (py *PythonPackageUpdater) handleUv(fixDetails *FixDetails) (err error) {
	const pyprojectFile = "pyproject.toml"
	currentFile, err := py.tryReadRequirementFile(pyprojectFile)
	if err != nil {
		return errors.New("failed to read pyproject.toml: " + err.Error())
	}
	escapedName := regexp.QuoteMeta(fixDetails.ImpactedDependencyName)
	re := regexp.MustCompile(PythonPackageRegexPrefix + pythonDependencyLeftBoundary + escapedName + PythonPackageRegexSuffix)
	if !re.MatchString(currentFile) {
		return fmt.Errorf("impacted package %s not found, fix failed", fixDetails.ImpactedDependencyName)
	}
	fixedPackage := strings.ToLower(fixDetails.ImpactedDependencyName) + "==" + fixDetails.SuggestedFixedVersion
	// ReplaceAllString, not just the first match: the same package can be pinned in more
	// than one place (e.g. [project].dependencies and a [dependency-groups] table), and
	// leaving one occurrence behind makes 'uv lock' fail as unsatisfiable.
	fixedFile := re.ReplaceAllString(currentFile, "${1}"+fixedPackage)

	//#nosec G703 -- False positive - the path is determined by internal file scanning, not user input, and was already validated by the preceding read.
	if err = os.WriteFile(pyprojectFile, []byte(fixedFile), 0600); err != nil {
		return fmt.Errorf("an error occurred while writing the fixed version of %s to pyproject.toml:\n%s", fixDetails.SuggestedFixedVersion, err.Error())
	}

	if lockErr := runPackageMangerCommand(techutils.Uv.GetExecCommandName(), techutils.Uv.String(), []string{"lock", "--upgrade-package", fixDetails.ImpactedDependencyName}); lockErr != nil {
		//#nosec G306 -- 0600 matches the permissions used for the write above.
		if rollbackErr := os.WriteFile(pyprojectFile, []byte(currentFile), 0600); rollbackErr != nil {
			return fmt.Errorf("failed to rollback pyproject.toml after uv lock failure: %w (original error: %v)", rollbackErr, lockErr)
		}
		return lockErr
	}
	return nil
}

func (py *PythonPackageUpdater) tryGetRequirementFile() (string, error) {
	if py.pipRequirementsFile != "" {
		fileContent, err := py.tryReadRequirementFile(py.pipRequirementsFile)
		if err != nil {
			return "", err
		}
		return fileContent, nil
	} else {
		py.pipRequirementsFile = "setup.py"
		fileContent, err := py.tryReadRequirementFile(py.pipRequirementsFile)
		if err != nil {
			py.pipRequirementsFile = "requirements.txt"
			fileContent, err = py.tryReadRequirementFile(py.pipRequirementsFile)
			if err != nil {
				return "", err
			}
			return fileContent, nil
		}
		return fileContent, nil
	}
}

func (py *PythonPackageUpdater) tryReadRequirementFile(file string) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	fullPath := filepath.Join(wd, file)
	if !strings.HasPrefix(filepath.Clean(fullPath), wd) {
		return "", errors.New("wrong requirements file input: " + fullPath)
	}
	data, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		return "", errors.New("an error occurred while attempting to read the requirements file:\n" + err.Error())
	}
	return string(data), nil
}
