package packageupdaters

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jfrog/jfrog-client-go/utils/log"
)

// nugetProjectFileSuffixes are matched case-insensitively, since MSBuild project file suffixes
// aren't guaranteed to be written in any particular casing.
var nugetProjectFileSuffixes = []string{".csproj", ".fsproj", ".vbproj"}

const (
	// (?i) accounts for MSBuild element names being case-insensitive (e.g. <packagereference> is
	// just as valid as <PackageReference>), even though this casing is rare in practice.
	nugetPackageReferenceElementPattern = `(?is)<PackageReference\b[^>]*/>|<PackageReference\b[^>]*[^/]>.*?</PackageReference>`
	nugetKeyAttrPattern                 = `(?i)\b(?:Include|Update)\s*=\s*["']%s["']`
	// nugetVersionAttrPattern matches whatever is already inside Version="...", including an
	// MSBuild property reference like "$(FooVersion)" - such a reference gets overwritten with the
	// literal fixed version rather than resolved and updated at its property definition. That's a
	// deliberate simplification, and a real behavior change versus how MSBuild itself would resolve
	// it; Maven's updater handles the analogous ${property} case by updating the definition instead.
	nugetVersionAttrPattern         = `(?is)(\bVersion\s*=\s*["'])[^"']*(["'])`
	nugetVersionElementPattern      = `(?is)(<Version>)[^<]*(</Version>)`
	nugetVersionOverrideAttrPattern = `(?is)(\bVersionOverride\s*=\s*["'])[^"']*(["'])`

	nugetPackageVersionElementPattern = `(?s)<PackageVersion\b[^>]*/>|<PackageVersion\b[^>]*[^/]>.*?</PackageVersion>`
	nugetPackageVersionKeyAttrPattern = `(?i)\bInclude\s*=\s*["']%s["']`
	nugetDirectoryPackagesPropsName   = "Directory.Packages.props"

	nugetLockFileName = "packages.lock.json"
	nugetObjDirName   = "obj"

	nugetRestoreForceEvaluateFlag = "--force-evaluate"
	// --no-dependencies keeps a fix scoped to the touched project's own lock file, instead of also
	// restoring (and diffing) every project it references via ProjectReference - a deliberate
	// divergence from what Renovate/Dependabot themselves pass.
	//
	// Known limitation: if the bumped package's transitive dependencies are only pulled in through
	// a referenced project (not the touched project itself), that referenced project's own
	// packages.lock.json can end up stale relative to the new resolution, since --no-dependencies
	// prevents restore from touching it at all.
	nugetRestoreNoDependenciesFlag = "--no-dependencies"
)

// NugetRestoreEnvVars suppresses first-run banner noise and telemetry prompts observed when
// invoking a freshly-installed dotnet CLI, on top of the inherited environment.
var NugetRestoreEnvVars = map[string]string{
	"DOTNET_NOLOGO":                     "1",
	"DOTNET_CLI_TELEMETRY_OPTOUT":       "1",
	"DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
}

type NugetPackageUpdater struct {
	CommonPackageUpdater
}

func (n *NugetPackageUpdater) UpdateDependency(fixDetails *FixDetails) error {
	if !fixDetails.IsDirectDependency {
		return &ErrUnsupportedFix{
			PackageName:  fixDetails.ImpactedDependencyName,
			FixedVersion: fixDetails.SuggestedFixedVersion,
			ErrorType:    IndirectDependencyFixNotSupported,
		}
	}

	projectFilePaths := collectProjectFilePaths(fixDetails)
	if len(projectFilePaths) == 0 {
		return fmt.Errorf("no NuGet project locations found for %s - Components array is empty or missing Location data", fixDetails.ImpactedDependencyName)
	}
	log.Verbose(fmt.Sprintf("Found vulnerability %s occurrences for component %s in %s", fixDetails.IssueId, fixDetails.ImpactedDependencyVersion, strings.Join(projectFilePaths, ", ")))

	originalWd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	var fixErrors error
	var failingDescriptors []string
	for _, projectFilePath := range projectFilePaths {
		if fixErr := n.fixVulnerabilityAndRestore(projectFilePath, fixDetails.ImpactedDependencyName, fixDetails.SuggestedFixedVersion, originalWd); fixErr != nil {
			log.Warn(fixErr.Error())
			fixErrors = errors.Join(fixErrors, fmt.Errorf("failed to fix '%s' in descriptor '%s': %w", fixDetails.ImpactedDependencyName, projectFilePath, fixErr))
			failingDescriptors = append(failingDescriptors, projectFilePath)
		} else {
			log.Debug("Updated successfully " + projectFilePath)
		}
	}

	if fixErrors != nil {
		return fmt.Errorf("encountered errors while fixing '%s' vulnerability in descriptors [%s]: %w", fixDetails.ImpactedDependencyName, strings.Join(failingDescriptors, ", "), fixErrors)
	}
	return nil
}

func collectProjectFilePaths(fixDetails *FixDetails) []string {
	var paths []string
	for _, path := range GetVulnerabilityLocations(fixDetails, []string{}, []string{}) {
		if hasNugetProjectFileSuffix(path) {
			paths = append(paths, path)
		}
	}
	return paths
}

func hasNugetProjectFileSuffix(path string) bool {
	lowerPath := strings.ToLower(path)
	for _, suffix := range nugetProjectFileSuffixes {
		if strings.HasSuffix(lowerPath, suffix) {
			return true
		}
	}
	return false
}

func (n *NugetPackageUpdater) fixVulnerabilityAndRestore(projectFilePath, packageName, fixedVersion, originalWd string) error {
	//#nosec G304 -- projectFilePath from descriptor discovery in the scanned repository.
	originalProjectFile, err := os.ReadFile(projectFilePath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", projectFilePath, err)
	}

	updatedProjectFile, fixErr := updatePackageReferenceVersion(originalProjectFile, packageName, fixedVersion)
	if fixErr != nil {
		var unsupportedErr *ErrUnsupportedFix
		if errors.As(fixErr, &unsupportedErr) && unsupportedErr.ErrorType == NoInlineVersionFixNotSupported {
			return n.fixViaDirectoryPackagesProps(projectFilePath, packageName, fixedVersion, originalWd)
		}
		return fmt.Errorf("%w in %s", fixErr, projectFilePath)
	}

	//#nosec G703 G306 -- projectFilePath from scan workflow; 0644 for VCS-tracked sources.
	if err = os.WriteFile(projectFilePath, updatedProjectFile, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", projectFilePath, err)
	}

	lockFilePath := filepath.Join(filepath.Dir(projectFilePath), nugetLockFileName)
	//#nosec G304 -- lockFilePath is derived from projectFilePath, itself from descriptor discovery.
	originalLockFile, err := os.ReadFile(lockFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			// No lock file for this project - nothing further to regenerate.
			return nil
		}
		return rollbackProjectFile(projectFilePath, originalProjectFile, fmt.Errorf("failed to read %s: %w", lockFilePath, err))
	}

	absLockFilePath := lockFilePath
	if !filepath.IsAbs(absLockFilePath) {
		absLockFilePath = filepath.Join(originalWd, absLockFilePath)
	}
	lockFileTracked, checkErr := IsFileTrackedByGit(absLockFilePath, originalWd)
	if checkErr != nil {
		log.Debug(fmt.Sprintf("Failed to check if lock file is tracked in git: %s. Proceeding with lock file regeneration.", checkErr.Error()))
		lockFileTracked = true
	}
	if !lockFileTracked {
		log.Debug(fmt.Sprintf("Lock file '%s' is not tracked in git, skipping lock file regeneration", lockFilePath))
		return nil
	}

	if err = n.runDotnetRestore(projectFilePath); err != nil {
		log.Warn(fmt.Sprintf("Failed to regenerate lock file after updating '%s' to version '%s': %s. Rolling back...", packageName, fixedVersion, err.Error()))
		return rollbackProjectFileAndLock(projectFilePath, originalProjectFile, lockFilePath, originalLockFile, err)
	}
	return nil
}

func (n *NugetPackageUpdater) fixViaDirectoryPackagesProps(projectFilePath, packageName, fixedVersion, originalWd string) error {
	unsupported := &ErrUnsupportedFix{
		PackageName:  packageName,
		FixedVersion: fixedVersion,
		ErrorType:    NoInlineVersionFixNotSupported,
	}

	propsPath, originalProps, err := resolveDirectoryPackagesProps(filepath.Dir(projectFilePath), originalWd)
	if err != nil {
		return fmt.Errorf("%w in %s", err, projectFilePath)
	}
	if propsPath == "" {
		return unsupported
	}

	updatedProps, fixedAny := updatePackageVersionEntry(originalProps, packageName, fixedVersion)
	if !fixedAny {
		return unsupported
	}

	//#nosec G703 G306 -- propsPath resolved from descriptor discovery in the scanned repository.
	if err = os.WriteFile(propsPath, updatedProps, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", propsPath, err)
	}

	projectDir := filepath.Dir(projectFilePath)
	lockFilePath := filepath.Join(projectDir, nugetLockFileName)
	//#nosec G304 -- lockFilePath is derived from projectFilePath, itself from descriptor discovery.
	originalLockFile, err := os.ReadFile(lockFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return rollbackProjectFile(propsPath, originalProps, fmt.Errorf("failed to read %s: %w", lockFilePath, err))
	}

	lockFileTracked, checkErr := IsFileTrackedByGit(lockFilePath, originalWd)
	if checkErr != nil {
		log.Debug(fmt.Sprintf("Failed to check if lock file is tracked in git: %s. Proceeding with lock file regeneration.", checkErr.Error()))
		lockFileTracked = true
	}
	if !lockFileTracked {
		log.Debug(fmt.Sprintf("Lock file '%s' is not tracked in git, skipping lock file regeneration", lockFilePath))
		return nil
	}

	if err = n.runDotnetRestore(projectFilePath); err != nil {
		log.Warn(fmt.Sprintf("Failed to regenerate lock file after updating '%s' to version '%s': %s. Rolling back...", packageName, fixedVersion, err.Error()))
		return rollbackProjectFileAndLock(propsPath, originalProps, lockFilePath, originalLockFile, err)
	}
	return nil
}

func (n *NugetPackageUpdater) runDotnetRestore(projectFilePath string) error {
	objDir := filepath.Join(filepath.Dir(projectFilePath), nugetObjDirName)
	objDirExisted := dirExists(objDir)
	defer func() {
		if objDirExisted {
			return
		}
		if cleanupErr := os.RemoveAll(objDir); cleanupErr != nil {
			log.Warn(fmt.Sprintf("Failed to remove restore-generated '%s': %s", objDir, cleanupErr.Error()))
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), nodePackageManagerInstallTimeout)
	defer cancel()

	//#nosec G204 -- projectFilePath from descriptor discovery; runs only after user approval.
	cmd := exec.CommandContext(ctx, "dotnet", "restore", projectFilePath, nugetRestoreForceEvaluateFlag, nugetRestoreNoDependenciesFlag)
	cmd.Env = n.BuildEnvWithOverrides(NugetRestoreEnvVars)
	log.Debug(fmt.Sprintf("Running 'dotnet restore %s %s %s'", projectFilePath, nugetRestoreForceEvaluateFlag, nugetRestoreNoDependenciesFlag))

	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		log.Debug(fmt.Sprintf("dotnet restore output:\n%s", string(output)))
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("dotnet restore timed out after %v", nodePackageManagerInstallTimeout)
	}
	if err != nil {
		return fmt.Errorf("dotnet restore failed: %s\n%s", err.Error(), output)
	}
	return nil
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func rollbackProjectFile(projectFilePath string, originalProjectFile []byte, origErr error) error {
	//#nosec G703 G306 -- projectFilePath from scan workflow; 0644 for VCS-tracked sources.
	if rollbackErr := os.WriteFile(projectFilePath, originalProjectFile, 0644); rollbackErr != nil {
		return fmt.Errorf("failed to rollback '%s': %w (original error: %v)", projectFilePath, rollbackErr, origErr)
	}
	return origErr
}

func rollbackProjectFileAndLock(projectFilePath string, originalProjectFile []byte, lockFilePath string, originalLockFile []byte, origErr error) error {
	//#nosec G703 G306 -- projectFilePath from scan workflow; 0644 for VCS-tracked sources.
	if rollbackErr := os.WriteFile(projectFilePath, originalProjectFile, 0644); rollbackErr != nil {
		return fmt.Errorf("failed to rollback '%s': %w (original error: %v)", projectFilePath, rollbackErr, origErr)
	}
	//#nosec G703 G306 -- lockFilePath derived from projectFilePath, from the same scan workflow.
	if rollbackErr := os.WriteFile(lockFilePath, originalLockFile, 0644); rollbackErr != nil {
		return fmt.Errorf("failed to rollback '%s': %w (original error: %v)", lockFilePath, rollbackErr, origErr)
	}
	return origErr
}

func updatePackageReferenceVersion(content []byte, packageName, fixedVersion string) ([]byte, error) {
	element := regexp.MustCompile(nugetPackageReferenceElementPattern)
	keyAttr := regexp.MustCompile(fmt.Sprintf(nugetKeyAttrPattern, regexp.QuoteMeta(packageName)))
	versionAttr := regexp.MustCompile(nugetVersionAttrPattern)
	versionElement := regexp.MustCompile(nugetVersionElementPattern)
	versionOverrideAttr := regexp.MustCompile(nugetVersionOverrideAttrPattern)

	var fixedAny, foundWithoutVersion bool
	updatedContent := element.ReplaceAllFunc(content, func(match []byte) []byte {
		if !keyAttr.Match(match) {
			return match
		}
		switch {
		case versionAttr.Match(match):
			fixedAny = true
			return versionAttr.ReplaceAll(match, []byte("${1}"+fixedVersion+"${2}"))
		case versionElement.Match(match):
			fixedAny = true
			return versionElement.ReplaceAll(match, []byte("${1}"+fixedVersion+"${2}"))
		case versionOverrideAttr.Match(match):
			fixedAny = true
			return versionOverrideAttr.ReplaceAll(match, []byte("${1}"+fixedVersion+"${2}"))
		default:
			foundWithoutVersion = true
			return match
		}
	})

	if foundWithoutVersion {
		return nil, &ErrUnsupportedFix{
			PackageName:  packageName,
			FixedVersion: fixedVersion,
			ErrorType:    NoInlineVersionFixNotSupported,
		}
	}
	if fixedAny {
		return updatedContent, nil
	}
	return nil, fmt.Errorf("dependency %s not found", packageName)
}

func updatePackageVersionEntry(content []byte, packageName, fixedVersion string) ([]byte, bool) {
	element := regexp.MustCompile(nugetPackageVersionElementPattern)
	keyAttr := regexp.MustCompile(fmt.Sprintf(nugetPackageVersionKeyAttrPattern, regexp.QuoteMeta(packageName)))
	versionAttr := regexp.MustCompile(nugetVersionAttrPattern)
	versionElement := regexp.MustCompile(nugetVersionElementPattern)

	var fixedAny bool
	updatedContent := element.ReplaceAllFunc(content, func(match []byte) []byte {
		if !keyAttr.Match(match) {
			return match
		}
		switch {
		case versionAttr.Match(match):
			fixedAny = true
			return versionAttr.ReplaceAll(match, []byte("${1}"+fixedVersion+"${2}"))
		case versionElement.Match(match):
			fixedAny = true
			return versionElement.ReplaceAll(match, []byte("${1}"+fixedVersion+"${2}"))
		default:
			return match
		}
	})
	return updatedContent, fixedAny
}

func resolveDirectoryPackagesProps(projectDir, repoRoot string) (path string, content []byte, err error) {
	absRepoRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		return "", nil, fmt.Errorf("failed to resolve absolute path for %s: %w", repoRoot, err)
	}
	dir, err := filepath.Abs(projectDir)
	if err != nil {
		return "", nil, fmt.Errorf("failed to resolve absolute path for %s: %w", projectDir, err)
	}

	for {
		candidate := filepath.Join(dir, nugetDirectoryPackagesPropsName)
		//#nosec G304 -- candidate is built from projectDir/repoRoot, from descriptor discovery.
		candidateContent, readErr := os.ReadFile(candidate)
		if readErr == nil {
			return candidate, candidateContent, nil
		}
		if !os.IsNotExist(readErr) {
			return "", nil, fmt.Errorf("failed to read %s: %w", candidate, readErr)
		}
		if dir == absRepoRoot {
			return "", nil, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", nil, nil
		}
		dir = parent
	}
}
