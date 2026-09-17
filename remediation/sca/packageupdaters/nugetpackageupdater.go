package packageupdaters

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
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
	nugetVersionAttrPattern            = `(?is)(\bVersion\s*=\s*["'])[^"']*(["'])`
	nugetVersionElementPattern         = `(?is)(<Version>)[^<]*(</Version>)`
	nugetVersionOverrideAttrPattern    = `(?is)(\bVersionOverride\s*=\s*["'])[^"']*(["'])`
	nugetVersionOverrideElementPattern = `(?is)(<VersionOverride>)[^<]*(</VersionOverride>)`

	nugetPackageVersionElementPattern  = `(?is)<PackageVersion\b[^>]*/>|<PackageVersion\b[^>]*[^/]>.*?</PackageVersion>`
	nugetPackageVersionKeyAttrPattern  = `(?i)\b(?:Include|Update)\s*=\s*["']%s["']`
	nugetDirectoryPackagesPropsName    = "Directory.Packages.props"
	nugetDirectoryBuildPropsName       = "Directory.Build.props"
	nugetDirectoryBuildTargetsName     = "Directory.Build.targets"
	nugetImportProjectAttrPattern      = `(?i)<Import\b[^>]*\bProject\s*=\s*["']([^"']+)["']`
	nugetManageCpmFalsePattern         = `(?is)<ManagePackageVersionsCentrally>\s*false\s*</ManagePackageVersionsCentrally>`
	nugetManageCpmTruePattern          = `(?is)<ManagePackageVersionsCentrally>\s*true\s*</ManagePackageVersionsCentrally>`
	nugetMSBuildThisFileDirectoryMacro = "$(MSBuildThisFileDirectory)"

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
	seen := make(map[string]struct{})
	var paths []string
	add := func(path string) {
		if path == "" {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}

	for _, path := range GetVulnerabilityLocations(fixDetails, []string{}, []string{}) {
		switch {
		case hasNugetProjectFileSuffix(path):
			add(path)
		case strings.EqualFold(filepath.Base(path), nugetLockFileName):
			projectPath, err := findProjectFileInDir(filepath.Dir(path))
			if err != nil {
				log.Debug(fmt.Sprintf("Failed to resolve project file next to '%s': %s", path, err.Error()))
				continue
			}
			add(projectPath)
		}
	}
	return paths
}

func findProjectFileInDir(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("failed to read directory %s: %w", dir, err)
	}
	var matches []string
	for _, entry := range entries {
		if !entry.IsDir() && hasNugetProjectFileSuffix(entry.Name()) {
			matches = append(matches, filepath.Join(dir, entry.Name()))
		}
	}
	if len(matches) == 0 {
		return "", nil
	}
	if len(matches) > 1 {
		sort.Strings(matches)
		log.Debug(fmt.Sprintf("Skipping lock file in '%s': found multiple project files (%s)", dir, strings.Join(matches, ", ")))
		return "", nil
	}
	return matches[0], nil
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
	if isMixedInlineAndNonInline(fixErr) {
		return fmt.Errorf("%w in %s", fixErr, projectFilePath)
	}
	if fixErr != nil {
		return n.fixViaVersionSource(projectFilePath, packageName, fixedVersion, originalWd)
	}

	//#nosec G703 G306 -- projectFilePath from scan workflow; 0644 for VCS-tracked sources.
	if err = os.WriteFile(projectFilePath, updatedProjectFile, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", projectFilePath, err)
	}

	return n.restoreLockFileAfterWrite(projectFilePath, projectFilePath, originalProjectFile, originalWd, packageName, fixedVersion)
}

func (n *NugetPackageUpdater) fixViaVersionSource(projectFilePath, packageName, fixedVersion, originalWd string) error {
	err := n.fixViaDirectoryPackagesProps(projectFilePath, packageName, fixedVersion, originalWd)
	if !isUnsupportedNoInlineVersion(err) {
		return err
	}
	return n.fixViaDirectoryBuildProps(projectFilePath, packageName, fixedVersion, originalWd)
}

func isUnsupportedNoInlineVersion(err error) bool {
	var unsupportedErr *ErrUnsupportedFix
	return errors.As(err, &unsupportedErr) && unsupportedErr.ErrorType == NoInlineVersionFixNotSupported
}

func isMixedInlineAndNonInline(err error) bool {
	var unsupportedErr *ErrUnsupportedFix
	return errors.As(err, &unsupportedErr) && unsupportedErr.ErrorType == MixedInlineAndNonInlineVersionFixNotSupported
}

func (n *NugetPackageUpdater) fixViaDirectoryPackagesProps(projectFilePath, packageName, fixedVersion, originalWd string) error {
	unsupported := &ErrUnsupportedFix{
		PackageName:  packageName,
		FixedVersion: fixedVersion,
		ErrorType:    NoInlineVersionFixNotSupported,
	}

	propsPath, originalProps, err := resolveDirectoryFile(filepath.Dir(projectFilePath), originalWd, nugetDirectoryPackagesPropsName)
	if err != nil {
		return fmt.Errorf("%w in %s", err, projectFilePath)
	}
	if propsPath == "" {
		return unsupported
	}

	absRepoRoot, err := filepath.Abs(originalWd)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute path for %s: %w", originalWd, err)
	}

	if isCentralPackageManagementDisabledInContext(projectFilePath, originalProps, absRepoRoot) {
		return unsupported
	}

	targetPath, originalContent, updatedContent, fixedAny, err := resolvePackageVersionUpdate(propsPath, originalProps, packageName, fixedVersion, absRepoRoot)
	if err != nil {
		return fmt.Errorf("%w in %s", err, projectFilePath)
	}
	if !fixedAny {
		return unsupported
	}

	//#nosec G703 G306 -- targetPath resolved from descriptor discovery in the scanned repository.
	if err = os.WriteFile(targetPath, updatedContent, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", targetPath, err)
	}

	return n.restoreLockFileAfterWrite(projectFilePath, targetPath, originalContent, originalWd, packageName, fixedVersion)
}

func (n *NugetPackageUpdater) fixViaDirectoryBuildProps(projectFilePath, packageName, fixedVersion, originalWd string) error {
	unsupported := &ErrUnsupportedFix{
		PackageName:  packageName,
		FixedVersion: fixedVersion,
		ErrorType:    NoInlineVersionFixNotSupported,
	}

	absRepoRoot, err := filepath.Abs(originalWd)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute path for %s: %w", originalWd, err)
	}

	for _, fileName := range []string{nugetDirectoryBuildPropsName, nugetDirectoryBuildTargetsName} {
		buildFilePath, buildFileContent, resolveErr := resolveDirectoryFile(filepath.Dir(projectFilePath), originalWd, fileName)
		if resolveErr != nil {
			return fmt.Errorf("%w in %s", resolveErr, projectFilePath)
		}
		if buildFilePath == "" {
			continue
		}

		for _, tryFix := range []versionFixFunc{tryFixPackageReference, tryFixPackageVersionEntry} {
			targetPath, originalContent, updatedContent, fixedAny, searchErr := searchVersionUpdate(buildFilePath, buildFileContent, packageName, fixedVersion, absRepoRoot, tryFix, map[string]struct{}{})
			if searchErr != nil {
				return fmt.Errorf("%w in %s", searchErr, projectFilePath)
			}
			if !fixedAny {
				continue
			}

			//#nosec G703 G306 -- targetPath resolved from descriptor discovery in the scanned repository.
			if err = os.WriteFile(targetPath, updatedContent, 0644); err != nil {
				return fmt.Errorf("failed to write %s: %w", targetPath, err)
			}
			return n.restoreLockFileAfterWrite(projectFilePath, targetPath, originalContent, originalWd, packageName, fixedVersion)
		}
	}
	return unsupported
}

func (n *NugetPackageUpdater) restoreLockFileAfterWrite(projectFilePath, writtenPath string, originalWritten []byte, originalWd, packageName, fixedVersion string) error {
	lockFilePath := filepath.Join(filepath.Dir(projectFilePath), nugetLockFileName)
	//#nosec G304 -- lockFilePath is derived from projectFilePath, itself from descriptor discovery.
	originalLockFile, err := os.ReadFile(lockFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return rollbackProjectFile(writtenPath, originalWritten, fmt.Errorf("failed to read %s: %w", lockFilePath, err))
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
		return rollbackProjectFileAndLock(writtenPath, originalWritten, lockFilePath, originalLockFile, err)
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
	versionOverrideElement := regexp.MustCompile(nugetVersionOverrideElementPattern)

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
		case versionOverrideElement.Match(match):
			fixedAny = true
			return versionOverrideElement.ReplaceAll(match, []byte("${1}"+fixedVersion+"${2}"))
		default:
			foundWithoutVersion = true
			return match
		}
	})

	if foundWithoutVersion && fixedAny {
		return nil, &ErrUnsupportedFix{
			PackageName:  packageName,
			FixedVersion: fixedVersion,
			ErrorType:    MixedInlineAndNonInlineVersionFixNotSupported,
		}
	}
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

type versionFixFunc func(content []byte, packageName, fixedVersion string) ([]byte, bool, error)

func resolvePackageVersionUpdate(propsPath string, propsContent []byte, packageName, fixedVersion, repoRoot string) (string, []byte, []byte, bool, error) {
	if isCentralPackageManagementDisabled(propsContent) {
		return "", nil, nil, false, nil
	}
	return searchVersionUpdate(propsPath, propsContent, packageName, fixedVersion, repoRoot, tryFixPackageVersionEntry, map[string]struct{}{})
}

func isCentralPackageManagementDisabled(content []byte) bool {
	return regexp.MustCompile(nugetManageCpmFalsePattern).Match(content)
}

func isCentralPackageManagementEnabled(content []byte) bool {
	return regexp.MustCompile(nugetManageCpmTruePattern).Match(content)
}

func isCentralPackageManagementDisabledInContext(projectFilePath string, packagesProps []byte, repoRoot string) bool {
	if isCentralPackageManagementDisabled(packagesProps) {
		return true
	}
	if isCentralPackageManagementEnabled(packagesProps) {
		return false
	}
	//#nosec G304 -- projectFilePath from descriptor discovery in the scanned repository.
	if projectContent, err := os.ReadFile(projectFilePath); err == nil {
		if isCentralPackageManagementDisabled(projectContent) {
			return true
		}
		if isCentralPackageManagementEnabled(projectContent) {
			return false
		}
	}
	buildFilePath, buildFileContent, err := resolveDirectoryFile(filepath.Dir(projectFilePath), repoRoot, nugetDirectoryBuildPropsName)
	if err != nil || buildFilePath == "" {
		return false
	}
	return isCentralPackageManagementDisabled(buildFileContent)
}

func tryFixPackageReference(content []byte, packageName, fixedVersion string) ([]byte, bool, error) {
	updated, err := updatePackageReferenceVersion(content, packageName, fixedVersion)
	if err == nil {
		return updated, true, nil
	}
	if isMixedInlineAndNonInline(err) {
		return nil, false, err
	}
	return nil, false, nil
}

func tryFixPackageVersionEntry(content []byte, packageName, fixedVersion string) ([]byte, bool, error) {
	updated, fixedAny := updatePackageVersionEntry(content, packageName, fixedVersion)
	return updated, fixedAny, nil
}

func searchVersionUpdate(path string, content []byte, packageName, fixedVersion, repoRoot string, tryFix versionFixFunc, visited map[string]struct{}) (string, []byte, []byte, bool, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", nil, nil, false, fmt.Errorf("failed to resolve absolute path for %s: %w", path, err)
	}
	if !isPathInsideRoot(repoRoot, absPath) {
		return "", nil, nil, false, nil
	}
	if _, seen := visited[absPath]; seen {
		return "", nil, nil, false, nil
	}
	visited[absPath] = struct{}{}

	updated, fixedAny, tryErr := tryFix(content, packageName, fixedVersion)
	if tryErr != nil {
		return "", nil, nil, false, tryErr
	}
	if fixedAny {
		return absPath, content, updated, true, nil
	}

	importAttr := regexp.MustCompile(nugetImportProjectAttrPattern)
	for _, match := range importAttr.FindAllSubmatch(content, -1) {
		projectRef := string(match[1])
		if strings.HasPrefix(projectRef, nugetMSBuildThisFileDirectoryMacro) {
			suffix := filepath.FromSlash(strings.TrimPrefix(projectRef, nugetMSBuildThisFileDirectoryMacro))
			projectRef = filepath.Join(filepath.Dir(absPath), suffix)
		}
		if strings.Contains(projectRef, "$") {
			continue
		}
		nextPath := projectRef
		if !filepath.IsAbs(projectRef) {
			nextPath = filepath.Join(filepath.Dir(absPath), filepath.FromSlash(projectRef))
		}
		nextAbs, absErr := filepath.Abs(nextPath)
		if absErr != nil || !isPathInsideRoot(repoRoot, nextAbs) {
			continue
		}
		//#nosec G304 -- nextAbs is an Import Project path constrained to the scanned repository.
		nextContent, readErr := os.ReadFile(nextAbs)
		if readErr != nil {
			if os.IsNotExist(readErr) {
				continue
			}
			return "", nil, nil, false, fmt.Errorf("failed to read %s: %w", nextAbs, readErr)
		}
		foundPath, original, updatedImported, ok, searchErr := searchVersionUpdate(nextAbs, nextContent, packageName, fixedVersion, repoRoot, tryFix, visited)
		if searchErr != nil || ok {
			return foundPath, original, updatedImported, ok, searchErr
		}
	}
	return "", nil, nil, false, nil
}

func resolveDirectoryFile(startDir, repoRoot, fileName string) (path string, content []byte, err error) {
	absRepoRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		return "", nil, fmt.Errorf("failed to resolve absolute path for %s: %w", repoRoot, err)
	}
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return "", nil, fmt.Errorf("failed to resolve absolute path for %s: %w", startDir, err)
	}

	for {
		if !isPathInsideRoot(absRepoRoot, dir) {
			return "", nil, nil
		}
		candidate := filepath.Join(dir, fileName)
		//#nosec G304 -- candidate is built from startDir/repoRoot, from descriptor discovery.
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

func isPathInsideRoot(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}
