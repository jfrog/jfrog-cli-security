package packageupdaters

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jfrog/jfrog-client-go/utils/log"
)

const csprojFileSuffix = ".csproj"

const (
	nugetPackageReferenceElementPattern = `(?s)<PackageReference\b[^>]*/>|<PackageReference\b[^>]*[^/]>.*?</PackageReference>`
	nugetKeyAttrPattern                 = `(?i)\b(?:Include|Update)\s*=\s*["']%s["']`
	nugetVersionAttrPattern             = `(?is)(\bVersion\s*=\s*["'])[^"']*(["'])`
	nugetVersionElementPattern          = `(?is)(<Version>)[^<]*(</Version>)`

	nugetLockFileName              = "packages.lock.json"
	nugetRestoreForceEvaluateFlag  = "--force-evaluate"
	nugetRestoreNoDependenciesFlag = "--no-dependencies"
)

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

	csprojPaths := collectCsprojPaths(fixDetails)
	if len(csprojPaths) == 0 {
		return fmt.Errorf("no .csproj locations found for %s - Components array is empty or missing Location data", fixDetails.ImpactedDependencyName)
	}
	log.Verbose(fmt.Sprintf("Found vulnerability %s occurrences for component %s in %s", fixDetails.IssueId, fixDetails.ImpactedDependencyVersion, strings.Join(csprojPaths, ", ")))

	originalWd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	var failingDescriptors []string
	for _, csprojPath := range csprojPaths {
		if fixErr := n.fixVulnerabilityAndRestore(csprojPath, fixDetails.ImpactedDependencyName, fixDetails.SuggestedFixedVersion, originalWd); fixErr != nil {
			log.Warn(fixErr.Error())
			err = errors.Join(err, fmt.Errorf("failed to fix '%s' in descriptor '%s': %w", fixDetails.ImpactedDependencyName, csprojPath, fixErr))
			failingDescriptors = append(failingDescriptors, csprojPath)
		} else {
			log.Debug("Updated successfully " + csprojPath)
		}
	}

	if err != nil {
		return fmt.Errorf("encountered errors while fixing '%s' vulnerability in descriptors [%s]: %w", fixDetails.ImpactedDependencyName, strings.Join(failingDescriptors, ", "), err)
	}
	return nil
}

func collectCsprojPaths(fixDetails *FixDetails) []string {
	var paths []string
	for _, path := range GetVulnerabilityLocations(fixDetails, []string{}, []string{}) {
		if strings.HasSuffix(path, csprojFileSuffix) {
			paths = append(paths, path)
		}
	}
	return paths
}

func (n *NugetPackageUpdater) fixVulnerabilityAndRestore(csprojPath, packageName, fixedVersion, originalWd string) error {
	//#nosec G304 -- csprojPath from descriptor discovery in the scanned repository.
	originalCsproj, err := os.ReadFile(csprojPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", csprojPath, err)
	}

	updatedCsproj, err := updatePackageReferenceVersion(originalCsproj, packageName, fixedVersion)
	if err != nil {
		return fmt.Errorf("%w in %s", err, csprojPath)
	}

	//#nosec G703 G306 -- csprojPath from scan workflow; 0644 for VCS-tracked sources.
	if err = os.WriteFile(csprojPath, updatedCsproj, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", csprojPath, err)
	}

	lockFilePath := filepath.Join(filepath.Dir(csprojPath), nugetLockFileName)
	//#nosec G304 -- lockFilePath is derived from csprojPath, itself from descriptor discovery.
	originalLockFile, err := os.ReadFile(lockFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			// No lock file for this project - nothing further to regenerate.
			return nil
		}
		return rollbackCsproj(csprojPath, originalCsproj, fmt.Errorf("failed to read %s: %w", lockFilePath, err))
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

	if err = n.runDotnetRestore(csprojPath); err != nil {
		log.Warn(fmt.Sprintf("Failed to regenerate lock file after updating '%s' to version '%s': %s. Rolling back...", packageName, fixedVersion, err.Error()))
		return rollbackCsprojAndLock(csprojPath, originalCsproj, lockFilePath, originalLockFile, err)
	}
	return nil
}

func (n *NugetPackageUpdater) runDotnetRestore(csprojPath string) error {
	//#nosec G204 -- csprojPath from descriptor discovery; runs only after user approval.
	cmd := exec.Command("dotnet", "restore", csprojPath, nugetRestoreForceEvaluateFlag, nugetRestoreNoDependenciesFlag)
	cmd.Env = n.BuildEnvWithOverrides(NugetRestoreEnvVars)
	log.Debug(fmt.Sprintf("Running 'dotnet restore %s %s %s'", csprojPath, nugetRestoreForceEvaluateFlag, nugetRestoreNoDependenciesFlag))

	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		log.Debug(fmt.Sprintf("dotnet restore output:\n%s", string(output)))
	}
	if err != nil {
		return fmt.Errorf("dotnet restore failed: %s\n%s", err.Error(), output)
	}
	return nil
}

func rollbackCsproj(csprojPath string, originalCsproj []byte, origErr error) error {
	//#nosec G703 G306 -- csprojPath from scan workflow; 0644 for VCS-tracked sources.
	if rollbackErr := os.WriteFile(csprojPath, originalCsproj, 0644); rollbackErr != nil {
		return fmt.Errorf("failed to rollback '%s': %w (original error: %v)", csprojPath, rollbackErr, origErr)
	}
	return origErr
}

func rollbackCsprojAndLock(csprojPath string, originalCsproj []byte, lockFilePath string, originalLockFile []byte, origErr error) error {
	//#nosec G703 G306 -- csprojPath from scan workflow; 0644 for VCS-tracked sources.
	if rollbackErr := os.WriteFile(csprojPath, originalCsproj, 0644); rollbackErr != nil {
		return fmt.Errorf("failed to rollback '%s': %w (original error: %v)", csprojPath, rollbackErr, origErr)
	}
	//#nosec G703 G306 -- lockFilePath derived from csprojPath, from the same scan workflow.
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
		default:
			foundWithoutVersion = true
			return match
		}
	})

	if fixedAny {
		return updatedContent, nil
	}
	if foundWithoutVersion {
		return nil, &ErrUnsupportedFix{
			PackageName:  packageName,
			FixedVersion: fixedVersion,
			ErrorType:    CentralPackageManagementFixNotSupported,
		}
	}
	return nil, fmt.Errorf("dependency %s not found", packageName)
}
