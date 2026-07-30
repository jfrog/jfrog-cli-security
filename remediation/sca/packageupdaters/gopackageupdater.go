package packageupdaters

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	goFlagModEditEnv      = "GOFLAGS=-mod=mod"
	goWorkOffEnv          = "GOWORK=off"
	GoModFileName         = "go.mod"
	GoSumFileName         = "go.sum"
	GoVendorDirName       = "vendor"
	goTidyContinueOnError = "-e"
)

type GoPackageUpdater struct{}

type GoModuleBackup struct {
	GoModPath    string
	GoModContent []byte
	GoSumPath    string
	GoSumContent []byte
}

func (gpu *GoPackageUpdater) UpdateDependency(fixDetails *FixDetails) error {
	descriptorPaths := GetVulnerabilityLocations(fixDetails, []string{GoModFileName}, []string{GoVendorDirName})
	if len(descriptorPaths) == 0 {
		return fmt.Errorf("no descriptor evidence was found for package %s", fixDetails.ImpactedDependencyName)
	}

	originalWd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	env := gpu.buildGoCommandEnv()

	var failingDescriptors []string
	for _, descriptorPath := range descriptorPaths {
		if fixErr := gpu.fixVulnerabilityAndTidy(fixDetails, descriptorPath, originalWd, env); fixErr != nil {
			failedFixErrorMsg := fmt.Errorf("failed to fix '%s' in descriptor '%s': %w", fixDetails.ImpactedDependencyName, descriptorPath, fixErr)
			log.Warn(failedFixErrorMsg.Error())
			err = errors.Join(err, failedFixErrorMsg)
			failingDescriptors = append(failingDescriptors, descriptorPath)
		}
	}
	if err != nil {
		return fmt.Errorf("encountered errors while fixing '%s' vulnerability in descriptors [%s]: %w", fixDetails.ImpactedDependencyName, strings.Join(failingDescriptors, ", "), err)
	}

	return nil
}

func (gpu *GoPackageUpdater) fixVulnerabilityAndTidy(fixDetails *FixDetails, descriptorPath, originalWd string, env []string) (err error) {
	backup, backupErr := gpu.BackupModuleFiles(descriptorPath)
	if backupErr != nil {
		return backupErr
	}

	descriptorDir := filepath.Dir(descriptorPath)
	if err = os.Chdir(descriptorDir); err != nil {
		return fmt.Errorf("failed to change directory to '%s': %w", descriptorDir, err)
	}
	defer func() {
		if chErr := os.Chdir(originalWd); chErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to return to original directory: %w", chErr))
		}
	}()

	if err = gpu.updateDependency(fixDetails, env); err != nil {
		log.Warn(fmt.Sprintf("Failed to update '%s' to version '%s': %s. Rolling back...", fixDetails.ImpactedDependencyName, fixDetails.SuggestedFixedVersion, err.Error()))
		if rollbackErr := gpu.RestoreModuleFiles(backup); rollbackErr != nil {
			return fmt.Errorf("failed to rollback module files after go get failure: %w (original error: %v)", rollbackErr, err)
		}
		return err
	}

	lockFileTracked, checkErr := IsFileTrackedByGit(backup.GoSumPath, originalWd)
	if checkErr != nil {
		log.Debug(fmt.Sprintf("Failed to check if lock file is tracked in git: %s. Proceeding with lock file regeneration.", checkErr.Error()))
		lockFileTracked = true
	}

	if !lockFileTracked {
		log.Debug(fmt.Sprintf("Lock file '%s' is not tracked in git, skipping lock file regeneration", backup.GoSumPath))
		return nil
	}

	if err = gpu.tidyLockFiles(descriptorDir, env); err != nil {
		log.Warn(fmt.Sprintf("Failed to tidy module files after updating '%s' to version '%s': %s. Rolling back...", fixDetails.ImpactedDependencyName, fixDetails.SuggestedFixedVersion, err.Error()))
		if rollbackErr := gpu.RestoreModuleFiles(backup); rollbackErr != nil {
			return fmt.Errorf("failed to rollback module files after tidy failure: %w (original error: %v)", rollbackErr, err)
		}
		return err
	}

	log.Debug(fmt.Sprintf("Successfully updated '%s' from version '%s' to '%s' in descriptor '%s'", fixDetails.ImpactedDependencyName, fixDetails.ImpactedDependencyVersion, fixDetails.SuggestedFixedVersion, descriptorPath))
	return nil
}

func (gpu *GoPackageUpdater) buildGoCommandEnv() []string {
	return append(os.Environ(), goFlagModEditEnv, goWorkOffEnv)
}

func (gpu *GoPackageUpdater) BackupModuleFiles(goModPath string) (*GoModuleBackup, error) {
	//#nosec G304 -- go.mod path from scan workflow.
	goModContent, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read '%s': %w", goModPath, err)
	}

	descriptorDir := filepath.Dir(goModPath)
	goSumPath := filepath.Join(descriptorDir, GoSumFileName)
	//#nosec G304 -- go.sum adjacent to go.mod from same scan workflow.
	goSumContent, err := os.ReadFile(goSumPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read '%s': %w", goSumPath, err)
	}

	backup := &GoModuleBackup{
		GoModPath:    goModPath,
		GoModContent: make([]byte, len(goModContent)),
		GoSumPath:    goSumPath,
		GoSumContent: make([]byte, len(goSumContent)),
	}
	copy(backup.GoModContent, goModContent)
	copy(backup.GoSumContent, goSumContent)

	return backup, nil
}

func (gpu *GoPackageUpdater) RestoreModuleFiles(backup *GoModuleBackup) error {
	//#nosec G306 -- 0644 for checked-out module files in workspace.
	if err := os.WriteFile(backup.GoModPath, backup.GoModContent, 0644); err != nil {
		return fmt.Errorf("failed to restore '%s': %w", backup.GoModPath, err)
	}
	//#nosec G306 -- 0644 for checked-out module files in workspace.
	if err := os.WriteFile(backup.GoSumPath, backup.GoSumContent, 0644); err != nil {
		return fmt.Errorf("failed to restore '%s': %w", backup.GoSumPath, err)
	}
	log.Debug(fmt.Sprintf("Successfully rolled back '%s' and '%s' to original state", backup.GoModPath, backup.GoSumPath))
	return nil
}

func (gpu *GoPackageUpdater) updateDependency(fixDetails *FixDetails, env []string) error {
	impactedPackage := strings.ToLower(fixDetails.ImpactedDependencyName)
	fixedVersion := strings.TrimSpace(fixDetails.SuggestedFixedVersion)

	if !strings.HasPrefix(fixedVersion, "v") {
		fixedVersion = "v" + fixedVersion
	}
	fixedPackage := strings.TrimSpace(impactedPackage) + "@" + fixedVersion

	//#nosec G204 -- runs only after user approval; arguments from vulnerability metadata.
	cmd := exec.Command("go", "get", fixedPackage)
	cmd.Env = env
	log.Debug(fmt.Sprintf("Running 'go get %s'", fixedPackage))

	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		log.Debug(fmt.Sprintf("go get output:\n%s", string(output)))
	}

	if err != nil {
		return fmt.Errorf("go get failed: %s\n%s", err.Error(), output)
	}
	return nil
}

func (gpu *GoPackageUpdater) tidyLockFiles(descriptorDir string, env []string) error {
	cmd := exec.Command("go", "mod", "tidy", goTidyContinueOnError)
	cmd.Env = env
	log.Debug("Running 'go mod tidy'")

	//#nosec G204 -- False positive - the subprocess only runs after the user's approval.
	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		log.Debug(fmt.Sprintf("go mod tidy output:\n%s", string(output)))
	}

	if err != nil {
		return fmt.Errorf("go mod tidy failed: %s\n%s", err.Error(), output)
	}

	if gpu.HasVendorDirectory(descriptorDir) {
		if err := gpu.updateVendor(env); err != nil {
			return err
		}
	}

	return nil
}

func (gpu *GoPackageUpdater) HasVendorDirectory(descriptorDir string) bool {
	vendorModulesPath := filepath.Join(descriptorDir, GoVendorDirName, "modules.txt")
	if _, err := os.Stat(vendorModulesPath); err == nil {
		log.Debug(fmt.Sprintf("Detected vendor directory at: %s", vendorModulesPath))
		return true
	}
	return false
}

func (gpu *GoPackageUpdater) updateVendor(env []string) error {
	vendorCmd := exec.Command("go", "mod", "vendor")
	vendorCmd.Env = env
	log.Debug("Running 'go mod vendor' to update vendored dependencies")

	//#nosec G204 -- False positive - the subprocess only runs after the user's approval.
	vendorOutput, err := vendorCmd.CombinedOutput()
	if len(vendorOutput) > 0 {
		log.Debug(fmt.Sprintf("go mod vendor output:\n%s", string(vendorOutput)))
	}

	if err != nil {
		return fmt.Errorf("go mod vendor failed: %s\n%s", err.Error(), vendorOutput)
	}

	log.Debug("Successfully updated vendor directory")
	return nil
}
