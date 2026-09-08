package packageupdaters

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	bibuildutils "github.com/jfrog/build-info-go/build/utils"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	yarnLockFileName               = "yarn.lock"
	yarnUpdateLockfileModeFlag     = "--mode=update-lockfile"
	yarnEnableImmutableInstallsEnv = "YARN_ENABLE_IMMUTABLE_INSTALLS"
	yarnMinFixableVersion          = "3.0.0"
	yarnInstallStateFileName       = "install-state.gz"
	yarnDirName                    = ".yarn"
	yarnCacheDirName               = "cache"
	yarnPnpFileName                = ".pnp.cjs"
	yarnPnpDataFileName            = ".pnp.data.json"
)

var YarnInstallEnvOverrides = map[string]string{
	yarnEnableImmutableInstallsEnv: "false",
}

type YarnPackageUpdater struct {
	CommonPackageUpdater
}

func (yarn *YarnPackageUpdater) UpdateDependency(fixDetails *FixDetails) error {
	if fixDetails.IsDirectDependency {
		return yarn.updateDirectDependency(fixDetails)
	}
	return &ErrUnsupportedFix{
		PackageName:  fixDetails.ImpactedDependencyName,
		FixedVersion: fixDetails.SuggestedFixedVersion,
		ErrorType:    IndirectDependencyFixNotSupported,
	}
}

func (yarn *YarnPackageUpdater) updateDirectDependency(fixDetails *FixDetails) error {
	descriptorPaths := yarn.CollectVulnerabilityDescriptorPaths(fixDetails, []string{NodePackageJSONFileName}, []string{NodeModulesDirName})
	if len(descriptorPaths) == 0 {
		return fmt.Errorf("no descriptor evidence was found for package %s", fixDetails.ImpactedDependencyName)
	}

	originalWd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	var failingDescriptors []string
	for _, descriptorPath := range descriptorPaths {
		if fixErr := yarn.fixVulnerabilityAndRegenerateLock(fixDetails, descriptorPath, originalWd); fixErr != nil {
			var unsupported *ErrUnsupportedFix
			if errors.As(fixErr, &unsupported) {
				return fixErr
			}
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

func (yarn *YarnPackageUpdater) fixVulnerabilityAndRegenerateLock(fixDetails *FixDetails, descriptorPath string, originalWd string) error {
	descriptorDir := filepath.Dir(descriptorPath)
	rootDir, err := FindYarnLockfileRoot(descriptorDir)
	if err != nil {
		return fmt.Errorf("failed to locate the yarn workspace root for descriptor '%s': %w", descriptorPath, err)
	}

	executablePath, err := bibuildutils.GetYarnExecutable()
	if err != nil {
		return &ErrUnsupportedFix{
			PackageName:  fixDetails.ImpactedDependencyName,
			FixedVersion: fixDetails.SuggestedFixedVersion,
			ErrorType:    UnsupportedFixReason,
			Reason:       fmt.Sprintf("no usable yarn executable was found on this runner: %s", err.Error()),
		}
	}

	yarnVersionStr, err := bibuildutils.GetVersion(executablePath, rootDir)
	if err != nil {
		return &ErrUnsupportedFix{
			PackageName:  fixDetails.ImpactedDependencyName,
			FixedVersion: fixDetails.SuggestedFixedVersion,
			ErrorType:    UnsupportedFixReason,
			Reason:       fmt.Sprintf("no usable yarn was found for the project at '%s': %s", rootDir, err.Error()),
		}
	}
	if version.NewVersion(yarnVersionStr).Compare(yarnMinFixableVersion) > 0 {
		return &ErrUnsupportedFix{
			PackageName:  fixDetails.ImpactedDependencyName,
			FixedVersion: fixDetails.SuggestedFixedVersion,
			ErrorType:    UnsupportedFixReason,
			Reason:       fmt.Sprintf("yarn %s has no lockfile-only install mode (requires yarn >= %s)", strings.TrimSpace(yarnVersionStr), yarnMinFixableVersion),
		}
	}

	backupContent, err := yarn.UpdatePackageJSONDescriptor(descriptorPath, fixDetails.ImpactedDependencyName, fixDetails.SuggestedFixedVersion)
	if err != nil {
		return err
	}

	lockFilePath := filepath.Join(rootDir, yarnLockFileName)

	lockFileTracked, checkErr := IsFileTrackedByGit(lockFilePath, originalWd)
	if checkErr != nil {
		log.Debug(fmt.Sprintf("Failed to check if lock file is tracked in git: %s. Proceeding with lock file regeneration.", checkErr.Error()))
		lockFileTracked = true
	}

	if !lockFileTracked {
		log.Debug(fmt.Sprintf("Lock file '%s' is not tracked in git, skipping lock file regeneration", lockFilePath))
		return nil
	}

	if err = yarn.regenerateLockfile(fixDetails, descriptorPath, rootDir, originalWd, executablePath, backupContent); err != nil {
		return err
	}

	log.Debug(fmt.Sprintf("Successfully updated '%s' from version '%s' to '%s' in descriptor '%s'", fixDetails.ImpactedDependencyName, fixDetails.ImpactedDependencyVersion, fixDetails.SuggestedFixedVersion, descriptorPath))
	return nil
}

func (yarn *YarnPackageUpdater) regenerateLockfile(fixDetails *FixDetails, descriptorPath, rootDir, originalWd, executablePath string, backupContent []byte) error {
	preExisting := snapshotYarnInstallArtifacts(rootDir)
	if err := os.Chdir(rootDir); err != nil {
		return fmt.Errorf("failed to change directory to '%s': %w", rootDir, err)
	}
	installErr := yarn.runYarnInstallUpdateLockfile(executablePath)
	if chErr := os.Chdir(originalWd); chErr != nil {
		return errors.Join(installErr, fmt.Errorf("failed to return to original directory: %w", chErr))
	}
	cleanupYarnInstallArtifacts(rootDir, preExisting)
	if installErr != nil {
		log.Warn(fmt.Sprintf("Failed to regenerate lock file after updating '%s' to version '%s': %s. Rolling back...", fixDetails.ImpactedDependencyName, fixDetails.SuggestedFixedVersion, installErr.Error()))
		//#nosec G306 -- 0644 is correct for a checked-out source file.
		if rollbackErr := os.WriteFile(descriptorPath, backupContent, 0644); rollbackErr != nil {
			return fmt.Errorf("failed to rollback descriptor after lock file regeneration failure: %w (original error: %v)", rollbackErr, installErr)
		}
		return installErr
	}
	return nil
}

type yarnInstallArtifactSnapshot struct {
	pnpCjsExisted      bool
	pnpDataJSONExisted bool
	cacheDirExisted    bool
}

func snapshotYarnInstallArtifacts(rootDir string) yarnInstallArtifactSnapshot {
	exists := func(path string) bool {
		_, err := os.Stat(path)
		return err == nil
	}
	return yarnInstallArtifactSnapshot{
		pnpCjsExisted:      exists(filepath.Join(rootDir, yarnPnpFileName)),
		pnpDataJSONExisted: exists(filepath.Join(rootDir, yarnPnpDataFileName)),
		cacheDirExisted:    exists(filepath.Join(rootDir, yarnDirName, yarnCacheDirName)),
	}
}

func cleanupYarnInstallArtifacts(rootDir string, preExisting yarnInstallArtifactSnapshot) {
	_ = os.Remove(filepath.Join(rootDir, yarnDirName, yarnInstallStateFileName))
	if !preExisting.pnpCjsExisted {
		_ = os.Remove(filepath.Join(rootDir, yarnPnpFileName))
	}
	if !preExisting.pnpDataJSONExisted {
		_ = os.Remove(filepath.Join(rootDir, yarnPnpDataFileName))
	}
	if !preExisting.cacheDirExisted {
		_ = os.RemoveAll(filepath.Join(rootDir, yarnDirName, yarnCacheDirName))
	}
}

func (yarn *YarnPackageUpdater) runYarnInstallUpdateLockfile(executablePath string) error {
	args := []string{"install", yarnUpdateLockfileModeFlag}
	fullCommand := "yarn " + strings.Join(args, " ")
	log.Debug(fmt.Sprintf("Running '%s'", fullCommand))

	ctx, cancel := context.WithTimeout(context.Background(), nodePackageManagerInstallTimeout)
	defer cancel()

	//#nosec G204 -- False positive - the subprocess only runs after the user's approval
	cmd := exec.CommandContext(ctx, executablePath, args...)
	cmd.Env = EnvWithCorepackIntegrityWorkaround(yarn.BuildEnvWithOverrides(YarnInstallEnvOverrides))
	output, err := cmd.CombinedOutput()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("yarn install timed out after %v", nodePackageManagerInstallTimeout)
	}

	if err != nil {
		return fmt.Errorf("yarn install failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}

func FindYarnLockfileRoot(startDir string) (string, error) {
	absDir, err := filepath.Abs(startDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve absolute path for '%s': %w", startDir, err)
	}
	for cur := absDir; ; {
		if techutils.DirectoryHasYarnIndicator(cur) {
			return cur, nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", fmt.Errorf("no yarn.lock/.yarnrc.yml/.yarnrc/.yarn found in '%s' or any parent directory", startDir)
		}
		cur = parent
	}
}
