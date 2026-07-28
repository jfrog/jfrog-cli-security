package packageupdaters

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	CiEnv                  = "CI"
	ConfigIgnoreScriptsEnv = "NPM_CONFIG_IGNORE_SCRIPTS"
	ConfigAuditEnv         = "NPM_CONFIG_AUDIT"
	ConfigFundEnv          = "NPM_CONFIG_FUND"
	ConfigLevelEnv         = "NPM_CONFIG_LOGLEVEL"

	npmPackageLockOnlyFlag = "--package-lock-only"
	npmIgnoreScriptsFlag   = "--ignore-scripts"
	npmNoAuditFlag         = "--no-audit"
	npmLegacyPeerDepsFlag  = "--legacy-peer-deps"
	npmNoFundFlag          = "--no-fund"

	npmLockFileName          = "package-lock.json"
	npmEreresolveErrorPrefix = "ERESOLVE"
)

var NpmInstallEnvVars = map[string]string{
	ConfigIgnoreScriptsEnv: "true",
	ConfigAuditEnv:         "false",
	ConfigFundEnv:          "false",
	ConfigLevelEnv:         "error",
	CiEnv:                  "true",
}

type NpmPackageUpdater struct {
	CommonPackageUpdater
}

func (npm *NpmPackageUpdater) UpdateDependency(fixDetails *FixDetails) error {
	if fixDetails.IsDirectDependency {
		return npm.updateDirectDependency(fixDetails)
	}
	return &ErrUnsupportedFix{
		PackageName:  fixDetails.ImpactedDependencyName,
		FixedVersion: fixDetails.SuggestedFixedVersion,
		ErrorType:    IndirectDependencyFixNotSupported,
	}
}

func (npm *NpmPackageUpdater) updateDirectDependency(fixDetails *FixDetails) error {
	descriptorPaths := npm.CollectVulnerabilityDescriptorPaths(fixDetails, []string{NodePackageJSONFileName}, []string{NodeModulesDirName})
	if len(descriptorPaths) == 0 {
		return fmt.Errorf("no descriptor evidence was found for package %s", fixDetails.ImpactedDependencyName)
	}

	originalWd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	var failingDescriptors []string
	for _, descriptorPath := range descriptorPaths {
		if fixErr := npm.fixVulnerabilityAndRegenerateLock(fixDetails, descriptorPath, originalWd); fixErr != nil {
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

func (npm *NpmPackageUpdater) fixVulnerabilityAndRegenerateLock(fixDetails *FixDetails, descriptorPath string, originalWd string) error {
	backupContent, err := npm.UpdatePackageJSONDescriptor(descriptorPath, fixDetails.ImpactedDependencyName, fixDetails.SuggestedFixedVersion)
	if err != nil {
		return err
	}

	descriptorDir := filepath.Dir(descriptorPath)
	lockFilePath := filepath.Join(descriptorDir, npmLockFileName)

	lockFileTracked, checkErr := IsFileTrackedByGit(lockFilePath, originalWd)
	if checkErr != nil {
		log.Debug(fmt.Sprintf("Failed to check if lock file is tracked in git: %s. Proceeding with lock file regeneration.", checkErr.Error()))
		lockFileTracked = true
	}

	if !lockFileTracked {
		log.Debug(fmt.Sprintf("Lock file '%s' is not tracked in git, skipping lock file regeneration", lockFilePath))
		return nil
	}

	if err = npm.regenerateLockfile(fixDetails, descriptorPath, originalWd, backupContent); err != nil {
		return err
	}

	log.Debug(fmt.Sprintf("Successfully updated '%s' from version '%s' to '%s' in descriptor '%s'", fixDetails.ImpactedDependencyName, fixDetails.ImpactedDependencyVersion, fixDetails.SuggestedFixedVersion, descriptorPath))
	return nil
}

func (npm *NpmPackageUpdater) regenerateLockfile(fixDetails *FixDetails, descriptorPath, originalWd string, backupContent []byte) error {
	return npm.withDescriptorWorkingDir(descriptorPath, originalWd, func() error {
		if err := npm.regenerateLockFileWithRetry(); err != nil {
			log.Warn(fmt.Sprintf("Failed to regenerate lock file after updating '%s' to version '%s': %s. Rolling back...", fixDetails.ImpactedDependencyName, fixDetails.SuggestedFixedVersion, err.Error()))
			//#nosec G306 -- 0644 is correct for a checked-out source file.
			if rollbackErr := os.WriteFile(descriptorPath, backupContent, 0644); rollbackErr != nil {
				return fmt.Errorf("failed to rollback descriptor after lock file regeneration failure: %w (original error: %v)", rollbackErr, err)
			}
			return err
		}
		return nil
	})
}

func (npm *NpmPackageUpdater) GetFixedDescriptor(content []byte, packageName, newVersion, descriptorPath string) ([]byte, error) {
	return npm.GetFixedPackageJSONManifest(content, packageName, newVersion, descriptorPath)
}

func (npm *NpmPackageUpdater) regenerateLockFileWithRetry() error {
	err := npm.runNpmInstall(false)
	if err != nil {
		if strings.Contains(err.Error(), npmEreresolveErrorPrefix) {
			log.Debug(fmt.Sprintf("First npm install attempt failed due to peer dependency conflict. Retrying with %s...", npmLegacyPeerDepsFlag))
			if err = npm.runNpmInstall(true); err != nil {
				return fmt.Errorf("npm install failed after retry with %s: %w", npmLegacyPeerDepsFlag, err)
			}
			return nil
		}
		return err
	}
	return nil
}

func (npm *NpmPackageUpdater) runNpmInstall(useLegacyPeerDeps bool) error {
	args := []string{
		"install",
		npmPackageLockOnlyFlag,
		npmIgnoreScriptsFlag,
		npmNoAuditFlag,
		npmNoFundFlag,
	}
	if useLegacyPeerDeps {
		args = append(args, npmLegacyPeerDepsFlag)
	}

	fullCommand := "npm " + strings.Join(args, " ")
	log.Debug(fmt.Sprintf("Running '%s'", fullCommand))

	ctx, cancel := context.WithTimeout(context.Background(), nodePackageManagerInstallTimeout)
	defer cancel()

	//#nosec G204 -- False positive - the subprocess only runs after the user's approval
	cmd := exec.CommandContext(ctx, "npm", args...)

	cmd.Env = npm.BuildEnvWithOverrides(NpmInstallEnvVars)
	output, err := cmd.CombinedOutput()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("npm install timed out after %v", nodePackageManagerInstallTimeout)
	}

	if err != nil {
		return fmt.Errorf("npm install failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}
