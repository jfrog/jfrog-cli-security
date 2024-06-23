package detect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"golang.org/x/exp/slices"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils"
	configs "github.com/jfrog/jfrog-cli-security/utils/configs"
	"github.com/jfrog/jfrog-cli-security/utils/results/output"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"

	"github.com/jfrog/jfrog-cli-security/utils/xray"
)

// From user input
type AppsDetectParams struct {
	// Target configurations
	configs.DetectTargetsParams
	// Scan configurations
	configs.DetectScanConfigParams
}

type DetectAppsCommand struct {
	serverDetails *config.ServerDetails
	params        *AppsDetectParams
}

func NewScanProfileCommand() *DetectAppsCommand {
	return &DetectAppsCommand{}
}

func (daCmd *DetectAppsCommand) CommandName() string {
	return "detect"
}

func (daCmd *DetectAppsCommand) ServerDetails() (*config.ServerDetails, error) {
	return daCmd.serverDetails, nil
}

func (daCmd *DetectAppsCommand) Run() (err error) {
	serverDetails, err := daCmd.ServerDetails()
	if err != nil {
		return
	}
	appsConfig, err := RunDetectSecurityConfig(serverDetails, daCmd.params)
	if err != nil {
		return
	}
	// Print output
	log.Info(fmt.Sprintf("Detected %d targets for security scanning with the following configuration", len(appsConfig.Targets)))
	output.PrintJson(appsConfig)
	return err
}

func RunDetectSecurityConfig(serverDetails *config.ServerDetails, params *AppsDetectParams) (*configs.AppsSecurityConfig, error) {
	xrayManager, xrayVersion, err := xray.CreateXrayServiceManagerAndGetVersion(serverDetails)
	if err != nil {
		return nil, err
	}
	entitledForJas, err := jas.IsEntitledForJas(xrayManager, xrayVersion)
	if err != nil {
		return nil, err
	}
	// Get local config
	localConfig, err := getLocalScanConfig()
	if err != nil {
		return nil, fmt.Errorf("Failed to get local information: %v", err)
	}
	return GenerateAppsSecurityConfig(localConfig, params, entitledForJas, xrayVersion)
}

func getLocalScanConfig() (jfrogAppsConfig *jfrogappsconfig.JFrogAppsConfig, err error) {
	if jfrogAppsConfig, err = jfrogappsconfig.LoadConfigIfExist(); err != nil {
		return nil, errorutils.CheckError(err)
	} else if jfrogAppsConfig == nil {
		log.Debug("No local scan configuration found for the current workspace.")
		return
	}
	for _, module := range jfrogAppsConfig.Modules {
		// Get absolute path from the source root
		root, err := filepath.Abs(module.SourceRoot)
		if err != nil {
			return nil, errorutils.CheckError(err)
		}
		module.SourceRoot = root
		if module.Scanners.Iac != nil {
			module.Scanners.Iac.WorkingDirs = getLocalScannerRoots(root, module, module.Scanners.Iac)
		}
		if module.Scanners.Secrets != nil {
			module.Scanners.Secrets.WorkingDirs = getLocalScannerRoots(root, module, module.Scanners.Secrets)
		}
		if module.Scanners.Sast != nil {
			module.Scanners.Sast.WorkingDirs = getLocalScannerRoots(root, module, &module.Scanners.Sast.Scanner)
		}
	}
	return
}

func getLocalScannerRoots(root string, module jfrogappsconfig.Module, scanner *jfrogappsconfig.Scanner) []string {
	if scanner == nil || len(scanner.WorkingDirs) == 0 {
		return []string{root}
	}
	var roots []string
	for _, workingDir := range scanner.WorkingDirs {
		roots = append(roots, filepath.Join(root, workingDir))
	}
	return roots
}

func GenerateAppsSecurityConfig(localConfiguration *jfrogappsconfig.JFrogAppsConfig, params *AppsDetectParams, entitledForJas bool, xrayVersion string) (appsConfig *configs.AppsSecurityConfig, err error) {
	appsConfig = GetEmptyAppsSecurityConfig(params, entitledForJas, xrayVersion)
	// Get targets
	scanTargets, err := GetTargets(localConfiguration, params)
	if err != nil {
		return
	}
	// If no targets were provided, detect in the current working directory
	targetDetectionMode := len(scanTargets) == 0
	currentWorkingDir, err := os.Getwd()
	if err != nil {
		return
	}
	if targetDetectionMode {
		log.Info("Detecting targets for security scanning in the current working directory")
		scanTargets = append(scanTargets, configs.ScanTarget{Target: currentWorkingDir})
	}
	// Detect actual targets and generate configurations for each
	for _, potentialTarget := range scanTargets {
		localModule, err := getLocalScanModule(localConfiguration, potentialTarget.Target)
		if err != nil {
			log.Warn(fmt.Sprintf("Failed to get local scan configuration for target '%s'. Skipping...", potentialTarget.String()))
			continue
		}
		fileSystemInfo, err := DetectWorkingDirectoryInformation(potentialTarget.Target, localModule, params, targetDetectionMode)
		if err != nil {
			log.Warn(fmt.Sprintf("Failed to detect information from the file system in '%s'. Skipping...", potentialTarget.String()))
			continue
		}
		targetConfigs, err := GetTargetScanConfigurations(potentialTarget, localModule, fileSystemInfo, params, entitledForJas, targetDetectionMode)
		if err != nil {
			log.Warn(fmt.Sprintf("Failed to generate scan configuration for target '%s'. Skipping...", potentialTarget.String()))
			continue
		}
		appsConfig.Targets = append(appsConfig.Targets, targetConfigs...)
	}
	return
}

func GetEmptyAppsSecurityConfig(params *AppsDetectParams, entitledForJas bool, xrayVersion string) (appsConfig *configs.AppsSecurityConfig) {
	return &configs.AppsSecurityConfig{
		XrayVersion:    xrayVersion,
		EntitledForJas: entitledForJas,
		// Policy context information
		ScanPolicyContext: configs.ScanPolicyContext{
			Watches:    params.Watches,
			ProjectKey: params.ProjectKey,
			RepoPath:   params.RepoPath,
		},
		// Output information
		ScanOutput: configs.ScanOutput{
			MinSeverity: params.MinSeverity,
			FixableOnly: params.FixableOnly,
		},
	}
}

func GetTargets(localConfig *jfrogappsconfig.JFrogAppsConfig, params *AppsDetectParams) (targets []configs.ScanTarget, err error) {
	// If user input parameters, use them
	workingDirs, err := coreutils.GetFullPathsWorkingDirs(params.WorkingDirs)
	if err != nil {
		return
	}
	if len(workingDirs) > 0 {
		log.Info(fmt.Sprintf("Using the provided working directories from the command line: %v", workingDirs))
		for _, workingDir := range workingDirs {
			targets = append(targets, configs.ScanTarget{Target: workingDir})
		}
		return
	}
	// If local configuration exists, use it
	if localConfig != nil {
		log.Info("Using the modules from the local scan configuration")
		for _, module := range localConfig.Modules {
			targets = append(targets, configs.ScanTarget{Target: module.SourceRoot, Name: module.Name})
		}
	}
	return
}

func getLocalScanModule(jfrogAppsConfig *jfrogappsconfig.JFrogAppsConfig, target string) (module *jfrogappsconfig.Module, err error) {
	if jfrogAppsConfig == nil {
		return nil, nil
	}
	for _, m := range jfrogAppsConfig.Modules {
		if m.SourceRoot == target {
			return &m, nil
		}
	}
	return nil, nil
}

func getLocalScanner(module *jfrogappsconfig.Module, scannerType utils.SubScanType) *jfrogappsconfig.Scanner {
	if module == nil {
		return nil
	}
	switch scannerType {
	case utils.SecretsScan:
		return module.Scanners.Secrets
	case utils.IacScan:
		return module.Scanners.Iac
	case utils.SastScan:
		return &module.Scanners.Sast.Scanner
	}
	return nil
}

func DetectWorkingDirectoryInformation(requestedDirectory string, localModuleConfig *jfrogappsconfig.Module, params *AppsDetectParams, recursive bool) (techToTargetWorkingDirs map[techutils.Technology]map[string][]string, err error) {
	if !fileutils.IsPathExists(requestedDirectory, false) {
		err = fmt.Errorf("The working directory doesn't exist")
		return
	}
	excludePatterns := params.Exclusions
	if localModuleConfig != nil && len(excludePatterns) == 0 {
		// Use local module exclude patterns if not provided by the user
		excludePatterns = localModuleConfig.ExcludePatterns
	}
	return techutils.DetectTechnologiesDescriptors(
		requestedDirectory,
		recursive,
		params.RequestedTechnologies,
		params.RequestedDescriptorsCustomNames,
		utils.GetExcludePattern(recursive, excludePatterns...),
	)
}

func GetTargetScanConfigurations(target configs.ScanTarget, localModule *jfrogappsconfig.Module, techToTargetWorkingDirs map[techutils.Technology]map[string][]string, params *AppsDetectParams, entitledForJas, targetDetectionMode bool) (targetConfigs []configs.ScanTargetConfig, err error) {
	// Create target configuration for each detected technology
	for tech, workingDirs := range techToTargetWorkingDirs {
		if tech == techutils.Dotnet {
			// We detect Dotnet and Nuget the same way, if one detected so does the other.
			// We don't need to scan for both and get duplicate results.
			continue
		}
		if !targetDetectionMode {
			// Create target configuration for the detected technology in the target
			targetConfigs = append(targetConfigs, CreateTargetScanConfigurations(target, localModule, params, entitledForJas, &tech, workingDirs[target.Target]...))
			continue
		}
		// Create target configuration for each detected working directory with a supported technology
		for workingDir, descriptors := range workingDirs {
			targetConfigs = append(targetConfigs, CreateTargetScanConfigurations(configs.ScanTarget{Target: workingDir}, localModule, params, entitledForJas, &tech, descriptors...))
		}
	}
	if len(targetConfigs) > 0 {
		return
	}
	if utils.ShouldPreformSubScan(params.RequestedSubScans, utils.ScaScan) {
		log.Info(fmt.Sprintf("Couldn't determine a package manager or build tool used in '%s'. Skipping the SCA scan...", target.Target))
	}
	if !entitledForJas {
		return
	}
	// Create target configuration for JAS scan
	targetConfigs = append(targetConfigs, CreateTargetScanConfigurations(target, localModule, params, entitledForJas, nil))
	return
}

func CreateTargetScanConfigurations(target configs.ScanTarget, localModule *jfrogappsconfig.Module, params *AppsDetectParams, entitledForJas bool, tech *techutils.Technology, descriptors ...string) (targetConfig configs.ScanTargetConfig) {
	targetConfig = configs.ScanTargetConfig{ScanTarget: target}
	// Create SCA scan configuration
	if tech != nil && ShouldPreformScanner(params.RequestedSubScans, localModule, utils.ScaScan) {
		targetConfig.Technology = *tech
		targetConfig.ScaScanConfig = &configs.TargetTechConfig{Descriptors: descriptors}
	}
	// Create JAS scan configurations
	if !entitledForJas {
		return
	}
	targetConfig.JasScanConfigs = &configs.JasScannersConfig{}
	if tech != nil && ShouldPreformScanner(params.RequestedSubScans, localModule, utils.ScaScan, utils.ContextualAnalysisScan) {
		targetConfig.JasScanConfigs.Applicability = GetScannerConfig(target, nil, params, utils.ContextualAnalysisScan)
	}
	if ShouldPreformScanner(params.RequestedSubScans, localModule, utils.SecretsScan) {
		targetConfig.JasScanConfigs.Secrets = GetScannerConfig(target, localModule, params, utils.SecretsScan)
	}
	if ShouldPreformScanner(params.RequestedSubScans, localModule, utils.IacScan) {
		targetConfig.JasScanConfigs.Iac = GetScannerConfig(target, localModule, params, utils.IacScan)
	}
	if ShouldPreformScanner(params.RequestedSubScans, localModule, utils.SastScan) {
		targetConfig.JasScanConfigs.Sast = GetSastScannerConfig(target, localModule, params)
	}

	return
}

func ShouldPreformScanner(requestedSubScans []utils.SubScanType, module *jfrogappsconfig.Module, relatedSubScans ...utils.SubScanType) bool {
	if len(requestedSubScans) > 0 {
		// If the user input requested to preform the scan, preform it
		if utils.ShouldPreformSubScan(requestedSubScans, relatedSubScans...) {
			return true
		}
	}
	// If local configuration does not exist, preform the scan
	if module == nil {
		return true
	}
	// If the scanner is excluded in the local configuration, skip it
	for _, scan := range relatedSubScans {
		if ShouldSkipScanner(module, scan) {
			return false
		}
	}
	return true
}

func GetScannerConfig(target configs.ScanTarget, localModule *jfrogappsconfig.Module, params *AppsDetectParams, scannerType utils.SubScanType) (scannerConfig *configs.ScannerConfig) {
	localScanner := getLocalScanner(localModule, scannerType)
	if localScanner == nil {
		// No local configuration, use user input (or default) in detected target
		return &configs.ScannerConfig{WorkingDirs: []string{target.Target}, ExcludePatterns: utils.GetExclusions(params.Exclusions...)}
	}
	// Use local configuration
	return &configs.ScannerConfig{
		WorkingDirs:     localScanner.WorkingDirs,
		ExcludePatterns: utils.GetExclusions(localScanner.ExcludePatterns...),
	}
}

func GetSastScannerConfig(target configs.ScanTarget, localModule *jfrogappsconfig.Module, params *AppsDetectParams) (sastScannerConfig *configs.SastScannerConfig) {
	if localModule == nil || localModule.Scanners.Sast == nil {
		// No local configuration, use user input (or default) in detected target
		return &configs.SastScannerConfig{ScannerConfig: configs.ScannerConfig{WorkingDirs: []string{target.Target}, ExcludePatterns: utils.GetExclusions()}}
	}
	return &configs.SastScannerConfig{
		ScannerConfig: *GetScannerConfig(target, localModule, params, utils.SastScan),
		Language:      localModule.Scanners.Sast.Language,
		ExcludedRules: localModule.Scanners.Sast.ExcludedRules,
	}
}

func ShouldSkipScanner(module *jfrogappsconfig.Module, scanType utils.SubScanType) bool {
	if module == nil {
		return false
	}
	lowerScanType := strings.ToLower(scanType.String())
	if slices.Contains((*module).ExcludeScanners, lowerScanType) {
		return true
	}
	return false
}
