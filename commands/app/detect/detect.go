package detect

import (
	"fmt"
	"os"
	"path/filepath"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"golang.org/x/exp/slices"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results/output"
	"github.com/jfrog/jfrog-cli-security/utils/scanconfig"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"

	"github.com/jfrog/jfrog-cli-security/utils/xray"
)

// From user input
type AppsDetectParams struct {
	WorkingDirs []string
	Exclusions  []string

	RequestedTechnologies []string // ?
	RequestedDescriptorsCustomNames map[techutils.Technology][]string // ?
	RequestedSubScans     []utils.SubScanType  // ?
}

type DetectAppsCommand struct {
	serverDetails *config.ServerDetails
	params 	  *AppsDetectParams
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

func RunDetectSecurityConfig(serverDetails *config.ServerDetails, params *AppsDetectParams) (*scanconfig.AppsSecurityConfig, error) {
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
		if module.Scanners.Iac {
			module.Scanners.Iac.WorkingDirs = getLocalScannerRoots(root, module, module.Scanners.Iac)
		}
		if module.Scanners.Secrets {
			module.Scanners.Secrets.WorkingDirs = getLocalScannerRoots(root, module, module.Scanners.Secrets)
		}
		if module.Scanners.Sast {
			module.Scanners.Sast.WorkingDirs = getLocalScannerRoots(root, module, module.Scanners.Sast)
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

func GenerateAppsSecurityConfig(localConfiguration *jfrogappsconfig.JFrogAppsConfig, params *AppsDetectParams, entitledForJas bool, xrayVersion string) (appsConfig *scanconfig.AppsSecurityConfig, err error) {
	appsConfig = &scanconfig.AppsSecurityConfig{XrayVersion: xrayVersion, EntitledForJas: entitledForJas}
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
		scanTargets = append(scanTargets, scanconfig.ScanTarget{Target: currentWorkingDir})
	}
	// Detect actual targets and generate configurations for each
	for _, potentialTarget := range scanTargets {
		localModule, err := getLocalScanModule(localConfiguration, potentialTarget.Target)
		if err != nil {
			log.Warn(fmt.Sprintf("Failed to get local scan configuration for target '%s'. Skipping...", potentialTarget.String()))
			continue
		}
		fileSystemInfo, err := DetectWorkingDirectoryInformation(potentialTarget.Target, params, targetDetectionMode) 
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

func GetTargets(localConfig *jfrogappsconfig.JFrogAppsConfig, params *AppsDetectParams) (targets []scanconfig.ScanTarget, err error) {
	// If user input parameters, use them
	workingDirs, err := coreutils.GetFullPathsWorkingDirs(params.WorkingDirs)
	if err != nil {
		return
	}
	if len(workingDirs) > 0 {
		log.Info(fmt.Sprintf("Using the provided working directories from the command line: %v", workingDirs))
		for _, workingDir := range workingDirs {
			targets = append(targets, scanconfig.ScanTarget{Target: workingDir})
		}
		return
	}
	// If local configuration exists, use it
	if localConfig != nil {
		log.Info("Using the modules from the local scan configuration")
		for _, module := range localConfig.Modules {
			targets = append(targets, scanconfig.ScanTarget{Target: module.SourceRoot, Name: module.Name})
		}
	}
	return
}

func getLocalScanModule(jfrogAppsConfig *jfrogappsconfig.JFrogAppsConfig, target string) (module *jfrogappsconfig.Module, err error) {
	if jfrogAppsConfig == nil {
		return nil, nil
	}
	for _, m := range jfrogAppsConfig.Modules {
		if moduleRoot == target {
			return &m, nil
		}
	}
	return nil, nil
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

func GetTargetScanConfigurations(target scanconfig.ScanTarget, localModule *jfrogappsconfig.Module, techToTargetWorkingDirs map[techutils.Technology]map[string][]string, params *AppsDetectParams, entitledForJas, targetDetectionMode bool) (targetConfigs []scanconfig.ScanTargetConfig, err error) {
	// Create target configuration for each detected technology
	for tech, workingDirs := range techToTargetWorkingDirs {
		if tech == techutils.Dotnet {
			// We detect Dotnet and Nuget the same way, if one detected so does the other.
			// We don't need to scan for both and get duplicate results.
			continue
		}
		if !targetDetectionMode {
			// Create target configuration for the detected technology in the target
			targetConfigs = append(targetConfigs, CreateTargetScanConfigurations(target, localModule, params.RequestedSubScans, entitledForJas, &tech, workingDirs[target.Target]...))
			continue
		}
		// Create target configuration for each detected working directory with a supported technology
		for workingDir, descriptors := range workingDirs {
			targetConfigs = append(targetConfigs, CreateTargetScanConfigurations(scanconfig.ScanTarget{Target: workingDir}, localModule, params.RequestedSubScans, entitledForJas, &tech, descriptors...))
		}
	}
	if len (targetConfigs) > 0 {
		return
	}
	if len(params.RequestedTechnologies) == 0 || slices.Contains(params.RequestedTechnologies, utils.ScaScan) {
		log.Info(fmt.Sprintf("Couldn't determine a package manager or build tool used in '%s'. Skipping the SCA scan...", target.Target))
	}
	if !entitledForJas {
		return
	}
	// Create target configuration for JAS scan
	targetConfigs = append(targetConfigs, CreateTargetScanConfigurations(target, localModule, params.RequestedSubScans, entitledForJas, nil))
	return
}

func CreateTargetScanConfigurations(target scanconfig.ScanTarget, localModule *jfrogappsconfig.Module, requestedSubScans []utils.SubScanType, entitledForJas bool, tech *techutils.Technology, descriptors ...string) (targetConfig scanconfig.ScanTargetConfig) {
	targetConfig = scanconfig.ScanTargetConfig{ScanTarget: target}
	// Create SCA scan configuration
	if tech != nil && (len(requestedSubScans) == 0 || slices.Contains(requestedSubScans, utils.ScaScan)) {
		targetConfig.Technology = *tech
		targetConfig.ScaScanConfig = &scanconfig.ScaConfig{Descriptors: descriptors}
	}
	// Create JAS scan configurations
	if !entitledForJas {
		return
	}
	targetConfig.JasScanConfigs = &scanconfig.ScannersConfig{
		Secrets: convertScannerInfo(localModule.Scanners.Secrets),
	}
	return
}

func GetScannerConfig(target scanconfig.ScanTarget, localScannerConfig *jfrogappsconfig.Scanner) (scannerConfig *scanconfig.ScannerConfig) {
	if localScannerConfig == nil {
		return
	}
	return &scanconfig.ScannerConfig{
		WorkingDirs: localScannerConfig.WorkingDirs,
		ExcludePatterns: localScannerConfig.ExcludePatterns,
	}
}

func convertScannerInfo(localModule *jfrogappsconfig.Module, scanner *jfrogappsconfig.Scanner) *scanconfig.ScannerConfig {
	if scanner == nil {
		return nil
	}
	scannerWorkingDirs, err := GetSourceRoots(localModule, scanner)
	return &scanconfig.ScannerConfig{
		WorkingDirs: ,
		ExcludePatterns: scanner.ExcludePatterns,
	}
}

func convertSastScannerInfo(scanner *jfrogappsconfig.SastScanner) *scanconfig.SastScannerConfig {
	if scanner == nil {
		return nil
	}
	converted := &scanconfig.SastScannerConfig{
		Language: scanner.Language,
		ExcludedRules: scanner.ExcludedRules,
	}
	if baseConfig := convertScannerInfo(&scanner.Scanner); baseConfig != nil {
		converted.ScannerConfig = *baseConfig
	} 
	return converted
}


func ShouldSkipScanner(module jfrogappsconfig.Module, scanType jasutils.JasScanType) bool {
	lowerScanType := strings.ToLower(string(scanType))
	if slices.Contains(module.ExcludeScanners, lowerScanType) {
		log.Info(fmt.Sprintf("Skipping %s scanning", scanType))
		return true
	}
	return false
}

func GetExcludePatterns(module jfrogappsconfig.Module, scanner *jfrogappsconfig.Scanner) []string {
	excludePatterns := module.ExcludePatterns
	if scanner != nil {
		excludePatterns = append(excludePatterns, scanner.ExcludePatterns...)
	}
	if len(excludePatterns) == 0 {
		return DefaultExcludePatterns
	}
	return excludePatterns
}


















func DetectTargetsMetadata(appsConfig *scanconfig.AppsSecurityConfig, params *AppsDetectParams) (err error) {
	detectedModules, techToWorkingDirs, err := DetectTargetsDescriptorsAndTechnologies(params)
	if err != nil {
		return
	}
	// Add detected modules metadata to the configuration
	for _, module := range detectedModules {
		configurationTarget := appsConfig.GetScanTarget(module.Target)
		if configurationTarget == nil {
			log.Warn(fmt.Sprintf("No configuration found for detected target '%s'. Skipping...", module.String()))
			continue
		}
		log.Debug(fmt.Sprintf("Detected target '%s' with technology '%s'", module.String(), module.Technology.ToFormal()))
		// Set technology and name if not provided and detected
		if configurationTarget.Technology == "" {
			configurationTarget.Technology = module.Technology
		}
		if configurationTarget.Name == "" {
			configurationTarget.Name = module.Name
		}
	}
	return
}

func GetTargetsScanConfigurations(params *AppsDetectParams, xrayVersion string, entitledForJas bool) (appsConfig *scanconfig.AppsSecurityConfig, err error) {
	// Get remote security config (TODO: when API ready)

	// Get local config (if exists)
	appsConfig, err = tryLoadLocalScanConfig(xrayVersion, entitledForJas)
	if err != nil {
		return
	}
	workingDirs, err := coreutils.GetFullPathsWorkingDirs(params.WorkingDirs)
	if err != nil {
		return
	}
	if appsConfig != nil && len(appsConfig.Targets) > 0 {
		if len(workingDirs) > 0 {
			log.Warn("Local scan configuration found, but working directories were provided. Ignoring working directories.")
		}
		return
	}
	// Create scan profile based on user input (remote, local, flags, env...)
	if appsConfig == nil {
		appsConfig = &scanconfig.AppsSecurityConfig{ XrayVersion: xrayVersion, EntitledForJas: entitledForJas }
	}
	if len(workingDirs) == 0 {
		// No working directories provided
		return
	}
	for _, workingDir := range workingDirs {
		appsConfig.Targets = append(appsConfig.Targets, scanconfig.ScanTargetConfig{
			ScanTarget: scanconfig.ScanTarget{Target: module.SourceRoot, Name: module.Name},
			ExcludePatterns: module.ExcludePatterns,
			JasScanConfigs: jasConfig,
		})
	}

	isRecursiveDetection := len(workingDirs) == 0

	if appsConfig.AppsConfig, err = createJFrogAppsConfig(workingDirs); err != nil || appsConfig.AppsConfig != nil {
		return
	}

	if appsConfig.AppsConfig == nil {
		// Create default config based on workingDirs
		appsConfig.AppsConfig = new(jfrogappsconfig.JFrogAppsConfig)
		for _, workingDir := range workingDirs {
			appsConfig.AppsConfig.Modules = append(appsConfig.AppsConfig.Modules, jfrogappsconfig.Module{SourceRoot: workingDir})
		}
	}

	// Create scan profile based on user input (remote, local, flags, env...)

	// Detect tech information and descriptors (+ detect modules if needed -> create config based on default profile)
	isRecursiveDetection := len(params.WorkingDirs) == 0 // If no workingDirs were provided by the user, we apply a recursive scan on the root repository
}



func tryLoadLocalScanConfig(xrayVersion string, entitledForJas bool) (appsConfig *scanconfig.AppsSecurityConfig, err error) {
	jfrogAppsConfig, err := jfrogappsconfig.LoadConfigIfExist()
	if err != nil {
		return nil, errorutils.CheckError(err)
	}
	if jfrogAppsConfig == nil {
		log.Debug("No local scan configuration found for the current workspace.")
		return
	}
	appsConfig = &scanconfig.AppsSecurityConfig{XrayVersion: xrayVersion, EntitledForJas: entitledForJas}
	// Convert loaded local scan config
	for _, module := range jfrogAppsConfig.Modules {
		var jasConfig *scanconfig.ScannersConfig
		if entitledForJas {
			jasConfig = &scanconfig.ScannersConfig{}
			if module.Scanners.Secrets != nil && !slices.Contains(module.ExcludeScanners, utils.SecretsScan.String()) {
				jasConfig.Secrets = convertScannerInfo(module.Scanners.Secrets)
			}
			if module.Scanners.Iac != nil && !slices.Contains(module.ExcludeScanners, utils.IacScan.String()) {
				jasConfig.Iac = convertScannerInfo(module.Scanners.Iac)
			}
			if module.Scanners.Sast != nil && !slices.Contains(module.ExcludeScanners, utils.SastScan.String()) {
				jasConfig.Sast = convertSastScannerInfo(module.Scanners.Sast)
			}
		}
		appsConfig.Targets = append(appsConfig.Targets, scanconfig.ScanTargetConfig{
			ScanTarget: scanconfig.ScanTarget{Target: module.SourceRoot, Name: module.Name},
			ExcludePatterns: utils.GetExcludePattern(false, module.ExcludePatterns...),
			JasScanConfigs: jasConfig,
		})
	}
	localStr := "Loaded local scan configurations"
	if str, err := utils.GetAsJsonString(appsConfig); err != nil {
		localStr = fmt.Sprintf("%s\n%s", localStr, str)
	}
	log.Debug(localStr)
	return
}

func getDefaultTargetConfig(workingDir string, entitledForJas bool) *scanconfig.ScanTargetConfig {
	var jasConfig *scanconfig.ScannersConfig
	if entitledForJas {
		jasConfig = &scanconfig.ScannersConfig{
			Secrets: &scanconfig.ScannerConfig{WorkingDirs: []string{workingDir}, ExcludePatterns: utils.GetExcludePattern(true)},
			Iac: &scanconfig.ScannerConfig{WorkingDirs: []string{workingDir}, ExcludePatterns: utils.GetExcludePattern(true)},
			Sast: &scanconfig.SastScannerConfig{ScannerConfig: scanconfig.ScannerConfig{WorkingDirs: []string{workingDir}, ExcludePatterns: utils.GetExcludePattern(true)}},
		}
	}
	return &scanconfig.ScanTargetConfig{
		ScanTarget: scanconfig.ScanTarget{Target: workingDir},
		ExcludePatterns: utils.GetExcludePattern(true),
		JasScanConfigs: jasConfig,
	}
}

func generateTargetConfig(target, name string, technology techutils.Technology, excludePatterns []string, scaScanConfig *scanconfig.ScaConfig, jasScanConfigs *scanconfig.ScannersConfig) *scanconfig.ScanTargetConfig {
	var jasConfig *scanconfig.ScannersConfig
		if entitledForJas {
			jasConfig = &scanconfig.ScannersConfig{}
			if module.Scanners.Secrets != nil && !slices.Contains(module.ExcludeScanners, utils.SecretsScan.String()) {
				jasConfig.Secrets = convertScannerInfo(module.Scanners.Secrets)
			}
			if module.Scanners.Iac != nil && !slices.Contains(module.ExcludeScanners, utils.IacScan.String()) {
				jasConfig.Iac = convertScannerInfo(module.Scanners.Iac)
			}
			if module.Scanners.Sast != nil && !slices.Contains(module.ExcludeScanners, utils.SastScan.String()) {
				jasConfig.Sast = convertSastScannerInfo(module.Scanners.Sast)
			}
		}
		return &scanconfig.ScanTargetConfig{
			ScanTarget: scanconfig.ScanTarget{Target: target, Name: name},
			ExcludePatterns: module.ExcludePatterns,
			JasScanConfigs: jasConfig,
		}
}

func convertScannerInfo(scanner *jfrogappsconfig.Scanner) *scanconfig.ScannerConfig {
	if scanner == nil {
		return nil
	}
	return &scanconfig.ScannerConfig{
		WorkingDirs: scanner.WorkingDirs,
		ExcludePatterns: scanner.ExcludePatterns,
	}
}

func convertSastScannerInfo(scanner *jfrogappsconfig.SastScanner) *scanconfig.SastScannerConfig {
	if scanner == nil {
		return nil
	}
	converted := &scanconfig.SastScannerConfig{
		Language: scanner.Language,
		ExcludedRules: scanner.ExcludedRules,
	}
	if baseConfig := convertScannerInfo(&scanner.Scanner); baseConfig != nil {
		converted.ScannerConfig = *baseConfig
	} 
	return converted
}

func createModuleConfig()

func createJFrogAppsConfig(workingDirs []string) (*jfrogappsconfig.JFrogAppsConfig, error) {
	if jfrogAppsConfig, err := jfrogappsconfig.LoadConfigIfExist(); err != nil {
		return nil, errorutils.CheckError(err)
	} else if jfrogAppsConfig != nil {
		// jfrog-apps-config.yml exist in the workspace
		return jfrogAppsConfig, nil
	}

	// jfrog-apps-config.yml does not exist in the workspace
	fullPathsWorkingDirs, err := coreutils.GetFullPathsWorkingDirs(workingDirs)
	if err != nil {
		return nil, err
	}
	jfrogAppsConfig := new(jfrogappsconfig.JFrogAppsConfig)
	for _, workingDir := range fullPathsWorkingDirs {
		jfrogAppsConfig.Modules = append(jfrogAppsConfig.Modules, jfrogappsconfig.Module{SourceRoot: workingDir})
	}
	return jfrogAppsConfig, nil
}

func DetectTargetsDescriptorsAndTechnologies(params *AppsDetectParams) (targets []scanconfig.ScanTarget, techToWorkingDirs map[techutils.Technology]map[string][]string, err error) {
	workingDirs, err := coreutils.GetFullPathsWorkingDirs(params.WorkingDirs)
	if err != nil {
		return
	}
	currentWorkingDir, err := os.Getwd()
	if err != nil {
		return
	}
	isRecursiveDetection := false
	if len(workingDirs) == 0 {
		// recursive from root
		log.Debug(fmt.Sprintf("No working directories provided. Running recursive detection on '%s'", currentWorkingDir))
		workingDirs = []string{currentWorkingDir}
		isRecursiveDetection = true
	}
	for _, requestedWorkingDir := range workingDirs {
		if !fileutils.IsPathExists(requestedWorkingDir, false) {
			log.Warn("The provided working directory", requestedWorkingDir, "doesn't exist. Skipping detection...")
			continue
		}
		// Detect descriptors and technologies in the requested directory.
		currentTechToWorkingDirs, err := techutils.DetectTechnologiesDescriptors(requestedWorkingDir, isRecursiveDetection, params.RequestedTechnologies, params.RequestedDescriptorsCustomNames, utils.GetExcludePattern(isRecursiveDetection, params.Exclusions...))
		if err != nil {
			log.Warn("Couldn't detect technologies in", requestedWorkingDir, "directory.", err.Error())
			continue
		}
		for tech, workingDirs := range currentTechToWorkingDirs {
			if tech == techutils.Dotnet {
				// We detect Dotnet and Nuget the same way, if one detected so does the other.
				// We don't need to scan for both and get duplicate results.
				continue
			}
			if _, ok := techToWorkingDirs[tech]; !ok {
				techToWorkingDirs[tech] = map[string][]string{}
			}
			for workingDir, descriptors := range workingDirs {
				if _, ok := techToWorkingDirs[tech][workingDir]; !ok {
					techToWorkingDirs[tech][workingDir] = descriptors
				} else {
					techToWorkingDirs[tech][workingDir] = append(techToWorkingDirs[tech][workingDir], descriptors...)
				}
					
				
			}
		}



		// Create targets based on detected technologies and descriptors
		for tech, workingDirs := range techToWorkingDirs {
			if tech == techutils.Dotnet {
				// We detect Dotnet and Nuget the same way, if one detected so does the other.
				// We don't need to scan for both and get duplicate results.
				continue
			}
			if len(workingDirs) == 0 {
				// Requested technology (from params) descriptors/indicators was not found, scan only requested directory for this technology.
				targets = append(targets, scanconfig.ScanTarget{Target: requestedWorkingDir, Technology: tech})
			} 
			for workingDir, descriptors := range workingDirs {
				// Add scan for each detected working directory.
				targets = append(targets, scanconfig.ScanTarget{Target: workingDir, Technology: tech, Descriptors: descriptors})
			}
		}
	}

	return
}

// Calculate the scans to preform
func getScaScansToPreform(params *AuditParams) (scansToPreform []*xrayutils.ScaScanResult) {
	for _, requestedDirectory := range params.workingDirs {
		if !fileutils.IsPathExists(requestedDirectory, false) {
			log.Warn("The working directory", requestedDirectory, "doesn't exist. Skipping SCA scan...")
			continue
		}
		// Detect descriptors and technologies in the requested directory.
		techToWorkingDirs, err := techutils.DetectTechnologiesDescriptors(requestedDirectory, params.IsRecursiveScan(), params.Technologies(), getRequestedDescriptors(params), sca.GetExcludePattern(params.AuditBasicParams))
		if err != nil {
			log.Warn("Couldn't detect technologies in", requestedDirectory, "directory.", err.Error())
			continue
		}
		// Create scans to preform
		for tech, workingDirs := range techToWorkingDirs {
			if tech == techutils.Dotnet {
				// We detect Dotnet and Nuget the same way, if one detected so does the other.
				// We don't need to scan for both and get duplicate results.
				continue
			}
			if len(workingDirs) == 0 {
				// Requested technology (from params) descriptors/indicators was not found, scan only requested directory for this technology.
				scansToPreform = append(scansToPreform, &xrayutils.ScaScanResult{Target: requestedDirectory, Technology: tech})
			}
			for workingDir, descriptors := range workingDirs {
				// Add scan for each detected working directory.
				scansToPreform = append(scansToPreform, &xrayutils.ScaScanResult{Target: workingDir, Technology: tech, Descriptors: descriptors})
			}
		}
	}
	return
}

func getRequestedDescriptors(params *AuditParams) map[techutils.Technology][]string {
	requestedDescriptors := map[techutils.Technology][]string{}
	if params.PipRequirementsFile() != "" {
		requestedDescriptors[techutils.Pip] = []string{params.PipRequirementsFile()}
	}
	return requestedDescriptors
}
