package detect

import (
	"fmt"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"golang.org/x/exp/slices"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results/output"
	"github.com/jfrog/jfrog-cli-security/utils/scanconfig"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"

	"github.com/jfrog/jfrog-cli-security/utils/xray"
)

// From user input
type AppsDetectParams struct {
	WorkingDirs []string
	Exclusions  []string

	RequestedTechnologies coreutils.Technology // ?
	RequestedSubScans     []utils.SubScanType  // ?

	PipRequirementsFile string
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

func RunDetectSecurityConfig(serverDetails *config.ServerDetails, params *AppsDetectParams) (appsConfig *scanconfig.AppsSecurityConfig, err error) {
	xrayManager, xrayVersion, err := xray.CreateXrayServiceManagerAndGetVersion(serverDetails)
	if err != nil {
		return
	}
	workingDirs, err := coreutils.GetFullPathsWorkingDirs(params.WorkingDirs)
	if err != nil {
		return
	}
	entitledForJas, err := jas.IsEntitledForJas(xrayManager, xrayVersion)
	if err != nil {
		return
	}

	

	return
}

func handleScanConfigurations(params *scanconfig.AppsSecurityConfig, xrayVersion string, entitledForJas bool) (appsConfig *scanconfig.AppsSecurityConfig, err error) {
	appsConfig = &scanconfig.AppsSecurityConfig{ XrayVersion: xrayVersion, EntitledForJas: entitledForJas }

	// Get remote security config (TODO: when API ready)

	// Get local config (if exists)
	localConfig, err = tryLoadLocalScanConfig()
	if err != nil {
		return
	}

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
			ExcludePatterns: module.ExcludePatterns,
			JasScanConfigs: jasConfig,
		})
	}
	return
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
