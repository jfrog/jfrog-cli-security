package xrayplugin

import (
	"fmt"
	"os/exec"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/sca/bom"
	"github.com/jfrog/jfrog-cli-security/sca/bom/xrayplugin/plugin"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

// SnippetDetectionFeatureId is "curation" because snippet detection is gated by the curation entitlement on the Xray server.
const SnippetDetectionFeatureId = "curation"

type XrayLibBomGenerator struct {
	binaryPath       string
	snippetDetection bool
	specificTechs    []techutils.Technology
}

func NewXrayLibBomGenerator() *XrayLibBomGenerator {
	return &XrayLibBomGenerator{}
}

func WithSpecificTechnologies(technologies []string) bom.SbomGeneratorOption {
	return func(sg bom.SbomGenerator) {
		if sbg, ok := sg.(*XrayLibBomGenerator); ok {
			sbg.specificTechs = make([]techutils.Technology, 0, len(technologies))
			for _, tech := range technologies {
				sbg.specificTechs = append(sbg.specificTechs, techutils.Technology(tech))
			}
		}
	}
}

func WithBinaryPath(binaryPath string) bom.SbomGeneratorOption {
	return func(sg bom.SbomGenerator) {
		if sbg, ok := sg.(*XrayLibBomGenerator); ok {
			sbg.binaryPath = binaryPath
		}
	}
}

func WithSnippetDetection(snippetDetection bool) bom.SbomGeneratorOption {
	return func(sg bom.SbomGenerator) {
		if sbg, ok := sg.(*XrayLibBomGenerator); ok {
			sbg.snippetDetection = snippetDetection
		}
	}
}

func (sbg *XrayLibBomGenerator) WithOptions(options ...bom.SbomGeneratorOption) bom.SbomGenerator {
	for _, option := range options {
		option(sbg)
	}
	return sbg
}

func (sbg *XrayLibBomGenerator) PrepareGenerator() (err error) {
	// Validate the binary path if provided
	if sbg.binaryPath != "" {
		exists, err := fileutils.IsFileExists(sbg.binaryPath, false)
		if err == nil && !exists {
			err = fmt.Errorf("unable to locate the Xray-Lib executable at %s", sbg.binaryPath)
		}
		// No need to download the plugin if the binary path is set and valid
		return err
	}
	if envPath, e := exec.LookPath(plugin.XrayLibPluginExecutableName); e == nil && envPath != "" {
		// No need to download the plugin if it's found in the system PATH
		return
	}
	// Download the xray-lib plugin if needed
	return plugin.DownloadXrayLibPluginIfNeeded()
}

func (sbg *XrayLibBomGenerator) GenerateSbom(target results.ScanTarget) (sbom *cyclonedx.BOM, err error) {
	binaryPath, err := sbg.getXrayLibExecutablePath()
	if err != nil || binaryPath == "" {
		return nil, fmt.Errorf("failed to get local Xray-Lib executable path: %w", err)
	}
	log.Debug(fmt.Sprintf("Using Xray-Lib executable at: %s", binaryPath))
	envVars := sbg.getPluginEnvVars()
	scanner, logPath, killPlugin, err := plugin.CreateScannerPluginClient(binaryPath, envVars)
	if err != nil {
		return nil, fmt.Errorf("failed to create Xray-Lib plugin client: %w", err)
	}
	defer killPlugin()
	if logPath != "" {
		log.Debug(fmt.Sprintf("Plugin logs: %s", logPath))
	}
	if len(envVars) > 0 {
		log.Debug(fmt.Sprintf("Environment variables: %v", envVars))
	}
	// Run the xray-lib command to generate the SBOM
	if sbom, err = sbg.executeScanner(scanner, target); err != nil {
		return nil, fmt.Errorf("failed to execute Xray-Lib command: %w", err)
	}
	return
}

func (sbg *XrayLibBomGenerator) getXrayLibExecutablePath() (xrayLibPath string, err error) {
	// If binaryPath is set, use it directly
	if sbg.binaryPath != "" {
		xrayLibPath = sbg.binaryPath
		return
	}
	return plugin.GetLocalXrayLibExecutablePath()
}

func (sbg *XrayLibBomGenerator) executeScanner(scanner plugin.Scanner, target results.ScanTarget) (output *cyclonedx.BOM, err error) {
	scanConfig := plugin.Config{
		BomRef:         cdxutils.GetFileRef(target.Target),
		Type:           string(cyclonedx.ComponentTypeFile),
		Name:           target.Target,
		IgnorePatterns: target.Exclude,
		IncludeDirs:    target.Include,
		Ecosystems:     sbg.specificTechs,
	}
	if scanConfigStr, err := utils.GetAsJsonString(scanConfig, false, true); err == nil {
		log.Debug(fmt.Sprintf("Scan configuration: %s", scanConfigStr))
	}
	return scanner.Scan(target.Target, scanConfig)
}

func (sbg *XrayLibBomGenerator) getPluginEnvVars() map[string]string {
	envVars := map[string]string{}
	if sbg.snippetDetection {
		envVars[plugin.SnippetDetectionEnvVariable] = "true"
	}
	return envVars
}

func (sbg *XrayLibBomGenerator) CleanUp() (err error) {
	// No cleanup needed for XrayLibBomGenerator
	return nil
}
