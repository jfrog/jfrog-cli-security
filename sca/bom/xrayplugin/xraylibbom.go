package xrayplugin

import (
	"fmt"
	"os/exec"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/sca/bom"
	"github.com/jfrog/jfrog-cli-security/sca/bom/xrayplugin/plugin"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

type XrayLibBomGenerator struct {
	binaryPath     string
	ignorePatterns []string
	totalTargets   int
}

func NewXrayLibBomGenerator() *XrayLibBomGenerator {
	return &XrayLibBomGenerator{}
}

func WithTotalTargets(totalTargets int) bom.SbomGeneratorOption {
	return func(sg bom.SbomGenerator) {
		if sbg, ok := sg.(*XrayLibBomGenerator); ok {
			sbg.totalTargets = totalTargets
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

func WithIgnorePatterns(ignorePatterns []string) bom.SbomGeneratorOption {
	return func(sg bom.SbomGenerator) {
		if sbg, ok := sg.(*XrayLibBomGenerator); ok {
			sbg.ignorePatterns = ignorePatterns
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
	startTime := time.Now()
	scanner, logPath, err := plugin.CreateScannerPluginClient(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create Xray-Lib plugin client: %w", err)
	}
	startLog := "Generating SBOM"
	if sbg.totalTargets > 1 {
		startLog += fmt.Sprintf(" for target: %s", target.Target)
	}
	if logPath != "" {
		startLog += fmt.Sprintf(" (plugin logs: %s)", logPath)
	}
	log.Info(startLog + "...")
	// Run the xray-lib command to generate the SBOM
	if sbom, err = sbg.executeScanner(scanner, target); err != nil {
		return nil, fmt.Errorf("failed to execute Xray-Lib command: %w", err)
	}
	sbg.logScannerOutput(sbom, target.Target, startTime)
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
		IgnorePatterns: sbg.ignorePatterns,
	}
	if scanConfigStr, err := utils.GetAsJsonString(scanConfig, false, true); err == nil {
		log.Debug(fmt.Sprintf("Scan configuration: %s", scanConfigStr))
	}
	return scanner.Scan(target.Target, scanConfig)
}

func (sbg *XrayLibBomGenerator) logScannerOutput(output *cyclonedx.BOM, target string, startTime time.Time) {
	libComponents := []string{}
	if output != nil && output.Components != nil {
		for _, component := range *output.Components {
			if component.Type == cyclonedx.ComponentTypeLibrary {
				libComponents = append(libComponents, component.PackageURL)
			}
		}
	}
	outLog := "SBOM generated"
	if sbg.totalTargets > 1 {
		outLog += fmt.Sprintf(" for target '%s'", target)
	}
	outLog += ";"
	if len(libComponents) == 0 {
		outLog += " no library components were found"
	} else {
		outLog += fmt.Sprintf(" found %d library components", len(libComponents))
	}
	log.Info(fmt.Sprintf("%s (duration %s)", outLog, time.Since(startTime).String()))
}

func (sbg *XrayLibBomGenerator) CleanUp() (err error) {
	// No cleanup needed for XrayLibBomGenerator
	return nil
}
