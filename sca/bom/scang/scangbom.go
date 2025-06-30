package scang

import (
	"fmt"
	"os/exec"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/sca/bom"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

type ScangBomGenerator struct {
	binaryPath     string
	ignorePatterns []string
}

func NewScangBomGenerator() *ScangBomGenerator {
	return &ScangBomGenerator{}
}

func WithBinaryPath(binaryPath string) bom.SbomGeneratorOption {
	return func(sg bom.SbomGenerator) {
		if sbg, ok := sg.(*ScangBomGenerator); ok {
			sbg.binaryPath = binaryPath
		}
	}
}

func WithIgnorePatterns(ignorePatterns []string) bom.SbomGeneratorOption {
	return func(sg bom.SbomGenerator) {
		if sbg, ok := sg.(*ScangBomGenerator); ok {
			sbg.ignorePatterns = ignorePatterns
		}
	}
}

func (sbg *ScangBomGenerator) WithOptions(options ...bom.SbomGeneratorOption) bom.SbomGenerator {
	for _, option := range options {
		option(sbg)
	}
	return sbg
}

func (sbg *ScangBomGenerator) PrepareGenerator() (err error) {
	// Validate the binary path if provided
	if sbg.binaryPath != "" {
		exists, err := fileutils.IsFileExists(sbg.binaryPath, false)
		if err == nil && !exists {
			err = fmt.Errorf("unable to locate the scang executable at %s", sbg.binaryPath)
		}
		// No need to download the plugin if the binary path is set and valid
		return err
	}
	if envPath, err := exec.LookPath(scangPluginExecutableName); err != nil && envPath != "" {
		// No need to download the plugin if it's found in the system PATH
		return nil
	}
	// Download the scang plugin if needed
	return DownloadScangPluginIfNeeded()
}

func (sbg *ScangBomGenerator) GenerateSbom(target results.ScanTarget) (sbom *cyclonedx.BOM, err error) {
	log.Info(fmt.Sprintf("Generating SBOM for target: %s", target.Target))
	binaryPath, err := sbg.getScangExecutablePath()
	if err != nil || binaryPath == "" {
		return nil, fmt.Errorf("failed to get local Scang executable path: %w", err)
	}
	log.Debug(fmt.Sprintf("Using Scang executable at: %s", binaryPath))
	// Run the scang command to generate the SBOM
	if sbom, err = sbg.executeScanner(binaryPath, target); err != nil {
		return nil, fmt.Errorf("failed to execute scang command: %w", err)
	}
	sbg.logScannerOutput(sbom, target.Target)
	return
}

func (sbg *ScangBomGenerator) getScangExecutablePath() (scangPath string, err error) {
	// If binaryPath is set, use it directly
	if sbg.binaryPath != "" {
		scangPath = sbg.binaryPath
		return
	}
	return getLocalScangExecutablePath()
}

func (sbg *ScangBomGenerator) executeScanner(scangBinary string, target results.ScanTarget) (output *cyclonedx.BOM, err error) {
	log.Debug(fmt.Sprintf("Executing command: %s %q", scangBinary, target.Target))
	// Create a new plugin client
	scanner, err := CreateScannerPluginClient(scangBinary)
	if err != nil {
		return nil, fmt.Errorf("failed to create scang plugin client: %w", err)
	}
	scanConfig := Config{
		BomRef:         cdxutils.GetFileRef(target.Target),
		Type:           string(cyclonedx.ComponentTypeFile),
		Name:           target.Target,
		IgnorePatterns: sbg.ignorePatterns,
	}
	return scanner.Scan(target.Target, scanConfig)
}

func (sbg *ScangBomGenerator) logScannerOutput(output *cyclonedx.BOM, target string) {
	libComponents := []string{}
	if output != nil && output.Components != nil {
		for _, component := range *output.Components {
			if component.Type == cyclonedx.ComponentTypeLibrary {
				libComponents = append(libComponents, component.PackageURL)
			}
		}
	}
	if pUrls, err := utils.GetAsJsonString(libComponents, false, true); err == nil {
		log.Debug(pUrls)
	} else {
		log.Debug(fmt.Sprintf("Failed to log SBOM components: %v", err))
	}
	if len(libComponents) == 0 {
		log.Info(fmt.Sprintf("No library components found in SBOM for target '%s'.", target))
	} else {
		log.Info(fmt.Sprintf("SBOM generated for target '%s': (%d lib Components)", target, len(libComponents)))
	}
}

func (sbg *ScangBomGenerator) CleanUp() (err error) {
	// No cleanup needed for ScangBomGenerator
	return nil
}
