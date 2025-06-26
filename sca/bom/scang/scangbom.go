package scang

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/sca/bom"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	defaultScangPluginVersion             = "1.0.0"
	jfrogCliScangPluginVersionEnvVariable = "JFROG_CLI_SCANG_PLUGIN_VERSION"

	scangPluginDirName        = "scang"
	scangPluginExecutableName = "scangplugin"
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

func getScangPluginVersion() string {
	if versionEnv := os.Getenv(jfrogCliScangPluginVersionEnvVariable); versionEnv != "" {
		return versionEnv
	}
	return defaultScangPluginVersion
}

func (sbg *ScangBomGenerator) PrepareGenerator() (err error) {
	// Validate the binary path if provided
	if sbg.binaryPath != "" {
		exists, err := fileutils.IsFileExists(sbg.binaryPath, false)
		if err == nil && !exists {
			err = fmt.Errorf("unable to locate the scang executable at %s", sbg.binaryPath)
		}
		return err
	}
	// Download the scang plugin if needed
	return
}

func (sbg *ScangBomGenerator) GenerateSbom(target results.ScanTarget) (sbom *cyclonedx.BOM, err error) {
	log.Info(fmt.Sprintf("Generating SBOM for target: %s", target.Target))
	binaryPath, err := sbg.getLocalScangExecutablePath()
	if err != nil {
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

func getScangExecutableName() string {
	if coreutils.IsWindows() {
		return scangPluginExecutableName + ".exe"
	}
	return scangPluginExecutableName
}

func (sbg *ScangBomGenerator) getLocalScangExecutablePath() (scangPath string, err error) {
	// If binaryPath is set, use it directly
	if sbg.binaryPath != "" {
		scangPath = sbg.binaryPath
		return
	}
	// Check if exists in JFrog CLI directory
	jfrogDir, err := config.GetJfrogDependenciesPath()
	if err != nil {
		return
	}
	scangPath = filepath.Join(jfrogDir, scangPluginDirName, getScangExecutableName())
	exists, err := fileutils.IsFileExists(scangPath, false)
	if err != nil || exists {
		return
	}
	// If not found, check in $PATH
	return exec.LookPath(scangPluginExecutableName)
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
	log.Debug(utils.GetAsJsonString(libComponents, false, true))
	log.Info(fmt.Sprintf("SBOM generated for target '%s': (%d lib Components)", target, len(libComponents)))
}

func (sbg *ScangBomGenerator) CleanUp() (err error) {
	// No cleanup needed for ScangBomGenerator
	return nil
}
