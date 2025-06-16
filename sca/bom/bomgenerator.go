package bom

import (
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"

	"github.com/jfrog/jfrog-client-go/utils/log"
)

// SbomGenerator is an interface for generating SBOMs from different sources.
type SbomGenerator interface {
	// PrepareGenerator prepares the generator for SBOM generation, should be called once before generating SBOMs.
	PrepareGenerator(options ...SbomGeneratorOption) error
	// GenerateSbom generates a CycloneDX SBOM for the given target.
	GenerateSbom(target results.ScanTarget) (*cyclonedx.BOM, error)
}

type SbomGeneratorOption func(sg SbomGenerator) error

type SbomGeneratorParams struct {
	Target               *results.TargetResults
	AllowPartialResults  bool
	ScanResultsOutputDir string
}

func GenerateSbomForTarget(generator SbomGenerator, params SbomGeneratorParams) {
	// Generate the SBOM for the target
	sbom, err := generator.GenerateSbom(params.Target.ScanTarget)
	if err != nil {
		_ = params.Target.AddTargetError(fmt.Errorf("failed to generate SBOM for %s: %s", params.Target.Target, err.Error()), params.AllowPartialResults)
		return
	}
	if err = logLibComponents(sbom.Components); err != nil {
		log.Warn(fmt.Sprintf("Failed to log library components in SBOM for %s: %s", params.Target.Target, err.Error()))
	}
	// Set the SBOM in the target results and update target information
	updateTarget(params.Target, sbom)
	// Save the SBOM to a file
	if params.ScanResultsOutputDir == "" {
		return
	}
	if err = utils.DumpCdxContentToFile(sbom, params.ScanResultsOutputDir, "bom"); err != nil {
		log.Warn(fmt.Sprintf("Failed to dump CycloneDX SBOM for %s: %s", params.Target.Target, err.Error()))
	}
}

func logLibComponents(components *[]cyclonedx.Component) (err error) {
	if log.GetLogger().GetLogLevel() != log.DEBUG {
		// Avoid printing and marshaling if not on DEBUG mode.
		return
	}
	libs := []string{}
	for _, component := range *components {
		if component.Type == cyclonedx.ComponentTypeLibrary {
			libs = append(libs, component.Name)
		}
	}
	if len(libs) == 0 {
		log.Debug("No library components found in the SBOM.")
		return
	}
	// Log the unique library components in the SBOM.
	str, err := utils.GetAsJsonString(libs, false, true)
	if err != nil {
		return err
	}
	log.Debug(fmt.Sprintf("Unique library components in SBOM:\n%s", str))
	return
}

func updateTarget(target *results.TargetResults, sbom *cyclonedx.BOM) {
	target.SetSbom(sbom)
	if target.Name != "" {
		// Target name is already set, no need to update.
		return
	}
	roots := cdxutils.GetRootDependenciesEntries(sbom.Dependencies)
	if len(roots) == 0 {
		// No root dependencies found, nothing to update.
		return
	}
	if len(roots) > 1 {
		log.Warn(fmt.Sprintf("Found multiple root dependencies in the SBOM for target '%s'. Only the first one will be used as the root component.", target.Target))
	}
	for _, root := range roots {
		rootComponent := cdxutils.SearchComponentByRef(sbom.Components, root.Ref)
		if rootComponent == nil {
			log.Warn(fmt.Sprintf("Root component '%s' not found in the SBOM components for target '%s'.", root.Ref, target.Target))
			continue
		}
		// Update the target with the root component information.
		target.Name, _, _ = techutils.SplitPackageURL(rootComponent.PackageURL)
		return
	}
}
