package bom

import (
	"fmt"
	"time"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"

	"github.com/jfrog/jfrog-client-go/utils/log"
)

// SbomGenerator is an interface for generating SBOMs from different sources.
type SbomGenerator interface {
	WithOptions(options ...SbomGeneratorOption) SbomGenerator
	// PrepareGenerator prepares the generator for SBOM generation, should be called once before generating SBOMs.
	PrepareGenerator() error
	// GenerateSbom generates a CycloneDX SBOM for the given target.
	GenerateSbom(target results.ScanTarget) (*cyclonedx.BOM, error)
	// CleanUp cleans up any resources used by the generator, should be called after all SBOMs are generated.
	CleanUp() error
}

type SbomGeneratorOption func(sg SbomGenerator)

type SbomGeneratorParams struct {
	Target               *results.TargetResults
	TotalTargets         int
	AllowPartialResults  bool
	ScanResultsOutputDir string

	DiffMode              bool
	TargetResultToCompare *results.TargetResults
}

func GenerateSbomForTarget(generator SbomGenerator, params SbomGeneratorParams) {
	startLog := "Generating SBOM"
	if params.TotalTargets > 1 {
		startLog += fmt.Sprintf(" for target: %s", params.Target.Target)
	}
	log.Info(startLog + "...")
	startTime := time.Now()
	// Generate the SBOM for the target
	sbom, err := generator.GenerateSbom(params.Target.ScanTarget)
	if err != nil {
		params.Target.ResultsStatus.UpdateStatus(results.CmdStepSbom, utils.NewIntPtr(1))
		_ = params.Target.AddTargetError(fmt.Errorf("failed to generate SBOM for %s: %s", params.Target.Target, err.Error()), params.AllowPartialResults)
		return
	}
	if params.DiffMode {
		// If in diff mode, get the diff SBOM compared to the previous target result
		sbom = getDiffSbom(sbom, params)
	}
	if err := logLibComponents(sbom, params.TotalTargets, params.Target.Target, startTime); err != nil {
		log.Warn(fmt.Sprintf("Failed to log library components in SBOM for %s: %s", params.Target.Target, err.Error()))
	}
	// Set the SBOM in the target results and update target information
	updateTarget(params.Target, sbom)
	// Save the SBOM to a file
	if params.ScanResultsOutputDir == "" {
		return
	}
	if _, err = utils.DumpCdxContentToFile(sbom, params.ScanResultsOutputDir, "bom", 0); err != nil {
		log.Warn(fmt.Sprintf("Failed to dump CycloneDX SBOM for %s: %s", params.Target.Target, err.Error()))
	}
}

func getDiffSbom(sbom *cyclonedx.BOM, params SbomGeneratorParams) *cyclonedx.BOM {
	if !params.DiffMode {
		// Not in diff mode, return the original SBOM.
		return sbom
	}
	if params.TargetResultToCompare == nil || params.TargetResultToCompare.ScaResults.Sbom == nil || params.TargetResultToCompare.ScaResults.Sbom.Components == nil {
		// First scan, no previous target result to compare with.
		log.Debug("No previous target result to compare with, returning the original SBOM.")
		return sbom
	}
	log.Debug(fmt.Sprintf("Excluding %s components from %s SBOM", params.TargetResultToCompare.Target, params.Target.Target))
	return cdxutils.Exclude(*sbom, *params.TargetResultToCompare.ScaResults.Sbom.Components...)
}

func updateTarget(target *results.TargetResults, sbom *cyclonedx.BOM) {
	target.SetSbom(sbom)
	target.ResultsStatus.UpdateStatus(results.CmdStepSbom, utils.NewIntPtr(0))
	if target.Name != "" {
		// Target name is already set, no need to update.
		return
	}
	rootsRefs := []string{}
	roots := cdxutils.GetRootDependenciesEntries(sbom, true)
	for _, root := range roots {
		rootsRefs = append(rootsRefs, root.Ref)
	}
	if len(rootsRefs) == 0 {
		// No root dependencies found, nothing to update.
		return
	}
	if len(rootsRefs) > 1 {
		log.Debug(fmt.Sprintf("Found multiple roots in the SBOM for target '%s'.", target.Target))
		return
	}
	rootComponent := cdxutils.SearchComponentByRef(sbom.Components, rootsRefs[0])
	if rootComponent == nil {
		log.Warn(fmt.Sprintf("Root component '%s' not found in the SBOM components for target '%s'.", rootsRefs[0], target.Target))
		return
	}
	// Update the target with the root component information.
	target.Name, _, _ = techutils.SplitPackageURL(rootComponent.PackageURL)
}

func logLibComponents(output *cyclonedx.BOM, totalTargets int, target string, startTime time.Time) (err error) {
	libs := []string{}
	if output != nil && output.Components != nil {
		for _, component := range *output.Components {
			if component.Type == cyclonedx.ComponentTypeLibrary {
				libs = append(libs, techutils.PurlToXrayComponentId(component.PackageURL))
			}
		}
	}
	outLog := "SBOM generated"
	if totalTargets > 1 {
		outLog += fmt.Sprintf(" for target '%s'", target)
	}
	outLog += ";"
	if len(libs) == 0 {
		outLog += " no library components were found"
	} else {
		outLog += fmt.Sprintf(" found %d library components", len(libs))
	}
	log.Info(fmt.Sprintf("%s (duration %s)", outLog, time.Since(startTime).String()))
	if log.GetLogger().GetLogLevel() != log.DEBUG || len(libs) == 0 {
		// Avoid printing and marshaling if not on DEBUG mode or no library components found.
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
