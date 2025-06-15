package bom

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/utils/results"
)

// SbomGenerator is an interface for generating SBOMs from different sources.
type SbomGenerator interface {
	// PrepareGenerator prepares the generator for SBOM generation, should be called once before generating SBOMs.
	PrepareGenerator() error
	// SetThreadId sets the thread ID for the SBOM generation.
	SetThreadId(threadId int) SbomGenerator
	// GenerateSbom generates a CycloneDX SBOM for the given target.
	GenerateSbom(target results.ScanTarget) (*cyclonedx.BOM, error)
}