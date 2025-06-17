package scan

import (
	"github.com/CycloneDX/cyclonedx-go"

	"github.com/jfrog/jfrog-client-go/xray/services"
)

// SbomScanStrategy is an interface for scanning SBOMs using different strategies.
type SbomScanStrategy interface {
	// SetThread sets the thread ID for the scan strategy.
	SetThread(threadId int) SbomScanStrategy
	// DeprecatedScanTask scans the given SBOM using the specified technology returning the scan response.
	// This method is deprecated and only used for backward compatibility until the new BOM can contain all the information scanResponse contains.
	// Missing attributes:
	// - ExtendedInformation (JfrogResearchInformation): ShortDescription, FullDescription, frogResearchSeverityReasons, Remediation
	DeprecatedScanTask(target *cyclonedx.BOM) (services.ScanResponse, error)
	// Perform a Scan on the given SBOM and return the enriched CycloneDX BOM and violations.
	SbomEnrichTask(target *cyclonedx.BOM) (*cyclonedx.BOM, []services.Violation, error)
}
