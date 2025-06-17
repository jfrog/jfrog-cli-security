package scan

import (
	"github.com/CycloneDX/cyclonedx-go"

	"github.com/jfrog/jfrog-client-go/xray/services"
)

// SbomScanStrategy is an interface for scanning SBOMs using different strategies.
type SbomScanStrategy interface {
	// Parallel creates new instance of Scanner for parallel execution.
	SetThread(threadId int) SbomScanStrategy
	// ScaScanTask scans the given SBOM using the specified technology.
	DeprecatedScanTask(target *cyclonedx.BOM) (services.ScanResponse, error)
	// Perform a Scan on the given SBOM and return the CycloneDX BOM.
	SbomEnrichTask(target *cyclonedx.BOM) (*cyclonedx.BOM, []services.Violation, error)
}
