package conversion

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/cyclonedxparser"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/sarifparser"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/simplejsonparser"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/summaryparser"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/tableparser"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xscServices "github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

type CommandResultsConvertor struct {
	Params ResultConvertParams
}

type ResultConvertParams struct {
	// If true, a violation context was provided and we expect violation results
	HasViolationContext bool
	// Control if the output should include vulnerabilities information
	IncludeVulnerabilities bool
	// If true and commandType.IsTargetBinary(), binary inner paths in results will be converted to the CI job file (relevant only for SARIF)
	PatchBinaryPaths bool
	// Control if SAST results should be parsed directly into the CycloneDX BOM, if false SARIF runs will be attached at "sast" attribute, diverting from the CDX spec (relevant only for CycloneDX)
	ParseSastResultDirectlyIntoCDX bool
	// Control if the output should include licenses information
	IncludeLicenses bool
	// Control if the output should include SBOM information (relevant only for Table)
	IncludeSbom bool
	// Control and override converting command results as multi target results, if nil will be determined by the results.HasMultipleTargets()
	IsMultipleRoots *bool
	// The requested scans to be included in the results, if empty all scans will be included
	RequestedScans []utils.SubScanType
	// // Create local license violations if repo context was not provided and a license is not in this list
	// AllowedLicenses []string
	// Output will contain only the unique violations determined by the GetUniqueKey function (SimpleJson only)
	SimplifiedOutput bool
	// Convert the results to a pretty format if supported (Table and SimpleJson only)
	Pretty bool
	// The JFrog platform URL to be used in the results (Sarif only - GitHub integration)
	PlatformUrl string
}

func NewCommandResultsConvertor(params ResultConvertParams) *CommandResultsConvertor {
	return &CommandResultsConvertor{Params: params}
}

// Parse a stream of results and convert them to the desired format T
type ResultsStreamFormatParser[T interface{}] interface {
	// Reset the convertor to start converting a new command results
	Reset(cmdType utils.CommandType, multiScanId, xrayVersion string, entitledForJas, multipleTargets bool, gitContext *xscServices.XscGitInfoContext, generalError error) error
	// Will be called for each scan target (indicating the current is done parsing and starting to parse a new scan)
	ParseNewTargetResults(target results.ScanTarget, errors ...error) error
	// TODO: This method is deprecated and only used for backward compatibility until the new BOM can contain all the information scanResponse contains.
	// Missing attributes:
	// - ExtendedInformation (JfrogResearchInformation): ShortDescription, FullDescription, frogResearchSeverityReasons, Remediation
	DeprecatedParseScaIssues(descriptors []string, scaResponse results.ScanResult[services.ScanResponse], applicableScan ...results.ScanResult[[]*sarif.Run]) error
	DeprecatedParseLicenses(scaResponse results.ScanResult[services.ScanResponse]) error
	// Parse SCA content to the current scan target
	ParseSbom(sbom *cyclonedx.BOM) error
	ParseSbomLicenses(components []cyclonedx.Component, dependencies ...cyclonedx.Dependency) error
	ParseCVEs(enrichedSbom results.ScanResult[*cyclonedx.BOM], applicableScan ...results.ScanResult[[]*sarif.Run]) error
	// Parse JAS content to the current scan target
	ParseSecrets(secrets ...results.ScanResult[[]*sarif.Run]) error
	ParseIacs(iacs ...results.ScanResult[[]*sarif.Run]) error
	ParseSast(sast ...results.ScanResult[[]*sarif.Run]) error
	// Parse JFrog violations to the format if supported
	ParseViolations(violations results.ScanResult[violationutils.Violations]) error
	// When done parsing the stream results, get the converted content
	Get() (T, error)
}

func (c *CommandResultsConvertor) ConvertToCycloneDx(cmdResults *results.SecurityCommandResults) (bom *cdxutils.FullBOM, err error) {
	parser := cyclonedxparser.NewCmdResultsCycloneDxConverter(c.Params.ParseSastResultDirectlyIntoCDX)
	return parseCommandResults(c.Params, parser, cmdResults)
}

func (c *CommandResultsConvertor) ConvertToSimpleJson(cmdResults *results.SecurityCommandResults) (simpleJsonResults formats.SimpleJsonResults, err error) {
	parser := simplejsonparser.NewCmdResultsSimpleJsonConverter(false, c.Params.SimplifiedOutput)
	return parseCommandResults(c.Params, parser, cmdResults)
}

func (c *CommandResultsConvertor) ConvertToSarif(cmdResults *results.SecurityCommandResults) (sarifReport *sarif.Report, err error) {
	parser := sarifparser.NewCmdResultsSarifConverter(c.Params.PlatformUrl, c.Params.PatchBinaryPaths)
	return parseCommandResults(c.Params, parser, cmdResults)
}

func (c *CommandResultsConvertor) ConvertToTable(cmdResults *results.SecurityCommandResults) (tableResults formats.ResultsTables, err error) {
	parser := tableparser.NewCmdResultsTableConverter(c.Params.Pretty)
	return parseCommandResults(c.Params, parser, cmdResults)
}

func (c *CommandResultsConvertor) ConvertToSummary(cmdResults *results.SecurityCommandResults) (summaryResults formats.ResultsSummary, err error) {
	parser := summaryparser.NewCmdResultsSummaryConverter(c.Params.IncludeVulnerabilities, c.Params.HasViolationContext)
	return parseCommandResults(c.Params, parser, cmdResults)
}

func parseCommandResults[T interface{}](params ResultConvertParams, parser ResultsStreamFormatParser[T], cmdResults *results.SecurityCommandResults) (converted T, err error) {
	jasEntitled := cmdResults.EntitledForJas
	multipleTargets := cmdResults.HasMultipleTargets()
	if params.IsMultipleRoots != nil {
		multipleTargets = *params.IsMultipleRoots
	}
	if err = parser.Reset(cmdResults.CmdType, cmdResults.MultiScanId, cmdResults.XrayVersion, jasEntitled, multipleTargets, cmdResults.GitContext, cmdResults.GeneralError); err != nil {
		return
	}
	for _, targetScansResults := range cmdResults.Targets {
		if err = parser.ParseNewTargetResults(targetScansResults.ScanTarget, targetScansResults.Errors...); err != nil {
			return
		}
		if params.IncludeSbom {
			if err = parser.ParseSbom(targetScansResults.ScaResults.Sbom); err != nil {
				return
			}
		}
		if utils.IsScanRequested(cmdResults.CmdType, utils.ScaScan, params.RequestedScans...) && targetScansResults.ScaResults != nil {
			if err = parseScaResults(params, parser, targetScansResults, jasEntitled); err != nil {
				return
			}
		}
		if !jasEntitled {
			continue
		}
		if err = parseJasResults(params, parser, targetScansResults, cmdResults.CmdType); err != nil {
			return
		}
	}
	if cmdResults.HasViolationContext() {
		if err = parser.ParseViolations(cmdResults.Violations); err != nil {
			return
		}
	}
	return parser.Get()
}

func parseScaResults[T interface{}](params ResultConvertParams, parser ResultsStreamFormatParser[T], targetScansResults *results.TargetResults, jasEntitled bool) (err error) {
	if targetScansResults.ScaResults == nil {
		// Nothing to parse, no SCA results
		return
	}
	// Prepare attributes for parsing SCA results
	var applicableRuns []results.ScanResult[[]*sarif.Run]
	if jasEntitled && targetScansResults.JasResults != nil {
		applicableRuns = targetScansResults.JasResults.ApplicabilityScanResults
	}
	// If no enriched SBOM was provided, we can't parse new flow
	if err = parseDeprecatedScaResults(params, parser, targetScansResults, jasEntitled); err != nil {
		return
	}
	if targetScansResults.ScaResults.Sbom == nil {
		// If no enriched SBOM was provided, we can't parse new flow
		return
	}
	// Parse the SCA results from the enriched SBOM
	if params.IncludeVulnerabilities && targetScansResults.ScaResults.Sbom.Vulnerabilities != nil {
		vulnerabilityScan := results.ScanResult[*cyclonedx.BOM]{
			Scan:       targetScansResults.ScaResults.Sbom,
			StatusCode: targetScansResults.ScaResults.ScanStatusCode,
		}
		if err = parser.ParseCVEs(vulnerabilityScan, applicableRuns...); err != nil {
			return
		}
	}
	// Must be called last for cyclonedxparser to be able to attach the licenses to all the components
	if params.IncludeLicenses && targetScansResults.ScaResults.Sbom.Components != nil {
		dependencies := []cyclonedx.Dependency{}
		if targetScansResults.ScaResults.Sbom.Dependencies != nil {
			dependencies = append(dependencies, *targetScansResults.ScaResults.Sbom.Dependencies...)
		}
		if err = parser.ParseSbomLicenses(*targetScansResults.ScaResults.Sbom.Components, dependencies...); err != nil {
			return
		}
	}
	return
}

func parseDeprecatedScaResults[T interface{}](params ResultConvertParams, parser ResultsStreamFormatParser[T], targetScansResults *results.TargetResults, jasEntitled bool) (err error) {
	if targetScansResults.ScaResults == nil {
		// Nothing to parse, no SCA results
		return
	}
	// Prepare attributes for parsing SCA results
	var applicableRuns []results.ScanResult[[]*sarif.Run]
	if jasEntitled && targetScansResults.JasResults != nil {
		applicableRuns = targetScansResults.JasResults.ApplicabilityScanResults
	}
	// Parse deprecated SCA results
	for _, scaResults := range targetScansResults.ScaResults.DeprecatedXrayResults {
		if params.IncludeVulnerabilities {
			if err = parser.DeprecatedParseScaIssues(targetScansResults.ScaResults.Descriptors, scaResults, applicableRuns...); err != nil {
				return
			}
		}
		// Must be called last for cyclonedxparser to be able to attach the licenses to the components
		if params.IncludeLicenses {
			if err = parser.DeprecatedParseLicenses(scaResults); err != nil {
				return
			}
		}
	}
	return
}

func parseJasResults[T interface{}](params ResultConvertParams, parser ResultsStreamFormatParser[T], targetResults *results.TargetResults, cmdType utils.CommandType) (err error) {
	if targetResults.JasResults == nil || !params.IncludeVulnerabilities {
		return
	}
	// Parsing JAS Secrets results
	if err = parser.ParseSecrets(targetResults.JasResults.JasVulnerabilities.SecretsScanResults...); err != nil {
		return
	}
	// Parsing JAS IAC results
	if err = parser.ParseIacs(targetResults.JasResults.JasVulnerabilities.IacScanResults...); err != nil {
		return
	}
	// Parsing JAS SAST results
	return parser.ParseSast(targetResults.JasResults.JasVulnerabilities.SastScanResults...)
}
