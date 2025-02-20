package conversion

import (
	"strings"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/sarifparser"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/simplejsonparser"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/summaryparser"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/tableparser"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
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
	// Control if the output should include licenses information
	IncludeLicenses bool
	// Control and override converting command results as multi target results, if nil will be determined by the results.HasMultipleTargets()
	IsMultipleRoots *bool
	// The requested scans to be included in the results, if empty all scans will be included
	RequestedScans []utils.SubScanType
	// Create local license violations if repo context was not provided and a license is not in this list
	AllowedLicenses []string
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
	Reset(cmdType utils.CommandType, multiScanId, xrayVersion string, entitledForJas, multipleTargets bool, generalError error) error
	// Will be called for each scan target (indicating the current is done parsing and starting to parse a new scan)
	ParseNewTargetResults(target results.ScanTarget, errors ...error) error
	// Parse SCA content to the current scan target
	ParseScaIssues(target results.ScanTarget, violations bool, scaResponse results.ScanResult[services.ScanResponse], applicableScan ...results.ScanResult[[]*sarif.Run]) error
	ParseLicenses(target results.ScanTarget, scaResponse results.ScanResult[services.ScanResponse]) error
	// Parse JAS content to the current scan target
	ParseSecrets(target results.ScanTarget, violations bool, secrets []results.ScanResult[[]*sarif.Run]) error
	ParseMalicious(target results.ScanTarget, violations bool, maliciousFindings []results.ScanResult[[]*sarif.Run]) error
	ParseIacs(target results.ScanTarget, violations bool, iacs []results.ScanResult[[]*sarif.Run]) error
	ParseSast(target results.ScanTarget, violations bool, sast []results.ScanResult[[]*sarif.Run]) error
	// When done parsing the stream results, get the converted content
	Get() (T, error)
}

func (c *CommandResultsConvertor) ConvertToSimpleJson(cmdResults *results.SecurityCommandResults) (simpleJsonResults formats.SimpleJsonResults, err error) {
	parser := simplejsonparser.NewCmdResultsSimpleJsonConverter(false, c.Params.SimplifiedOutput)
	return parseCommandResults(c.Params, parser, cmdResults)
}

func (c *CommandResultsConvertor) ConvertToSarif(cmdResults *results.SecurityCommandResults) (sarifReport *sarif.Report, err error) {
	parser := sarifparser.NewCmdResultsSarifConverter(c.Params.PlatformUrl, c.Params.IncludeVulnerabilities, c.Params.HasViolationContext, c.Params.PatchBinaryPaths)
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
	if err = parser.Reset(cmdResults.CmdType, cmdResults.MultiScanId, cmdResults.XrayVersion, jasEntitled, multipleTargets, cmdResults.GeneralError); err != nil {
		return
	}
	for _, targetScansResults := range cmdResults.Targets {
		if err = parser.ParseNewTargetResults(targetScansResults.ScanTarget, targetScansResults.Errors...); err != nil {
			return
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
	return parser.Get()
}

func parseScaResults[T interface{}](params ResultConvertParams, parser ResultsStreamFormatParser[T], targetScansResults *results.TargetResults, jasEntitled bool) (err error) {
	if targetScansResults.ScaResults == nil {
		return
	}
	for _, scaResults := range targetScansResults.ScaResults.XrayResults {
		actualTarget := getScaScanTarget(targetScansResults.ScaResults, targetScansResults.ScanTarget)
		var applicableRuns []results.ScanResult[[]*sarif.Run]
		if jasEntitled && targetScansResults.JasResults != nil {
			applicableRuns = targetScansResults.JasResults.ApplicabilityScanResults
		}
		if params.IncludeVulnerabilities {
			if err = parser.ParseScaIssues(actualTarget, false, scaResults, applicableRuns...); err != nil {
				return
			}
		}
		if params.HasViolationContext {
			if err = parser.ParseScaIssues(actualTarget, true, scaResults, applicableRuns...); err != nil {
				return
			}
		} else if !scaResults.IsScanFailed() && len(scaResults.Scan.Violations) == 0 && len(params.AllowedLicenses) > 0 {
			// If no violations were found, check if there are licenses that are not allowed
			if scaResults.Scan.Violations = results.GetViolatedLicenses(params.AllowedLicenses, scaResults.Scan.Licenses); len(scaResults.Scan.Violations) > 0 {
				if err = parser.ParseScaIssues(actualTarget, true, scaResults); err != nil {
					return
				}
			}
		}
		if params.IncludeLicenses {
			if err = parser.ParseLicenses(actualTarget, scaResults); err != nil {
				return
			}
		}
	}
	return
}

// Get the best match for the scan target in the sca results
func getScaScanTarget(scaResults *results.ScaScanResults, target results.ScanTarget) results.ScanTarget {
	if scaResults == nil || len(scaResults.Descriptors) == 0 {
		// If No Sca scan or no descriptors discovered, use the scan target (build-scan, binary-scan...)
		return target
	}
	// Get the one that it's directory is the prefix of the target and the shortest
	// This is for multi module projects where there are multiple sca results for the same target
	var bestMatch string
	for _, descriptor := range scaResults.Descriptors {
		if strings.HasPrefix(descriptor, target.Target) && (bestMatch == "" || len(descriptor) < len(bestMatch)) {
			bestMatch = descriptor
		}
	}
	if bestMatch != "" {
		return target.Copy(bestMatch)
	}
	return target
}

func parseJasResults[T interface{}](params ResultConvertParams, parser ResultsStreamFormatParser[T], targetResults *results.TargetResults, cmdType utils.CommandType) (err error) {
	if targetResults.JasResults == nil {
		return
	}
	// Parsing JAS Secrets results
	if err = parseJasScanResults(params, targetResults, cmdType, utils.SecretsScan, func(violations bool) error {
		scanResults := targetResults.JasResults.JasVulnerabilities.SecretsScanResults
		if violations {
			scanResults = targetResults.JasResults.JasViolations.SecretsScanResults
		}
		return parser.ParseSecrets(targetResults.ScanTarget, violations, scanResults)
	}); err != nil {
		return
	}
	// Parsing JAS IAC results
	if err = parseJasScanResults(params, targetResults, cmdType, utils.IacScan, func(violations bool) error {
		scanResults := targetResults.JasResults.JasVulnerabilities.IacScanResults
		if violations {
			scanResults = targetResults.JasResults.JasViolations.IacScanResults
		}
		return parser.ParseIacs(targetResults.ScanTarget, violations, scanResults)
	}); err != nil {
		return
	}
	// Parsing JAS Malicious code results
	if err = parseJasScanResults(params, targetResults, cmdType, utils.MaliciousCodeScan, func(violations bool) error {
		scanResults := targetResults.JasResults.JasVulnerabilities.MaliciousScanResults
		if violations {
			scanResults = targetResults.JasResults.JasViolations.MaliciousScanResults
		}
		return parser.ParseMalicious(targetResults.ScanTarget, violations, scanResults)
	}); err != nil {
		return
	}
	// Parsing JAS SAST results
	return parseJasScanResults(params, targetResults, cmdType, utils.SastScan, func(violations bool) error {
		scanResults := targetResults.JasResults.JasVulnerabilities.SastScanResults
		if violations {
			scanResults = targetResults.JasResults.JasViolations.SastScanResults
		}
		return parser.ParseSast(targetResults.ScanTarget, violations, scanResults)
	})
}

func parseJasScanResults(params ResultConvertParams, targetResults *results.TargetResults, cmdType utils.CommandType, subScanType utils.SubScanType, parseJasFunc func(violations bool) error) (err error) {
	if !utils.IsScanRequested(cmdType, subScanType, params.RequestedScans...) || targetResults.JasResults == nil {
		return
	}
	if params.IncludeVulnerabilities {
		// Parse vulnerabilities
		if err = parseJasFunc(false); err != nil {
			return
		}
	}
	if !params.HasViolationContext {
		return
	}
	// Parse violations
	return parseJasFunc(true)
}
