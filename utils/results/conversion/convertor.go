package conversion

import (
	"strings"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/sarifparser"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/simplejsonparser"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/summaryparser"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/tableparser"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

type CommandResultsConvertor struct {
	Params ResultConvertParams
}

type ResultConvertParams struct {
	// Control and override converting command results as multi target results
	IsMultipleRoots *bool
	// Control if the output should include licenses information
	IncludeLicenses bool
	// Control if the output should include vulnerabilities information
	IncludeVulnerabilities bool
	// Output will contain only the unique violations determined by the GetUniqueKey function
	SimplifiedOutput bool
	// Create local license violations if repo context was not provided and a license is not in this list
	AllowedLicenses []string
	// Convert the results to a pretty format if supported
	Pretty bool
	// Relevant for Sarif format since Github format does not support results without locations
	AllowResultsWithoutLocations bool
}

func NewCommandResultsConvertor(params ResultConvertParams) *CommandResultsConvertor {
	return &CommandResultsConvertor{Params: params}
}

// Parse a stream of results and convert to the desired format
type ResultsStreamFormatParser interface {
	// Reset the convertor to start converting a new command results
	Reset(multiScanId, xrayVersion string, entitledForJas, multipleTargets bool) error
	// Will be called for each scan target (indicating the current is done parsing and starting to parse a new scan)
	ParseNewTargetResults(target string, errors ...error) error
	// Parse SCA content to the current scan target
	ParseViolations(target string, tech techutils.Technology, violations []services.Violation, applicabilityRuns ...*sarif.Run) error
	ParseVulnerabilities(target string, tech techutils.Technology, vulnerabilities []services.Vulnerability, applicabilityRuns ...*sarif.Run) error
	ParseLicenses(target string, tech techutils.Technology, licenses []services.License) error
	// Parse JAS content to the current scan target
	ParseSecrets(target string, secrets ...*sarif.Run) error
	ParseIacs(target string, iacs ...*sarif.Run) error
	ParseSast(target string, sast ...*sarif.Run) error
}

func (c *CommandResultsConvertor) ConvertToSimpleJson(cmdResults *results.SecurityCommandResults) (simpleJsonResults formats.SimpleJsonResults, err error) {
	parser := simplejsonparser.NewCmdResultsSimpleJsonConverter(false, c.Params.SimplifiedOutput)
	err = c.parseCommandResults(parser, cmdResults)
	if err != nil {
		return
	}
	content := parser.Get()
	if content == nil {
		simpleJsonResults = formats.SimpleJsonResults{}
	} else {
		simpleJsonResults = *content
	}
	return
}

func (c *CommandResultsConvertor) ConvertToSarif(cmdResults *results.SecurityCommandResults) (sarifReport *sarif.Report, err error) {
	parser := sarifparser.NewCmdResultsSarifConverter(c.Params.Pretty, c.Params.AllowResultsWithoutLocations)
	err = c.parseCommandResults(parser, cmdResults)
	if err != nil {
		return
	}
	return parser.Get()
}

func (c *CommandResultsConvertor) ConvertToTable(cmdResults *results.SecurityCommandResults) (tableResults formats.ResultsTables, err error) {
	parser := tableparser.NewCmdResultsTableConverter(c.Params.Pretty)
	err = c.parseCommandResults(parser, cmdResults)
	if err != nil {
		return
	}
	content := parser.Get()
	if content == nil {
		tableResults = formats.ResultsTables{}
	} else {
		tableResults = *content
	}
	return
}

func (c *CommandResultsConvertor) ConvertToSummary(cmdResults *results.SecurityCommandResults) (summaryResults formats.SummaryResults, err error) {
	parser := summaryparser.NewCmdResultsSummaryConverter()
	err = c.parseCommandResults(parser, cmdResults)
	if err != nil {
		return
	}
	return *parser.Get(), nil
}

func (c *CommandResultsConvertor) parseCommandResults(parser ResultsStreamFormatParser, cmdResults *results.SecurityCommandResults) (err error) {
	jasEntitled := cmdResults.EntitledForJas
	multipleTargets := cmdResults.HasMultipleTargets()
	if c.Params.IsMultipleRoots != nil {
		multipleTargets = *c.Params.IsMultipleRoots
	}
	if err = parser.Reset(cmdResults.MultiScanId, cmdResults.XrayVersion, jasEntitled, multipleTargets); err != nil {
		return
	}
	for _, targetScansResults := range cmdResults.Targets {
		if err = parser.ParseNewTargetResults(targetScansResults.Target, targetScansResults.Errors...); err != nil {
			return
		}
		if targetScansResults.ScaResults != nil {
			if err = c.parseScaResults(parser, targetScansResults, jasEntitled); err != nil {
				return
			}
		}
		if !jasEntitled || targetScansResults.JasResults == nil {
			continue
		}
		if err = parser.ParseSecrets(targetScansResults.Target, targetScansResults.JasResults.SecretsScanResults...); err != nil {
			return
		}
		if err = parser.ParseIacs(targetScansResults.Target, targetScansResults.JasResults.IacScanResults...); err != nil {
			return
		}
		if err = parser.ParseSast(targetScansResults.Target, targetScansResults.JasResults.SastScanResults...); err != nil {
			return
		}
	}
	return
}

func (c *CommandResultsConvertor) parseScaResults(parser ResultsStreamFormatParser, targetScansResults *results.TargetResults, jasEntitled bool) (err error) {
	for _, scaResults := range targetScansResults.ScaResults.XrayResults {
		actualTarget := getScaScanTarget(targetScansResults.ScaResults, targetScansResults.Target)
		var applicableRuns []*sarif.Run
		if jasEntitled && targetScansResults.JasResults != nil {
			applicableRuns = targetScansResults.JasResults.ApplicabilityScanResults
		}
		if len(scaResults.Vulnerabilities) > 0 {
			if err = parser.ParseVulnerabilities(actualTarget, targetScansResults.Technology, scaResults.Vulnerabilities, applicableRuns...); err != nil {
				return
			}
		}
		if len(scaResults.Violations) > 0 {
			if err = parser.ParseViolations(actualTarget, targetScansResults.Technology, scaResults.Violations, applicableRuns...); err != nil {
				return
			}
		} else if len(c.Params.AllowedLicenses) > 0 {
			// If no violations were found, check if there are licenses that are not allowed
			licViolations := results.GetViolatedLicenses(c.Params.AllowedLicenses, scaResults.Licenses)
			if len(licViolations) > 0 {
				if err = parser.ParseViolations(actualTarget, targetScansResults.Technology, results.GetViolatedLicenses(c.Params.AllowedLicenses, scaResults.Licenses)); err != nil {
					return
				}
			}
		}
		if c.Params.IncludeLicenses {
			if err = parser.ParseLicenses(actualTarget, targetScansResults.Technology, scaResults.Licenses); err != nil {
				return
			}
		}
	}
	return
}

func getScaScanTarget(scaResults *results.ScaScanResults, target string) string {
	if scaResults == nil || len(scaResults.Descriptors) == 0 {
		// If target was not provided, use the scan target
		// TODO: make sure works for build-scan since its not a file
		return target
	}
	// Get the one that it's directory is the prefix of the target and the shortest
	var bestMatch string
	for _, descriptor := range scaResults.Descriptors {
		if strings.HasPrefix(descriptor, target) && (bestMatch == "" || len(descriptor) < len(bestMatch)) {
			bestMatch = descriptor
		}
	}
	if bestMatch != "" {
		return bestMatch
	}
	return target
}
