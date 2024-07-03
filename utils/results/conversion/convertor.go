package conversion

import (
	"strconv"
	"strings"

	"github.com/jfrog/jfrog-cli-security/utils"
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
	Reset(multiScanId, xrayVersion string, entitledForJas bool) error
	// Will be called for each scan target (indicating the current is done parsing and starting to parse a new scan)
	ParseNewScanResultsMetadata(target string, errors ...error) error
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
	parser := simplejsonparser.NewCmdResultsSimpleJsonConverter(false)
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
	parser.Reset(cmdResults.MultiScanId, cmdResults.XrayVersion, jasEntitled)
	for _, targetScansResults := range cmdResults.Targets {
		if err = parser.ParseNewScanResultsMetadata(targetScansResults.Target, targetScansResults.Errors...); err != nil {
			return
		}
		if targetScansResults.ScaResults != nil {
			if err = c.parseScaResults(parser, targetScansResults, jasEntitled, multipleTargets); err != nil {
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

func (c *CommandResultsConvertor) parseScaResults(parser ResultsStreamFormatParser, targetScansResults *results.TargetResults, jasEntitled, multipleTargets bool) (err error) {
	for _, scaResults := range targetScansResults.ScaResults.XrayResults {
		actualTarget := getScaScanTarget(targetScansResults.ScaResults, targetScansResults.Target)
		var applicableRuns []*sarif.Run
		if jasEntitled && targetScansResults.JasResults != nil {
			applicableRuns = targetScansResults.JasResults.ApplicabilityScanResults
		}
		vulnerabilities := scaResults.Vulnerabilities
		if c.Params.SimplifiedOutput {
			vulnerabilities = simplifyVulnerabilities(vulnerabilities, multipleTargets)
		}
		if len(vulnerabilities) > 0 {
			if err = parser.ParseVulnerabilities(actualTarget, targetScansResults.Technology, vulnerabilities, applicableRuns...); err != nil {
				return
			}
		}
		violations := scaResults.Violations
		if c.Params.SimplifiedOutput {
			violations = simplifyViolations(violations, multipleTargets)
		}
		if len(violations) > 0 {
			if err = parser.ParseViolations(actualTarget, targetScansResults.Technology, violations, applicableRuns...); err != nil {
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

// simplifyViolations returns a new slice of services.Violations that contains only the unique violations from the input slice
// The uniqueness of the violations is determined by the GetUniqueKey function
func simplifyViolations(scanViolations []services.Violation, multipleRoots bool) []services.Violation {
	var uniqueViolations = make(map[string]*services.Violation)
	for _, violation := range scanViolations {
		for vulnerableComponentId := range violation.Components {
			vulnerableDependency, vulnerableVersion, _ := techutils.SplitComponentId(vulnerableComponentId)
			packageKey := GetUniqueKey(vulnerableDependency, vulnerableVersion, violation.IssueId, len(violation.Components[vulnerableComponentId].FixedVersions) > 0)
			if uniqueVulnerability, exist := uniqueViolations[packageKey]; exist {
				fixedVersions := utils.UniqueUnion(uniqueVulnerability.Components[vulnerableComponentId].FixedVersions, violation.Components[vulnerableComponentId].FixedVersions...)
				impactPaths := results.AppendUniqueImpactPaths(uniqueVulnerability.Components[vulnerableComponentId].ImpactPaths, violation.Components[vulnerableComponentId].ImpactPaths, multipleRoots)
				uniqueViolations[packageKey].Components[vulnerableComponentId] = services.Component{
					FixedVersions: fixedVersions,
					ImpactPaths:   impactPaths,
				}
				continue
			}
			uniqueViolations[packageKey] = &services.Violation{
				Summary:       violation.Summary,
				Severity:      violation.Severity,
				ViolationType: violation.ViolationType,
				Components:    map[string]services.Component{vulnerableComponentId: violation.Components[vulnerableComponentId]},
				WatchName:     violation.WatchName,
				IssueId:       violation.IssueId,
				Cves:          violation.Cves,
				LicenseKey:    violation.LicenseKey,
				LicenseName:   violation.LicenseName,
				Technology:    violation.Technology,
			}
		}
	}
	// convert map to slice
	result := make([]services.Violation, 0, len(uniqueViolations))
	for _, v := range uniqueViolations {
		result = append(result, *v)
	}
	return result
}

// simplifyVulnerabilities returns a new slice of services.Vulnerability that contains only the unique vulnerabilities from the input slice
// The uniqueness of the vulnerabilities is determined by the GetUniqueKey function
func simplifyVulnerabilities(scanVulnerabilities []services.Vulnerability, multipleRoots bool) []services.Vulnerability {
	var uniqueVulnerabilities = make(map[string]*services.Vulnerability)
	for _, vulnerability := range scanVulnerabilities {
		for vulnerableComponentId := range vulnerability.Components {
			vulnerableDependency, vulnerableVersion, _ := techutils.SplitComponentId(vulnerableComponentId)
			packageKey := GetUniqueKey(vulnerableDependency, vulnerableVersion, vulnerability.IssueId, len(vulnerability.Components[vulnerableComponentId].FixedVersions) > 0)
			if uniqueVulnerability, exist := uniqueVulnerabilities[packageKey]; exist {
				fixedVersions := utils.UniqueUnion(uniqueVulnerability.Components[vulnerableComponentId].FixedVersions, vulnerability.Components[vulnerableComponentId].FixedVersions...)
				impactPaths := results.AppendUniqueImpactPaths(uniqueVulnerability.Components[vulnerableComponentId].ImpactPaths, vulnerability.Components[vulnerableComponentId].ImpactPaths, multipleRoots)
				uniqueVulnerabilities[packageKey].Components[vulnerableComponentId] = services.Component{
					FixedVersions: fixedVersions,
					ImpactPaths:   impactPaths,
				}
				continue
			}
			uniqueVulnerabilities[packageKey] = &services.Vulnerability{
				Cves:                vulnerability.Cves,
				Severity:            vulnerability.Severity,
				Components:          map[string]services.Component{vulnerableComponentId: vulnerability.Components[vulnerableComponentId]},
				IssueId:             vulnerability.IssueId,
				Technology:          vulnerability.Technology,
				ExtendedInformation: vulnerability.ExtendedInformation,
				Summary:             vulnerability.Summary,
			}
		}
	}
	// convert map to slice
	result := make([]services.Vulnerability, 0, len(uniqueVulnerabilities))
	for _, v := range uniqueVulnerabilities {
		result = append(result, *v)
	}
	return result
}

// GetUniqueKey returns a unique string key of format "vulnerableDependency:vulnerableVersion:xrayID:fixVersionExist"
func GetUniqueKey(vulnerableDependency, vulnerableVersion, xrayID string, fixVersionExist bool) string {
	return strings.Join([]string{vulnerableDependency, vulnerableVersion, xrayID, strconv.FormatBool(fixVersionExist)}, ":")
}
