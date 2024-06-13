package conversion

import (
	"strconv"
	"strings"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/sarifformat"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/simplejsonformat"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/summaryformat"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/tableformat"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

type CommandResultsConvertor struct {
	Params ResultConvertParams
}

type ResultConvertParams struct {
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
type ResultsStreamFormatConvertor interface {
	// Reset the convertor to start converting a new command results
	Reset(multiScanId, xrayVersion string, entitledForJas, multipleTargets bool) error
	// Will be called for each scan target (indicating the current is done parsing and starting to parse a new scan)
	ParseNewScanResultsMetadata(target string, errors error) error
	// Parse SCA content to the current scan target
	ParseViolations(target string, tech techutils.Technology, violations []services.Violation, applicabilityRuns ...*sarif.Run) error
	ParseVulnerabilities(target string, tech techutils.Technology, vulnerabilities []services.Vulnerability, applicabilityRuns ...*sarif.Run) error
	ParseLicenses(target string, tech techutils.Technology, licenses []services.License) error
	// Parse JAS content to the current scan target
	ParseSecrets(target string, secrets ...*sarif.Run) error
	ParseIacs(target string, iacs ...*sarif.Run) error
	ParseSast(target string, sast ...*sarif.Run) error
}

func (c *CommandResultsConvertor) ConvertToSimpleJson(cmdResults *results.ScanCommandResults) (simpleJsonResults formats.SimpleJsonResults, err error) {
	convertor := simplejsonformat.NewCmdResultsSimpleJsonConverter(false)
	err = c.parseCommandResults(convertor, cmdResults)
	if err != nil {
		return
	}
	content := convertor.Get()
	if content == nil {
		simpleJsonResults = formats.SimpleJsonResults{}
	} else {
		simpleJsonResults = *content
	}
	return
}

func (c *CommandResultsConvertor) ConvertToSarif(cmdResults *results.ScanCommandResults) (sarifReport *sarif.Report, err error) {
	convertor := sarifformat.NewCmdResultsSarifConverter(c.Params.Pretty, c.Params.AllowResultsWithoutLocations)
	err = c.parseCommandResults(convertor, cmdResults)
	if err != nil {
		return
	}
	return convertor.Get()
}

func (c *CommandResultsConvertor) ConvertToTable(cmdResults *results.ScanCommandResults) (tableResults formats.ResultsTables, err error) {
	convertor := tableformat.NewCmdResultsTableConverter(c.Params.Pretty)
	err = c.parseCommandResults(convertor, cmdResults)
	if err != nil {
		return
	}
	content := convertor.Get()
	if content == nil {
		tableResults = formats.ResultsTables{}
	} else {
		tableResults = *content
	}
	return
}

func (c *CommandResultsConvertor) ConvertToSummary(cmdResults *results.ScanCommandResults) (summaryResults formats.SummaryResults, err error) {
	convertor := summaryformat.NewCmdResultsSummaryConverter()
	err = c.parseCommandResults(convertor, cmdResults)
	if err != nil {
		return
	}
	return *convertor.Get(), nil
}

func (c *CommandResultsConvertor) parseCommandResults(convertor ResultsStreamFormatConvertor, cmdResults *results.ScanCommandResults) (err error) {
	jasEntitled := cmdResults.EntitledForJas
	multipleTargets := cmdResults.HasMultipleTargets()
	convertor.Reset(cmdResults.MultiScanId, cmdResults.XrayVersion, jasEntitled, multipleTargets)
	for _, scan := range cmdResults.Scans {
		if err = convertor.ParseNewScanResultsMetadata(scan.Target, scan.Errors); err != nil {
			return err
		}
		for _, scaResults := range scan.ScaResults {
			actualTarget := scaResults.Target
			if actualTarget == "" {
				// If target was not provided, use the scan target
				// TODO: make sure works for build-scan since its not a file
				actualTarget = scan.Target
			}
			var applicableRuns []*sarif.Run
			if jasEntitled && scan.JasResults != nil {
				applicableRuns = scan.JasResults.ApplicabilityScanResults
			}
			vulnerabilities := scaResults.XrayResult.Vulnerabilities
			if c.Params.SimplifiedOutput {
				vulnerabilities = simplifyVulnerabilities(vulnerabilities, multipleTargets)
			}
			if len(vulnerabilities) > 0 {
				if err = convertor.ParseVulnerabilities(actualTarget, scaResults.Technology, vulnerabilities, applicableRuns...); err != nil {
					return
				}
			}
			violations := scaResults.XrayResult.Violations
			if c.Params.SimplifiedOutput {
				violations = simplifyViolations(violations, multipleTargets)
			}
			if len(violations) > 0 {
				if err = convertor.ParseViolations(actualTarget, scaResults.Technology, violations, applicableRuns...); err != nil {
					return
				}
			} else if len(c.Params.AllowedLicenses) > 0 {
				// If no violations were found, check if there are licenses that are not allowed
				licViolations := results.GetViolatedLicenses(c.Params.AllowedLicenses, scaResults.XrayResult.Licenses)
				if len(licViolations) > 0 {
					if err = convertor.ParseViolations(actualTarget, scaResults.Technology, results.GetViolatedLicenses(c.Params.AllowedLicenses, scaResults.XrayResult.Licenses)); err != nil {
						return
					}
				}
			}
			if c.Params.IncludeLicenses {
				if err = convertor.ParseLicenses(actualTarget, scaResults.Technology, scaResults.XrayResult.Licenses); err != nil {
					return
				}
			}
		}
		if !jasEntitled || scan.JasResults == nil {
			continue
		}
		if err = convertor.ParseSecrets(scan.Target, scan.JasResults.SecretsScanResults...); err != nil {
			return
		}
		if err = convertor.ParseIacs(scan.Target, scan.JasResults.IacScanResults...); err != nil {
			return
		}
		if err = convertor.ParseSast(scan.Target, scan.JasResults.SastScanResults...); err != nil {
			return
		}
	}
	return
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
