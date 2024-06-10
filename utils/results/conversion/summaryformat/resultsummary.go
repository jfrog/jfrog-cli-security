package summaryformat

import (
	"fmt"
	"strings"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-cli-security/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/exp/maps"
)

type CmdResultsSummaryConverter struct {
	current *sarif.Report
	entitledForJas bool
}

func NewCmdResultsSummaryConverter() *CmdResultsSummaryConverter {
	return &CmdResultsSummaryConverter{}
}

func (sc *CmdResultsSummaryConverter) Get() *formats.TableResults {
	if sjc.current == nil {
		return formats.SimpleJsonResults{}
	}
	return *sjc.current
}

func (sc *CmdResultsSummaryConverter) Reset(multiScanId, _ string, entitledForJas bool) error {
	sjc.current = &formats.SimpleJsonResults{MultiScanId: multiScanId}
	sjc.entitledForJas = entitledForJas
	return nil
}

func (sc *CmdResultsSummaryConverter) ParseNewScanResultsMetadata(target string, errors error) error {
	return nil
}

func (sc *CmdResultsSummaryConverter) ParseViolations(target string, tech techutils.Technology, violations []services.Violation, applicabilityRuns ...*sarif.Run) error {
	return nil
}

func (sc *CmdResultsSummaryConverter) ParseVulnerabilities(target string, tech techutils.Technology, vulnerabilities []services.Vulnerability, applicabilityRuns ...*sarif.Run) error {
	return nil
}

func (sc *CmdResultsSummaryConverter) ParseLicenses(target string, tech techutils.Technology, licenses []services.License) error {
	return nil
}

func (sc *CmdResultsSummaryConverter) ParseSecrets(target string, secrets ...*sarif.Run) error {
	return nil
}

func (sc *CmdResultsSummaryConverter) ParseIacs(target string, iacs ...*sarif.Run) error {
	return nil
}

func (sc *CmdResultsSummaryConverter) ParseSast(target string, sast ...*sarif.Run) error {
	return nil
}


type IssueDetails struct {
	FirstLevelValue  string
	SecondLevelValue string
}

// -- Command results to summary conversion

func GetSummary(r *results.ScanCommandResults) (summary formats.SummaryResults) {
	for _, scan := range r.Scans {
		summary.Scans = append(summary.Scans, scan.GetSummary())
	}
	return
}

func getScanSummary(extendedScanResults *ExtendedScanResults, scaResults ...ScaScanResult) (summary formats.ScanSummaryResult) {
	if len(scaResults) == 0 {
		return
	}
	if len(scaResults) == 1 {
		summary.Target = scaResults[0].Target
	}
	// Parse violations
	summary.Violations = getScanViolationsSummary(scaResults...)
	// Parse vulnerabilities
	summary.Vulnerabilities = getScanSecurityVulnerabilitiesSummary(extendedScanResults, scaResults...)
	return
}

func getScanViolationsSummary(scaResults ...ScaScanResult) (violations formats.TwoLevelSummaryCount) {
	vioUniqueFindings := map[string]IssueDetails{}
	if len(scaResults) == 0 {
		return
	}
	// Parse unique findings
	for _, scaResult := range scaResults {
		for _, xrayResult := range scaResult.XrayResults {
			for _, violation := range xrayResult.Violations {
				details := IssueDetails{FirstLevelValue: violation.ViolationType, SecondLevelValue: GetSeverity(violation.Severity, utils.NotScanned).Severity}
				for compId := range violation.Components {
					if violation.ViolationType == formats.ViolationTypeSecurity.String() {
						for _, cve := range violation.Cves {
							vioUniqueFindings[getCveId(cve, violation.IssueId)+compId] = details
						}
					} else {
						vioUniqueFindings[violation.IssueId+compId] = details
					}
				}
			}
		}
	}
	// Aggregate
	return issueDetailsToSummaryCount(vioUniqueFindings)
}

func getScanSecurityVulnerabilitiesSummary(extendedScanResults *ExtendedScanResults, scaResults ...ScaScanResult) (summary *formats.ScanVulnerabilitiesSummary) {
	summary = &formats.ScanVulnerabilitiesSummary{}
	if extendedScanResults == nil {
		summary.ScaScanResults = getScaSummaryResults(&scaResults)
		return
	}
	if len(scaResults) > 0 {
		summary.ScaScanResults = getScaSummaryResults(&scaResults, extendedScanResults.ApplicabilityScanResults...)
	}
	summary.IacScanResults = getJASSummaryCount(extendedScanResults.IacScanResults...)
	summary.SecretsScanResults = getJASSummaryCount(extendedScanResults.SecretsScanResults...)
	summary.SastScanResults = getJASSummaryCount(extendedScanResults.SastScanResults...)
	return
}



func getCveId(cve services.Cve, defaultIssueId string) string {
	if cve.Id == "" {
		return defaultIssueId
	}
	return cve.Id
}

func getSecurityIssueFindings(cves []services.Cve, issueId, severity string, components map[string]services.Component, applicableRuns ...*sarif.Run) (findings, uniqueFindings map[string]IssueDetails) {
	findings = map[string]IssueDetails{}
	uniqueFindings = map[string]IssueDetails{}
	for _, cve := range cves {
		cveId := getCveId(cve, issueId)
		applicableStatus := jasutils.NotScanned
		if applicableInfo := GetCveApplicabilityField(cveId, applicableRuns, components); applicableInfo != nil {
			applicableStatus = jasutils.ConvertToApplicabilityStatus(applicableInfo.Status)
		}
		uniqueFindings[cveId] = IssueDetails{
			FirstLevelValue:  GetSeverity(severity, applicableStatus).Severity,
			SecondLevelValue: applicableStatus.String(),
		}
		for compId := range components {
			findings[cveId+compId] = uniqueFindings[cveId]
		}
	}
	return
}

func getScaSummaryResults(scaScanResults *[]ScaScanResult, applicableRuns ...*sarif.Run) *formats.ScanScaResult {
	vulFindings := map[string]IssueDetails{}
	vulUniqueFindings := map[string]IssueDetails{}
	if len(*scaScanResults) == 0 {
		return nil
	}
	// Aggregate unique findings
	for _, scaResult := range *scaScanResults {
		for _, xrayResult := range scaResult.XrayResults {
			for _, vulnerability := range xrayResult.Vulnerabilities {
				vulFinding, vulUniqueFinding := getSecurityIssueFindings(vulnerability.Cves, vulnerability.IssueId, vulnerability.Severity, vulnerability.Components, applicableRuns...)
				for key, value := range vulFinding {
					vulFindings[key] = value
				}
				for key, value := range vulUniqueFinding {
					vulUniqueFindings[key] = value
				}
			}
		}
	}
	return &formats.ScanScaResult{
		SummaryCount:   issueDetailsToSummaryCount(vulFindings),
		UniqueFindings: issueDetailsToSummaryCount(vulUniqueFindings).GetTotal(),
	}
}

func issueDetailsToSummaryCount(uniqueFindings map[string]IssueDetails) formats.TwoLevelSummaryCount {
	summary := formats.TwoLevelSummaryCount{}
	for _, details := range uniqueFindings {
		if _, ok := summary[details.FirstLevelValue]; !ok {
			summary[details.FirstLevelValue] = formats.SummaryCount{}
		}
		summary[details.FirstLevelValue][details.SecondLevelValue]++
	}
	return summary
}

func getJASSummaryCount(runs ...*sarif.Run) *formats.SummaryCount {
	if len(runs) == 0 {
		return nil
	}
	count := formats.SummaryCount{}
	issueToSeverity := map[string]string{}
	for _, run := range runs {
		for _, result := range run.Results {
			for _, location := range result.Locations {
				issueToSeverity[sarifutils.GetLocationId(location)] = sarifutils.GetResultSeverity(result)
			}
		}
	}
	for _, severity := range issueToSeverity {
		count[severity]++
	}
	return &count
}

// -- Summary to string conversion


