package summaryparser

import (
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

type CmdResultsSummaryConverter struct {
	current          *formats.SummaryResults
	currentScan      *formats.ScanSummaryResult
	currentCveUnique *datastructures.Set[string]
	entitledForJas   bool
}

func NewCmdResultsSummaryConverter() *CmdResultsSummaryConverter {
	return &CmdResultsSummaryConverter{}
}

func (sc *CmdResultsSummaryConverter) Get() *formats.SummaryResults {
	if sc.current == nil {
		return &formats.SummaryResults{}
	}
	// Flush the last scan
	sc.ParseNewScanResultsMetadata("", nil)
	return sc.current
}

func (sc *CmdResultsSummaryConverter) Reset(_, _ string, entitledForJas bool) (err error) {
	sc.current = &formats.SummaryResults{}
	sc.entitledForJas = entitledForJas
	sc.currentCveUnique = datastructures.MakeSet[string]()
	return
}

func (sc *CmdResultsSummaryConverter) ParseNewScanResultsMetadata(target string, _ ...error) (err error) {
	if sc.current == nil {
		return results.ConvertorResetErr
	}
	if sc.currentScan != nil {
		sc.current.Scans = append(sc.current.Scans, *sc.currentScan)
	}
	sc.currentScan = &formats.ScanSummaryResult{Target: target}
	return
}

func (sc *CmdResultsSummaryConverter) ParseViolations(target string, _ techutils.Technology, violations []services.Violation, applicabilityRuns ...*sarif.Run) (err error) {
	if sc.current == nil {
		return results.ConvertorResetErr
	}
	if sc.currentScan == nil {
		return results.ConvertorNewScanErr
	}
	if sc.currentScan.Vulnerabilities == nil {
		sc.currentScan.Vulnerabilities = &formats.ScanVulnerabilitiesSummary{}
	}
	if sc.currentScan.Vulnerabilities.ScaScanResults == nil {
		sc.currentScan.Vulnerabilities.ScaScanResults = &formats.ScanScaResult{}
	}
	err = results.PrepareScaViolations(
		target,
		violations,
		sc.entitledForJas,
		false,
		applicabilityRuns,
		sc.getScaViolationHandler(),
		sc.getScaViolationHandler(),
		sc.getScaViolationHandler(),
	)
	return
}

func (sc *CmdResultsSummaryConverter) getScaViolationHandler() results.PrepareScaViolationFunc {
	return func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) (err error) {
		for i := 0; i < len(getCveIds(cves, violation.IssueId)); i++ {
			sc.currentScan.Violations[violation.ViolationType][severity.String()]++
		}
		return
	}
}

func (sc *CmdResultsSummaryConverter) ParseVulnerabilities(target string, tech techutils.Technology, vulnerabilities []services.Vulnerability, applicabilityRuns ...*sarif.Run) (err error) {
	if sc.current == nil {
		return results.ConvertorResetErr
	}
	if sc.currentScan == nil {
		return results.ConvertorNewScanErr
	}
	if sc.currentScan.Vulnerabilities == nil {
		sc.currentScan.Vulnerabilities = &formats.ScanVulnerabilitiesSummary{}
	}
	if sc.currentScan.Vulnerabilities.ScaScanResults == nil {
		sc.currentScan.Vulnerabilities.ScaScanResults = &formats.ScanScaResult{}
	}
	err = results.PrepareScaVulnerabilities(
		target,
		vulnerabilities,
		sc.entitledForJas,
		false,
		applicabilityRuns,
		func(vulnerability services.Vulnerability, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error {
			for _, id := range getCveIds(cves, vulnerability.IssueId) {
				issueId := results.GetScaIssueId(impactedPackagesName, impactedPackagesVersion, id)
				if !sc.currentCveUnique.Exists(issueId) {
					sc.currentScan.Vulnerabilities.ScaScanResults.UniqueFindings++
					sc.currentCveUnique.Add(issueId)
				}
				sc.currentScan.Vulnerabilities.ScaScanResults.SummaryCount[severity.String()][applicabilityStatus.String()]++
			}
			return nil
		},
	)
	return
}

func getCveIds(cves []formats.CveRow, issueId string) []string {
	ids := []string{}
	for _, cve := range cves {
		ids = append(ids, cve.Id)
	}
	if len(ids) == 0 {
		ids = append(ids, issueId)
	}
	return ids
}

func (sc *CmdResultsSummaryConverter) ParseLicenses(target string, tech techutils.Technology, licenses []services.License) (err error) {
	// Not supported in the summary
	return
}

func (sc *CmdResultsSummaryConverter) ParseSecrets(target string, secrets ...*sarif.Run) (err error) {
	if !sc.entitledForJas {
		return
	}
	if sc.current == nil {
		return results.ConvertorResetErr
	}
	if sc.currentScan == nil {
		return results.ConvertorNewScanErr
	}
	if sc.currentScan.Vulnerabilities == nil {
		sc.currentScan.Vulnerabilities = &formats.ScanVulnerabilitiesSummary{}
	}
	if sc.currentScan.Vulnerabilities.SecretsScanResults == nil {
		sc.currentScan.Vulnerabilities.SecretsScanResults = &formats.SummaryCount{}
	}
	return results.PrepareJasIssues(target, secrets, sc.entitledForJas, sc.getJasHandler(jasutils.Secrets))
}

func (sc *CmdResultsSummaryConverter) ParseIacs(target string, iacs ...*sarif.Run) (err error) {
	if !sc.entitledForJas {
		return
	}
	if sc.current == nil {
		return results.ConvertorResetErr
	}
	if sc.currentScan == nil {
		return results.ConvertorNewScanErr
	}
	if sc.currentScan.Vulnerabilities == nil {
		sc.currentScan.Vulnerabilities = &formats.ScanVulnerabilitiesSummary{}
	}
	if sc.currentScan.Vulnerabilities.IacScanResults == nil {
		sc.currentScan.Vulnerabilities.IacScanResults = &formats.SummaryCount{}
	}
	return results.PrepareJasIssues(target, iacs, sc.entitledForJas, sc.getJasHandler(jasutils.IaC))
}

func (sc *CmdResultsSummaryConverter) ParseSast(target string, sast ...*sarif.Run) (err error) {
	if !sc.entitledForJas {
		return
	}
	if sc.current == nil {
		return results.ConvertorResetErr
	}
	if sc.currentScan == nil {
		return results.ConvertorNewScanErr
	}
	if sc.currentScan.Vulnerabilities == nil {
		sc.currentScan.Vulnerabilities = &formats.ScanVulnerabilitiesSummary{}
	}
	if sc.currentScan.Vulnerabilities.SastScanResults == nil {
		sc.currentScan.Vulnerabilities.SastScanResults = &formats.SummaryCount{}
	}
	return results.PrepareJasIssues(target, sast, sc.entitledForJas, sc.getJasHandler(jasutils.Sast))
}

func (sc *CmdResultsSummaryConverter) getJasHandler(scanType jasutils.JasScanType) results.PrepareJasFunc {
	return func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) (err error) {
		if location == nil {
			return
		}
		var count *formats.SummaryCount
		switch scanType {
		case jasutils.Secrets:
			count = sc.currentScan.Vulnerabilities.SecretsScanResults
		case jasutils.IaC:
			count = sc.currentScan.Vulnerabilities.IacScanResults
		case jasutils.Sast:
			count = sc.currentScan.Vulnerabilities.SastScanResults
		}
		if count == nil {
			return
		}
		(*count)[severity.String()]++
		return
	}
}
