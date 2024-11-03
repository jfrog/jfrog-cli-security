package summaryparser

import (
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

type CmdResultsSummaryConverter struct {
	entitledForJas         bool
	includeVulnerabilities bool
	includeViolations      bool

	current     *formats.ResultsSummary
	currentScan *formats.ScanSummary
}

func NewCmdResultsSummaryConverter(includeVulnerabilities, hasViolationContext bool) *CmdResultsSummaryConverter {
	return &CmdResultsSummaryConverter{includeVulnerabilities: includeVulnerabilities, includeViolations: hasViolationContext}
}

func (sc *CmdResultsSummaryConverter) Get() (formats.ResultsSummary, error) {
	if sc.current == nil {
		return formats.ResultsSummary{}, nil
	}
	// Flush the last scan
	if err := sc.ParseNewTargetResults(results.ScanTarget{}, nil); err != nil {
		return formats.ResultsSummary{}, err
	}
	return *sc.current, nil
}

func (sc *CmdResultsSummaryConverter) Reset(_ utils.CommandType, _, _ string, entitledForJas, _ bool, _ error) (err error) {
	sc.current = &formats.ResultsSummary{}
	sc.entitledForJas = entitledForJas
	return
}

func (sc *CmdResultsSummaryConverter) ParseNewTargetResults(target results.ScanTarget, _ ...error) (err error) {
	if sc.current == nil {
		return results.ErrResetConvertor
	}
	if sc.currentScan != nil {
		sc.current.Scans = append(sc.current.Scans, *sc.currentScan)
	}
	sc.currentScan = &formats.ScanSummary{Target: target.Target, Name: target.Name}
	if sc.includeVulnerabilities {
		sc.currentScan.Vulnerabilities = &formats.ScanResultSummary{}
	}
	if sc.includeViolations {
		sc.currentScan.Violations = &formats.ScanViolationsSummary{ScanResultSummary: formats.ScanResultSummary{}}
	}
	return
}

// validateBeforeParse checks if the parser is initialized to parse results (checks if Reset and at least one ParseNewTargetResults was called before)
func (sc *CmdResultsSummaryConverter) validateBeforeParse() (err error) {
	if sc.current == nil {
		return results.ErrResetConvertor
	}
	if sc.currentScan == nil {
		return results.ErrNoTargetConvertor
	}
	return
}

func (sc *CmdResultsSummaryConverter) ParseViolations(target results.ScanTarget, scaResponse services.ScanResponse, applicabilityRuns ...*sarif.Run) (err error) {
	if err = sc.validateBeforeParse(); err != nil || sc.currentScan.Violations == nil {
		return
	}
	if sc.currentScan.Violations.ScanResultSummary.ScaResults == nil {
		sc.currentScan.Violations.ScanResultSummary.ScaResults = &formats.ScaScanResultSummary{}
	}
	// Parse general SCA results
	if scaResponse.ScanId != "" {
		sc.currentScan.Violations.ScanResultSummary.ScaResults.ScanIds = utils.UniqueUnion(sc.currentScan.Violations.ScanResultSummary.ScaResults.ScanIds, scaResponse.ScanId)
	}
	if scaResponse.XrayDataUrl != "" {
		sc.currentScan.Violations.ScanResultSummary.ScaResults.MoreInfoUrls = utils.UniqueUnion(sc.currentScan.Violations.ScanResultSummary.ScaResults.MoreInfoUrls, scaResponse.XrayDataUrl)
	}
	// Parse violations
	parsed := datastructures.MakeSet[string]()
	watches, failBuild, err := results.PrepareScaViolations(
		target,
		scaResponse.Violations,
		sc.entitledForJas,
		applicabilityRuns,
		sc.getScaSecurityViolationHandler(parsed),
		sc.getScaLicenseViolationHandler(parsed),
		sc.getScaOperationalRiskViolationHandler(parsed),
	)
	if err != nil {
		return
	}
	sc.currentScan.Violations.Watches = utils.UniqueUnion(sc.currentScan.Violations.Watches, watches...)
	sc.currentScan.Violations.FailBuild = sc.currentScan.Violations.FailBuild || failBuild
	return
}

func (sc *CmdResultsSummaryConverter) getScaSecurityViolationHandler(parsed *datastructures.Set[string]) results.ParseScaViolationFunc {
	return func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) (err error) {
		for _, id := range getCveIds(cves, violation.IssueId) {
			// PrepareScaViolations calls the handler for each violation and impacted component pair, we want to count unique violations
			key := violation.WatchName + id
			if parsed.Exists(key) {
				continue
			}
			parsed.Add(key)
			// Count the violation
			scaSecurityHandler(sc.currentScan.Violations.ScanResultSummary.ScaResults, severity, applicabilityStatus)
		}
		return
	}
}

func (sc *CmdResultsSummaryConverter) getScaLicenseViolationHandler(parsed *datastructures.Set[string]) results.ParseScaViolationFunc {
	return func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) (err error) {
		if sc.currentScan.Violations.ScaResults.License == nil {
			sc.currentScan.Violations.ScaResults.License = formats.ResultSummary{}
		}
		// PrepareScaViolations calls the handler for each violation and impacted component pair, we want to count unique violations
		key := violation.WatchName + violation.IssueId
		if parsed.Exists(key) {
			return
		}
		parsed.Add(key)
		if _, ok := sc.currentScan.Violations.ScaResults.License[severity.String()]; !ok {
			sc.currentScan.Violations.ScaResults.License[severity.String()] = map[string]int{}
		}
		sc.currentScan.Violations.ScaResults.License[severity.String()][formats.NoStatus]++
		return
	}
}

func (sc *CmdResultsSummaryConverter) getScaOperationalRiskViolationHandler(parsed *datastructures.Set[string]) results.ParseScaViolationFunc {
	return func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) (err error) {
		if sc.currentScan.Violations.ScaResults.OperationalRisk == nil {
			sc.currentScan.Violations.ScaResults.OperationalRisk = formats.ResultSummary{}
		}
		// PrepareScaViolations calls the handler for each violation and impacted component pair, we want to count unique violations
		key := violation.WatchName + violation.IssueId
		if parsed.Exists(key) {
			return
		}
		parsed.Add(key)
		if _, ok := sc.currentScan.Violations.ScaResults.OperationalRisk[severity.String()]; !ok {
			sc.currentScan.Violations.ScaResults.OperationalRisk[severity.String()] = map[string]int{}
		}
		sc.currentScan.Violations.ScaResults.OperationalRisk[severity.String()][formats.NoStatus]++
		return
	}
}

func (sc *CmdResultsSummaryConverter) ParseVulnerabilities(target results.ScanTarget, scaResponse services.ScanResponse, applicabilityRuns ...*sarif.Run) (err error) {
	if err = sc.validateBeforeParse(); err != nil || sc.currentScan.Vulnerabilities == nil {
		return
	}
	if sc.currentScan.Vulnerabilities.ScaResults == nil {
		sc.currentScan.Vulnerabilities.ScaResults = &formats.ScaScanResultSummary{}
	}
	// Parse general SCA results
	if scaResponse.ScanId != "" {
		sc.currentScan.Vulnerabilities.ScaResults.ScanIds = utils.UniqueUnion(sc.currentScan.Vulnerabilities.ScaResults.ScanIds, scaResponse.ScanId)
	}
	if scaResponse.XrayDataUrl != "" {
		sc.currentScan.Vulnerabilities.ScaResults.MoreInfoUrls = utils.UniqueUnion(sc.currentScan.Vulnerabilities.ScaResults.MoreInfoUrls, scaResponse.XrayDataUrl)
	}
	// Parse vulnerabilities
	parsed := datastructures.MakeSet[string]()
	err = results.PrepareScaVulnerabilities(
		target,
		scaResponse.Vulnerabilities,
		sc.entitledForJas,
		applicabilityRuns,
		sc.getScaVulnerabilityHandler(parsed),
	)
	return
}

func (sc *CmdResultsSummaryConverter) getScaVulnerabilityHandler(parsed *datastructures.Set[string]) results.ParseScaVulnerabilityFunc {
	return func(vulnerability services.Vulnerability, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) (err error) {
		for _, id := range getCveIds(cves, vulnerability.IssueId) {
			// PrepareScaVulnerabilities calls the handler for each vulnerability and impacted component pair, we want to count unique vulnerabilities
			if parsed.Exists(id) {
				continue
			}
			parsed.Add(id)
			// Count the vulnerability
			scaSecurityHandler(sc.currentScan.Vulnerabilities.ScaResults, severity, applicabilityStatus)
		}
		return
	}
}

func scaSecurityHandler(scaResults *formats.ScaScanResultSummary, severity severityutils.Severity, applicabilityStatus jasutils.ApplicabilityStatus) {
	if scaResults.Security == nil {
		scaResults.Security = formats.ResultSummary{}
	}
	if _, ok := scaResults.Security[severity.String()]; !ok {
		scaResults.Security[severity.String()] = map[string]int{}
	}
	if _, ok := scaResults.Security[severity.String()][applicabilityStatus.String()]; !ok {
		scaResults.Security[severity.String()][applicabilityStatus.String()] = 0
	}
	scaResults.Security[severity.String()][applicabilityStatus.String()]++
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

func (sc *CmdResultsSummaryConverter) ParseLicenses(target results.ScanTarget, licenses []services.License) (err error) {
	// Not supported in the summary
	return
}

func (sc *CmdResultsSummaryConverter) ParseSecrets(_ results.ScanTarget, secrets ...*sarif.Run) (err error) {
	if !sc.entitledForJas || sc.currentScan.Vulnerabilities == nil {
		// JAS results are only supported as vulnerabilities for now
		return
	}
	if err = sc.validateBeforeParse(); err != nil {
		return
	}
	if sc.currentScan.Vulnerabilities.SecretsResults == nil {
		sc.currentScan.Vulnerabilities.SecretsResults = &formats.ResultSummary{}
	}
	return results.PrepareJasIssues(secrets, sc.entitledForJas, sc.getJasHandler(jasutils.Secrets))
}

func (sc *CmdResultsSummaryConverter) ParseIacs(_ results.ScanTarget, iacs ...*sarif.Run) (err error) {
	if !sc.entitledForJas || sc.currentScan.Vulnerabilities == nil {
		// JAS results are only supported as vulnerabilities for now
		return
	}
	if err = sc.validateBeforeParse(); err != nil {
		return
	}
	if sc.currentScan.Vulnerabilities.IacResults == nil {
		sc.currentScan.Vulnerabilities.IacResults = &formats.ResultSummary{}
	}
	return results.PrepareJasIssues(iacs, sc.entitledForJas, sc.getJasHandler(jasutils.IaC))
}

func (sc *CmdResultsSummaryConverter) ParseSast(_ results.ScanTarget, sast ...*sarif.Run) (err error) {
	if !sc.entitledForJas || sc.currentScan.Vulnerabilities == nil {
		// JAS results are only supported as vulnerabilities for now
		return
	}
	if err = sc.validateBeforeParse(); err != nil {
		return
	}
	if sc.currentScan.Vulnerabilities.SastResults == nil {
		sc.currentScan.Vulnerabilities.SastResults = &formats.ResultSummary{}
	}
	return results.PrepareJasIssues(sast, sc.entitledForJas, sc.getJasHandler(jasutils.Sast))
}

func (sc *CmdResultsSummaryConverter) getJasHandler(scanType jasutils.JasScanType) results.ParseJasFunc {
	return func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) (err error) {
		if location == nil {
			// Only count the issue if it has a location
			return
		}
		// Get the scanType count
		var count *formats.ResultSummary
		switch scanType {
		case jasutils.Secrets:
			count = sc.currentScan.Vulnerabilities.SecretsResults
		case jasutils.IaC:
			count = sc.currentScan.Vulnerabilities.IacResults
		case jasutils.Sast:
			count = sc.currentScan.Vulnerabilities.SastResults
		}
		if count == nil {
			return
		}
		// PrepareJasIssues calls the handler for each issue (location)
		if _, ok := (*count)[severity.String()]; !ok {
			(*count)[severity.String()] = map[string]int{}
		}
		(*count)[severity.String()][formats.NoStatus] += 1
		return
	}
}
