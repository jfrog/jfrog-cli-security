package summaryparser

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
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

func (sc *CmdResultsSummaryConverter) DeprecatedParseScaIssues(target results.ScanTarget, violations bool, scaResponse results.ScanResult[services.ScanResponse], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	if violations {
		return sc.parseScaViolations(target, scaResponse, applicableScan...)
	}
	return sc.parseScaVulnerabilities(target, scaResponse, applicableScan...)
}

func (sc *CmdResultsSummaryConverter) parseScaViolations(target results.ScanTarget, scaResponse results.ScanResult[services.ScanResponse], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	if err = sc.validateBeforeParse(); err != nil || sc.currentScan.Violations == nil {
		return
	}
	if sc.currentScan.Violations.ScanResultSummary.ScaResults == nil {
		sc.currentScan.Violations.ScanResultSummary.ScaResults = &formats.ScaScanResultSummary{}
	}
	// Parse general SCA results
	if scaResponse.Scan.ScanId != "" {
		sc.currentScan.Violations.ScanResultSummary.ScaResults.ScanIds = utils.UniqueUnion(sc.currentScan.Violations.ScanResultSummary.ScaResults.ScanIds, scaResponse.Scan.ScanId)
	}
	if scaResponse.Scan.XrayDataUrl != "" {
		sc.currentScan.Violations.ScanResultSummary.ScaResults.MoreInfoUrls = utils.UniqueUnion(sc.currentScan.Violations.ScanResultSummary.ScaResults.MoreInfoUrls, scaResponse.Scan.XrayDataUrl)
	}
	if scaResponse.IsScanFailed() {
		return
	}
	applicabilityRuns := []*sarif.Run{}
	for _, scan := range applicableScan {
		if scan.IsScanFailed() {
			continue
		}
		applicabilityRuns = append(applicabilityRuns, scan.Scan...)
	}
	// Parse violations
	parsed := datastructures.MakeSet[string]()
	watches, failBuild, err := results.ForEachScanGraphViolation(
		target,
		scaResponse.Scan.Violations,
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

func (sc *CmdResultsSummaryConverter) getScaSecurityViolationHandler(parsed *datastructures.Set[string]) results.ParseScanGraphViolationFunc {
	return func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesId string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) (err error) {
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

func (sc *CmdResultsSummaryConverter) getScaLicenseViolationHandler(parsed *datastructures.Set[string]) results.ParseScanGraphViolationFunc {
	return func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesId string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) (err error) {
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

func (sc *CmdResultsSummaryConverter) getScaOperationalRiskViolationHandler(parsed *datastructures.Set[string]) results.ParseScanGraphViolationFunc {
	return func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesId string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) (err error) {
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

func (sc *CmdResultsSummaryConverter) parseScaVulnerabilities(target results.ScanTarget, scaResponse results.ScanResult[services.ScanResponse], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	if err = sc.validateBeforeParse(); err != nil || sc.currentScan.Vulnerabilities == nil {
		return
	}
	if sc.currentScan.Vulnerabilities.ScaResults == nil {
		sc.currentScan.Vulnerabilities.ScaResults = &formats.ScaScanResultSummary{}
	}
	// Parse general SCA results
	if scaResponse.Scan.ScanId != "" {
		sc.currentScan.Vulnerabilities.ScaResults.ScanIds = utils.UniqueUnion(sc.currentScan.Vulnerabilities.ScaResults.ScanIds, scaResponse.Scan.ScanId)
	}
	if scaResponse.Scan.XrayDataUrl != "" {
		sc.currentScan.Vulnerabilities.ScaResults.MoreInfoUrls = utils.UniqueUnion(sc.currentScan.Vulnerabilities.ScaResults.MoreInfoUrls, scaResponse.Scan.XrayDataUrl)
	}
	if scaResponse.IsScanFailed() {
		return
	}
	applicabilityRuns := []*sarif.Run{}
	for _, scan := range applicableScan {
		if scan.IsScanFailed() {
			continue
		}
		applicabilityRuns = append(applicabilityRuns, scan.Scan...)
	}
	// Parse vulnerabilities
	parsed := datastructures.MakeSet[string]()
	err = results.ForEachScanGraphVulnerability(
		target,
		scaResponse.Scan.Vulnerabilities,
		sc.entitledForJas,
		applicabilityRuns,
		sc.getScaVulnerabilityHandler(parsed),
	)
	return
}

func (sc *CmdResultsSummaryConverter) getScaVulnerabilityHandler(parsed *datastructures.Set[string]) results.ParseScanGraphVulnerabilityFunc {
	return func(vulnerability services.Vulnerability, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesId string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) (err error) {
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

func (sc *CmdResultsSummaryConverter) DeprecatedParseLicenses(_ results.ScanTarget, _ results.ScanResult[services.ScanResponse]) (err error) {
	// Not supported in the summary
	return
}

func (sc *CmdResultsSummaryConverter) ParseSbom(_ results.ScanTarget, _ *cyclonedx.BOM) (err error) {
	// Not supported in the summary
	return
}

func (sc *CmdResultsSummaryConverter) ParseSbomLicenses(target results.ScanTarget, components []cyclonedx.Component, dependencies ...cyclonedx.Dependency) (err error) {
	// Not supported in the summary
	return
}

func (sc *CmdResultsSummaryConverter) ParseCVEs(target results.ScanTarget, enrichedSbom results.ScanResult[*cyclonedx.BOM], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	if err = sc.validateBeforeParse(); err != nil || sc.currentScan.Vulnerabilities == nil {
		return
	}
	if sc.currentScan.Vulnerabilities.ScaResults == nil {
		sc.currentScan.Vulnerabilities.ScaResults = &formats.ScaScanResultSummary{}
	}
	// Parse general SCA results
	if enrichedSbom.IsScanFailed() {
		return
	}
	applicabilityRuns := []*sarif.Run{}
	for _, scan := range applicableScan {
		if scan.IsScanFailed() {
			continue
		}
		applicabilityRuns = append(applicabilityRuns, scan.Scan...)
	}
	// Parse vulnerabilities
	return results.ForEachScaBomVulnerability(target, enrichedSbom.Scan, sc.entitledForJas, applicabilityRuns, sc.getBomScaVulnerabilityHandler())
}

func (sc *CmdResultsSummaryConverter) getBomScaVulnerabilityHandler() results.ParseBomScaVulnerabilityFunc {
	parsed := datastructures.MakeSet[string]()
	return func(vulnerability cyclonedx.Vulnerability, _ cyclonedx.Component, _ *[]cyclonedx.AffectedVersions, applicability *formats.Applicability, severity severityutils.Severity) (err error) {
		if parsed.Exists(vulnerability.BOMRef) {
			return
		}
		parsed.Add(vulnerability.BOMRef)
		// Count the vulnerability
		applicabilityStatus := jasutils.NotScanned
		if applicability != nil {
			applicabilityStatus = jasutils.ConvertToApplicabilityStatus(applicability.Status)
		}
		scaSecurityHandler(sc.currentScan.Vulnerabilities.ScaResults, severity, applicabilityStatus)
		return
	}
}

func (sc *CmdResultsSummaryConverter) ParseViolations(target results.ScanTarget, violations []services.Violation, applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	scanResponse := results.ScanResult[services.ScanResponse]{
		Scan: services.ScanResponse{
			Violations: violations,
			// ScanId and XrayDataUrl are not supported in the summary for new flow, will be implemented after the JPD can produce the new UI
			ScanId:      "",
			XrayDataUrl: "",
		},
	}
	return sc.parseScaViolations(target, scanResponse, applicableScan...)
}

func (sc *CmdResultsSummaryConverter) ParseSecrets(_ results.ScanTarget, isViolationsResults bool, secrets []results.ScanResult[[]*sarif.Run]) (err error) {
	if !sc.entitledForJas || sc.currentScan.Vulnerabilities == nil {
		// JAS results are only supported as vulnerabilities for now
		return
	}
	if err = sc.validateBeforeParse(); err != nil {
		return
	}
	if !isViolationsResults && sc.currentScan.Vulnerabilities.SecretsResults == nil {
		sc.currentScan.Vulnerabilities.SecretsResults = &formats.ResultSummary{}
	}
	if isViolationsResults {
		if sc.currentScan.Violations.SecretsResults == nil {
			sc.currentScan.Violations.SecretsResults = &formats.ResultSummary{}
		}
		sc.currentScan.Violations.Watches = utils.UniqueUnion(sc.currentScan.Violations.Watches, getJasScansWatches(secrets...)...)
	}
	return results.ForEachJasIssue(results.ScanResultsToRuns(secrets), sc.entitledForJas, sc.getJasHandler(jasutils.Secrets, isViolationsResults))
}

func (sc *CmdResultsSummaryConverter) ParseIacs(_ results.ScanTarget, isViolationsResults bool, iacs []results.ScanResult[[]*sarif.Run]) (err error) {
	if !sc.entitledForJas || sc.currentScan.Vulnerabilities == nil {
		// JAS results are only supported as vulnerabilities for now
		return
	}
	if err = sc.validateBeforeParse(); err != nil {
		return
	}
	if !isViolationsResults && sc.currentScan.Vulnerabilities.IacResults == nil {
		sc.currentScan.Vulnerabilities.IacResults = &formats.ResultSummary{}
	}
	if isViolationsResults {
		if sc.currentScan.Violations.IacResults == nil {
			sc.currentScan.Violations.IacResults = &formats.ResultSummary{}
		}
		sc.currentScan.Violations.Watches = utils.UniqueUnion(sc.currentScan.Violations.Watches, getJasScansWatches(iacs...)...)
	}
	return results.ForEachJasIssue(results.ScanResultsToRuns(iacs), sc.entitledForJas, sc.getJasHandler(jasutils.IaC, isViolationsResults))
}

func (sc *CmdResultsSummaryConverter) ParseSast(_ results.ScanTarget, isViolationsResults bool, sast []results.ScanResult[[]*sarif.Run]) (err error) {
	if !sc.entitledForJas || sc.currentScan.Vulnerabilities == nil {
		// JAS results are only supported as vulnerabilities for now
		return
	}
	if err = sc.validateBeforeParse(); err != nil {
		return
	}
	if !isViolationsResults && sc.currentScan.Vulnerabilities.SastResults == nil {
		sc.currentScan.Vulnerabilities.SastResults = &formats.ResultSummary{}
	}
	if isViolationsResults {
		if sc.currentScan.Violations.SastResults == nil {
			sc.currentScan.Violations.SastResults = &formats.ResultSummary{}
		}
		sc.currentScan.Violations.Watches = utils.UniqueUnion(sc.currentScan.Violations.Watches, getJasScansWatches(sast...)...)
	}
	return results.ForEachJasIssue(results.ScanResultsToRuns(sast), sc.entitledForJas, sc.getJasHandler(jasutils.Sast, isViolationsResults))
}

// getJasHandler returns a handler that counts the JAS results (based on severity and CA status) for each issue it handles
func (sc *CmdResultsSummaryConverter) getJasHandler(scanType jasutils.JasScanType, violations bool) results.ParseJasIssueFunc {
	return func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) (err error) {
		if location == nil {
			// Only count the issue if it has a location
			return
		}
		// Get the count map in the `sc.currentScan` object based on the scanType and violation
		resultStatus := formats.NoStatus
		var count *formats.ResultSummary
		switch scanType {
		case jasutils.Secrets:
			if tokenStatus := sarifutils.GetResultPropertyTokenValidation(result); tokenStatus != "" {
				resultStatus = tokenStatus
			}
			if violations {
				count = sc.currentScan.Violations.SecretsResults
			} else {
				count = sc.currentScan.Vulnerabilities.SecretsResults
			}
		case jasutils.IaC:
			if violations {
				count = sc.currentScan.Violations.IacResults
			} else {
				count = sc.currentScan.Vulnerabilities.IacResults
			}
		case jasutils.Sast:
			if violations {
				count = sc.currentScan.Violations.SastResults
			} else {
				count = sc.currentScan.Vulnerabilities.SastResults
			}
		}
		if count == nil {
			return
		}
		// Aggregate the issue in to the count (based on severity and CA status)
		if _, ok := (*count)[severity.String()]; !ok {
			(*count)[severity.String()] = map[string]int{}
		}
		(*count)[severity.String()][resultStatus] += 1
		return
	}
}

func getJasScansWatches(scans ...results.ScanResult[[]*sarif.Run]) (watches []string) {
	for _, scanInfo := range scans {
		for _, run := range scanInfo.Scan {
			for _, result := range run.Results {
				if watch := sarifutils.GetResultWatches(result); watch != "" {
					watches = append(watches, watch)
				}
			}
		}
	}
	return
}
