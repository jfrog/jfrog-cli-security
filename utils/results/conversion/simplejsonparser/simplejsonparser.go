package simplejsonparser

import (
	"sort"
	"strconv"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

type CmdResultsSimpleJsonConverter struct {
	// If supported, pretty print the output text
	pretty bool
	// Current stream parse cache information
	current *formats.SimpleJsonResults
	// General information on the current command results
	entitledForJas bool
}

func NewCmdResultsSimpleJsonConverter(pretty bool) *CmdResultsSimpleJsonConverter {
	return &CmdResultsSimpleJsonConverter{pretty: pretty}
}

func (sjc *CmdResultsSimpleJsonConverter) Get() *formats.SimpleJsonResults {
	if sjc.current == nil {
		return nil
	}
	sortResults(sjc.current)
	return sjc.current
}

func (sjc *CmdResultsSimpleJsonConverter) Reset(multiScanId, _ string, entitledForJas bool) (err error) {
	sjc.current = &formats.SimpleJsonResults{MultiScanId: multiScanId}
	sjc.entitledForJas = entitledForJas
	return
}

func (sjc *CmdResultsSimpleJsonConverter) ParseNewScanResultsMetadata(target string, errors error) (err error) {
	if sjc.current == nil {
		return results.ConvertorResetErr
	}
	if errors != nil {
		sjc.current.Errors = append(sjc.current.Errors, formats.SimpleJsonError{FilePath: target, ErrorMessage: errors.Error()})
	}
	return
}

func (sjc *CmdResultsSimpleJsonConverter) ParseViolations(target string, _ techutils.Technology, violations []services.Violation, applicabilityRuns ...*sarif.Run) (err error) {
	if sjc.current == nil {
		return results.ConvertorResetErr
	}
	secViolationsSimpleJson, licViolationsSimpleJson, opRiskViolationsSimpleJson, err := PrepareSimpleJsonViolations(target, violations, sjc.entitledForJas, sjc.pretty, applicabilityRuns...)
	if err != nil {
		return
	}
	sjc.current.SecurityViolations = append(sjc.current.SecurityViolations, secViolationsSimpleJson...)
	sjc.current.LicensesViolations = append(sjc.current.LicensesViolations, licViolationsSimpleJson...)
	sjc.current.OperationalRiskViolations = append(sjc.current.OperationalRiskViolations, opRiskViolationsSimpleJson...)
	return
}

func (sjc *CmdResultsSimpleJsonConverter) ParseVulnerabilities(target string, _ techutils.Technology, vulnerabilities []services.Vulnerability, applicabilityRuns ...*sarif.Run) (err error) {
	if sjc.current == nil {
		return results.ConvertorResetErr
	}
	vulSimpleJson, err := PrepareSimpleJsonVulnerabilities(target, vulnerabilities, sjc.entitledForJas, sjc.pretty, applicabilityRuns...)
	if err != nil || len(vulSimpleJson) == 0 {
		return
	}
	sjc.current.Vulnerabilities = append(sjc.current.Vulnerabilities, vulSimpleJson...)
	return
}

func (sjc *CmdResultsSimpleJsonConverter) ParseLicenses(target string, _ techutils.Technology, licenses []services.License) (err error) {
	if sjc.current == nil {
		return results.ConvertorResetErr
	}
	licSimpleJson, err := PrepareSimpleJsonLicenses(target, licenses)
	if err != nil || len(licSimpleJson) == 0 {
		return
	}
	sjc.current.Licenses = append(sjc.current.Licenses, licSimpleJson...)
	return
}

func (sjc *CmdResultsSimpleJsonConverter) ParseSecrets(target string, secrets ...*sarif.Run) (err error) {
	if !sjc.entitledForJas {
		return
	}
	if sjc.current == nil {
		return results.ConvertorResetErr
	}
	secretsSimpleJson, err := PrepareSimpleJsonJasIssues(target, sjc.entitledForJas, sjc.pretty, secrets...)
	if err != nil || len(secretsSimpleJson) == 0 {
		return
	}
	sjc.current.Secrets = append(sjc.current.Secrets, secretsSimpleJson...)
	return
}

func (sjc *CmdResultsSimpleJsonConverter) ParseIacs(target string, iacs ...*sarif.Run) (err error) {
	if !sjc.entitledForJas {
		return
	}
	if sjc.current == nil {
		return results.ConvertorResetErr
	}
	iacSimpleJson, err := PrepareSimpleJsonJasIssues(target, sjc.entitledForJas, sjc.pretty, iacs...)
	if err != nil || len(iacSimpleJson) == 0 {
		return
	}
	sjc.current.Iacs = append(sjc.current.Iacs, iacSimpleJson...)
	return
}

func (sjc *CmdResultsSimpleJsonConverter) ParseSast(target string, sast ...*sarif.Run) (err error) {
	if !sjc.entitledForJas {
		return
	}
	if sjc.current == nil {
		return results.ConvertorResetErr
	}
	sastSimpleJson, err := PrepareSimpleJsonJasIssues(target, sjc.entitledForJas, sjc.pretty, sast...)
	if err != nil || len(sastSimpleJson) == 0 {
		return
	}
	sjc.current.Sast = append(sjc.current.Sast, sastSimpleJson...)
	return
}

func PrepareSimpleJsonViolations(target string, violations []services.Violation, jasEntitled, pretty bool, applicabilityRuns ...*sarif.Run) ([]formats.VulnerabilityOrViolationRow, []formats.LicenseRow, []formats.OperationalRiskViolationRow, error) {
	var securityViolationsRows []formats.VulnerabilityOrViolationRow
	var licenseViolationsRows []formats.LicenseRow
	var operationalRiskViolationsRows []formats.OperationalRiskViolationRow
	err := results.PrepareScaViolations(
		target,
		violations,
		jasEntitled,
		pretty,
		applicabilityRuns,
		addSimpleJsonSecurityViolation(&securityViolationsRows, pretty),
		addSimpleJsonLicenseViolation(&licenseViolationsRows, pretty),
		addSimpleJsonOperationalRiskViolation(&operationalRiskViolationsRows, pretty),
	)
	return securityViolationsRows, licenseViolationsRows, operationalRiskViolationsRows, err
}

func PrepareSimpleJsonVulnerabilities(target string, vulnerabilities []services.Vulnerability, entitledForJas, pretty bool, applicabilityRuns ...*sarif.Run) ([]formats.VulnerabilityOrViolationRow, error) {
	var vulnerabilitiesRows []formats.VulnerabilityOrViolationRow
	err := results.PrepareScaVulnerabilities(
		target,
		vulnerabilities,
		entitledForJas,
		pretty,
		applicabilityRuns,
		addSimpleJsonVulnerability(&vulnerabilitiesRows, pretty),
	)
	return vulnerabilitiesRows, err
}

func addSimpleJsonVulnerability(vulnerabilitiesRows *[]formats.VulnerabilityOrViolationRow, pretty bool) results.PrepareScaVulnerabilityFunc {
	return func(vulnerability services.Vulnerability, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error {
		*vulnerabilitiesRows = append(*vulnerabilitiesRows,
			formats.VulnerabilityOrViolationRow{
				Summary: vulnerability.Summary,
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:           severityutils.GetAsDetails(severity, applicabilityStatus, pretty),
					ImpactedDependencyName:    impactedPackagesName,
					ImpactedDependencyVersion: impactedPackagesVersion,
					ImpactedDependencyType:    impactedPackagesType,
					Components:                directComponents,
				},
				FixedVersions:            fixedVersion,
				Cves:                     cves,
				IssueId:                  vulnerability.IssueId,
				References:               vulnerability.References,
				JfrogResearchInformation: convertJfrogResearchInformation(vulnerability.ExtendedInformation),
				ImpactPaths:              impactPaths,
				Technology:               techutils.Technology(vulnerability.Technology),
				Applicable:               applicabilityStatus.ToString(pretty),
			},
		)
		return nil
	}
}

func addSimpleJsonSecurityViolation(securityViolationsRows *[]formats.VulnerabilityOrViolationRow, pretty bool) results.PrepareScaViolationFunc {
	return func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error {
		*securityViolationsRows = append(*securityViolationsRows,
			formats.VulnerabilityOrViolationRow{
				Summary: violation.Summary,
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:           severityutils.GetAsDetails(severity, applicabilityStatus, pretty),
					ImpactedDependencyName:    impactedPackagesName,
					ImpactedDependencyVersion: impactedPackagesVersion,
					ImpactedDependencyType:    impactedPackagesType,
					Components:                directComponents,
				},
				FixedVersions:            fixedVersion,
				Cves:                     cves,
				IssueId:                  violation.IssueId,
				References:               violation.References,
				JfrogResearchInformation: convertJfrogResearchInformation(violation.ExtendedInformation),
				ImpactPaths:              impactPaths,
				Technology:               techutils.Technology(violation.Technology),
				Applicable:               applicabilityStatus.ToString(pretty),
			},
		)
		return nil
	}
}

func addSimpleJsonLicenseViolation(licenseViolationsRows *[]formats.LicenseRow, pretty bool) results.PrepareScaViolationFunc {
	return func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error {
		*licenseViolationsRows = append(*licenseViolationsRows,
			formats.LicenseRow{
				LicenseKey: violation.LicenseKey,
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:           severityutils.GetAsDetails(severity, applicabilityStatus, pretty),
					ImpactedDependencyName:    impactedPackagesName,
					ImpactedDependencyVersion: impactedPackagesVersion,
					ImpactedDependencyType:    impactedPackagesType,
					Components:                directComponents,
				},
			},
		)
		return nil
	}
}

func addSimpleJsonOperationalRiskViolation(operationalRiskViolationsRows *[]formats.OperationalRiskViolationRow, pretty bool) results.PrepareScaViolationFunc {
	return func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error {
		violationOpRiskData := getOperationalRiskViolationReadableData(violation)
		for compIndex := 0; compIndex < len(impactedPackagesName); compIndex++ {
			operationalRiskViolationsRow := &formats.OperationalRiskViolationRow{
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:           severityutils.GetAsDetails(severity, applicabilityStatus, pretty),
					ImpactedDependencyName:    impactedPackagesName,
					ImpactedDependencyVersion: impactedPackagesVersion,
					ImpactedDependencyType:    impactedPackagesType,
					Components:                directComponents,
				},
				IsEol:         violationOpRiskData.isEol,
				Cadence:       violationOpRiskData.cadence,
				Commits:       violationOpRiskData.commits,
				Committers:    violationOpRiskData.committers,
				NewerVersions: violationOpRiskData.newerVersions,
				LatestVersion: violationOpRiskData.latestVersion,
				RiskReason:    violationOpRiskData.riskReason,
				EolMessage:    violationOpRiskData.eolMessage,
			}
			*operationalRiskViolationsRows = append(*operationalRiskViolationsRows, *operationalRiskViolationsRow)
		}
		return nil
	}
}

func PrepareSimpleJsonLicenses(target string, licenses []services.License) ([]formats.LicenseRow, error) {
	var licensesRows []formats.LicenseRow
	err := results.PrepareLicenses(target, licenses, addSimpleJsonLicense(&licensesRows))
	return licensesRows, err
}

func addSimpleJsonLicense(licenseViolationsRows *[]formats.LicenseRow) results.PrepareLicensesFunc {
	return func(license services.License, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error {
		*licenseViolationsRows = append(*licenseViolationsRows,
			formats.LicenseRow{
				LicenseKey:  license.Key,
				ImpactPaths: impactPaths,
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					ImpactedDependencyName:    impactedPackagesName,
					ImpactedDependencyVersion: impactedPackagesVersion,
					ImpactedDependencyType:    impactedPackagesType,
					Components:                directComponents,
				},
			},
		)
		return nil
	}
}

func PrepareSimpleJsonJasIssues(target string, entitledForJas, pretty bool, jasIssues ...*sarif.Run) ([]formats.SourceCodeRow, error) {
	var rows []formats.SourceCodeRow
	err := results.PrepareJasIssues(target, jasIssues, entitledForJas, func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) error {
		scannerDescription := ""
		if rule != nil {
			scannerDescription = sarifutils.GetRuleFullDescription(rule)
		}
		rows = append(rows,
			formats.SourceCodeRow{
				SeverityDetails:    severityutils.GetAsDetails(severity, jasutils.Applicable, pretty),
				Finding:            sarifutils.GetResultMsgText(result),
				ScannerDescription: scannerDescription,
				Location: formats.Location{
					File:        sarifutils.GetRelativeLocationFileName(location, run.Invocations),
					StartLine:   sarifutils.GetLocationStartLine(location),
					StartColumn: sarifutils.GetLocationStartColumn(location),
					EndLine:     sarifutils.GetLocationEndLine(location),
					EndColumn:   sarifutils.GetLocationEndColumn(location),
					Snippet:     sarifutils.GetLocationSnippet(location),
				},
				CodeFlow: codeFlowToLocationFlow(sarifutils.GetLocationRelatedCodeFlowsFromResult(location, result), run.Invocations, pretty),
			},
		)
		return nil
	})
	return rows, err
}

func codeFlowToLocationFlow(flows []*sarif.CodeFlow, invocations []*sarif.Invocation, isTable bool) (flowRows [][]formats.Location) {
	if isTable {
		// Not displaying in table
		return
	}
	for _, codeFlow := range flows {
		for _, stackTrace := range codeFlow.ThreadFlows {
			rowFlow := []formats.Location{}
			for _, stackTraceEntry := range stackTrace.Locations {
				rowFlow = append(rowFlow, formats.Location{
					File:        sarifutils.GetRelativeLocationFileName(stackTraceEntry.Location, invocations),
					StartLine:   sarifutils.GetLocationStartLine(stackTraceEntry.Location),
					StartColumn: sarifutils.GetLocationStartColumn(stackTraceEntry.Location),
					EndLine:     sarifutils.GetLocationEndLine(stackTraceEntry.Location),
					EndColumn:   sarifutils.GetLocationEndColumn(stackTraceEntry.Location),
					Snippet:     sarifutils.GetLocationSnippet(stackTraceEntry.Location),
				})
			}
			flowRows = append(flowRows, rowFlow)
		}
	}
	return
}

func sortResults(simpleJsonResults *formats.SimpleJsonResults) {
	if simpleJsonResults == nil {
		return
	}
	if len(simpleJsonResults.SecurityViolations) > 0 {
		sortVulnerabilityOrViolationRows(simpleJsonResults.SecurityViolations)
	}
	if len(simpleJsonResults.Vulnerabilities) > 0 {
		sortVulnerabilityOrViolationRows(simpleJsonResults.Vulnerabilities)
	}
	if len(simpleJsonResults.LicensesViolations) > 0 {
		sort.Slice(simpleJsonResults.LicensesViolations, func(i, j int) bool {
			return simpleJsonResults.LicensesViolations[i].SeverityNumValue > simpleJsonResults.LicensesViolations[j].SeverityNumValue
		})
	}
	if len(simpleJsonResults.OperationalRiskViolations) > 0 {
		sort.Slice(simpleJsonResults.OperationalRiskViolations, func(i, j int) bool {
			return simpleJsonResults.OperationalRiskViolations[i].SeverityNumValue > simpleJsonResults.OperationalRiskViolations[j].SeverityNumValue
		})
	}
	if len(simpleJsonResults.Secrets) > 0 {
		sort.Slice(simpleJsonResults.Secrets, func(i, j int) bool {
			return simpleJsonResults.Secrets[i].SeverityNumValue > simpleJsonResults.Secrets[j].SeverityNumValue
		})
	}
	if len(simpleJsonResults.Iacs) > 0 {
		sort.Slice(simpleJsonResults.Iacs, func(i, j int) bool {
			return simpleJsonResults.Iacs[i].SeverityNumValue > simpleJsonResults.Iacs[j].SeverityNumValue
		})
	}
	if len(simpleJsonResults.Sast) > 0 {
		sort.Slice(simpleJsonResults.Sast, func(i, j int) bool {
			return simpleJsonResults.Sast[i].SeverityNumValue > simpleJsonResults.Sast[j].SeverityNumValue
		})
	}
}

func sortVulnerabilityOrViolationRows(rows []formats.VulnerabilityOrViolationRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].SeverityNumValue != rows[j].SeverityNumValue {
			return rows[i].SeverityNumValue > rows[j].SeverityNumValue
		}
		return len(rows[i].FixedVersions) > 0 && len(rows[j].FixedVersions) > 0
	})
}

func convertJfrogResearchInformation(extendedInfo *services.ExtendedInformation) *formats.JfrogResearchInformation {
	if extendedInfo == nil {
		return nil
	}
	var severityReasons []formats.JfrogResearchSeverityReason
	for _, severityReason := range extendedInfo.JfrogResearchSeverityReasons {
		severityReasons = append(severityReasons, formats.JfrogResearchSeverityReason{
			Name:        severityReason.Name,
			Description: severityReason.Description,
			IsPositive:  severityReason.IsPositive,
		})
	}
	return &formats.JfrogResearchInformation{
		Summary:         extendedInfo.ShortDescription,
		Details:         extendedInfo.FullDescription,
		SeverityDetails: formats.SeverityDetails{Severity: extendedInfo.JfrogResearchSeverity},
		SeverityReasons: severityReasons,
		Remediation:     extendedInfo.Remediation,
	}
}

type operationalRiskViolationReadableData struct {
	isEol         string
	cadence       string
	commits       string
	committers    string
	eolMessage    string
	riskReason    string
	latestVersion string
	newerVersions string
}

func getOperationalRiskViolationReadableData(violation services.Violation) *operationalRiskViolationReadableData {
	isEol, cadence, commits, committers, newerVersions, latestVersion := "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"
	if violation.IsEol != nil {
		isEol = strconv.FormatBool(*violation.IsEol)
	}
	if violation.Cadence != nil {
		cadence = strconv.FormatFloat(*violation.Cadence, 'f', -1, 64)
	}
	if violation.Committers != nil {
		committers = strconv.FormatInt(int64(*violation.Committers), 10)
	}
	if violation.Commits != nil {
		commits = strconv.FormatInt(*violation.Commits, 10)
	}
	if violation.NewerVersions != nil {
		newerVersions = strconv.FormatInt(int64(*violation.NewerVersions), 10)
	}
	if violation.LatestVersion != "" {
		latestVersion = violation.LatestVersion
	}
	return &operationalRiskViolationReadableData{
		isEol:         isEol,
		cadence:       cadence,
		commits:       commits,
		committers:    committers,
		eolMessage:    violation.EolMessage,
		riskReason:    violation.RiskReason,
		latestVersion: latestVersion,
		newerVersions: newerVersions,
	}
}