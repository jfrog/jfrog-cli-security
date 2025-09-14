package simplejsonparser

import (
	"sort"
	"strconv"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/policy/local"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xscServices "github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

type CmdResultsSimpleJsonConverter struct {
	// If supported, pretty print the output text
	pretty bool
	// If true, the output will contain only unique issues (ignoring the same issue in different locations)
	uniqueScaIssues bool
	// Current stream parse cache information
	current       *formats.SimpleJsonResults
	currentTarget results.ScanTarget
	// General information on the current command results
	entitledForJas bool
	multipleRoots  bool
}

func NewCmdResultsSimpleJsonConverter(pretty, uniqueScaIssues bool) *CmdResultsSimpleJsonConverter {
	return &CmdResultsSimpleJsonConverter{pretty: pretty, uniqueScaIssues: uniqueScaIssues}
}

func (sjc *CmdResultsSimpleJsonConverter) Get() (formats.SimpleJsonResults, error) {
	if sjc.current == nil {
		return formats.SimpleJsonResults{}, nil
	}
	if sjc.uniqueScaIssues {
		sjc.current.Vulnerabilities = removeScaDuplications(sjc.current.Vulnerabilities, sjc.multipleRoots)
		sjc.current.SecurityViolations = removeScaDuplications(sjc.current.SecurityViolations, sjc.multipleRoots)
	}
	sortResults(sjc.current)
	return *sjc.current, nil
}

func (sjc *CmdResultsSimpleJsonConverter) Reset(_ utils.CommandType, multiScanId, _ string, entitledForJas, multipleTargets bool, _ *xscServices.XscGitInfoContext, generalError error) (err error) {
	sjc.current = &formats.SimpleJsonResults{MultiScanId: multiScanId}
	sjc.entitledForJas = entitledForJas
	sjc.multipleRoots = multipleTargets
	if generalError != nil {
		sjc.current.Errors = append(sjc.current.Errors, formats.SimpleJsonError{ErrorMessage: generalError.Error()})
	}
	return
}

func (sjc *CmdResultsSimpleJsonConverter) ParseNewTargetResults(target results.ScanTarget, errors ...error) (err error) {
	if sjc.current == nil {
		return results.ErrResetConvertor
	}
	sjc.currentTarget = target
	for _, err := range errors {
		if err != nil {
			sjc.current.Errors = append(sjc.current.Errors, formats.SimpleJsonError{FilePath: target.Target, ErrorMessage: err.Error()})
		}
	}
	return
}

func (sjc *CmdResultsSimpleJsonConverter) DeprecatedParseScaIssues(descriptors []string, scaResponse results.ScanResult[services.ScanResponse], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	if sjc.current == nil {
		return results.ErrResetConvertor
	}
	if results.ShouldUpdateStatus(sjc.current.Statuses.ScaStatusCode, &scaResponse.StatusCode) {
		sjc.current.Statuses.ScaStatusCode = &scaResponse.StatusCode
	}
	for i := range applicableScan {
		if results.ShouldUpdateStatus(sjc.current.Statuses.ApplicabilityStatusCode, &applicableScan[i].StatusCode) {
			sjc.current.Statuses.ApplicabilityStatusCode = &applicableScan[i].StatusCode
		}
	}
	err = sjc.parseScaVulnerabilities(sjc.currentTarget, descriptors, scaResponse.Scan, results.ScanResultsToRuns(applicableScan)...)

	// if violations {
	// 	err = sjc.parseScaViolations(target, descriptors, scaResponse.Scan, results.ScanResultsToRuns(applicableScan)...)
	// } else {
	// 	err = sjc.parseScaVulnerabilities(target, descriptors, scaResponse.Scan, results.ScanResultsToRuns(applicableScan)...)
	// }
	return
}

func (sjc *CmdResultsSimpleJsonConverter) ParseSbomLicenses(components []cyclonedx.Component, dependencies ...cyclonedx.Dependency) (err error) {
	if sjc.current == nil {
		return results.ErrResetConvertor
	}
	if len(components) == 0 {
		return
	}
	// Iterate through the components and collect licenses
	for _, component := range components {
		if component.Licenses == nil || len(*component.Licenses) == 0 {
			// No licenses found for this component, continue to the next one
			continue
		}
		compName, compVersion, compType := techutils.SplitPackageURL(component.PackageURL)
		for _, license := range *component.Licenses {
			if license.License == nil && license.License.Name == "" {
				// No license name found, continue to the next one
				continue
			}
			sjc.current.Licenses = append(sjc.current.Licenses, formats.LicenseRow{
				LicenseKey:  license.License.ID,
				LicenseName: license.License.Name,
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					ImpactedDependencyName:    compName,
					ImpactedDependencyVersion: compVersion,
					ImpactedDependencyType:    techutils.ConvertXrayPackageType(techutils.CdxPackageTypeToXrayPackageType(compType)),
					Components:                results.GetDirectDependenciesAsComponentRows(component, components, dependencies),
				},
				ImpactPaths: results.BuildImpactPath(component, components, dependencies...),
			})
		}
	}
	return
}

func (sjc *CmdResultsSimpleJsonConverter) ParseCVEs(enrichedSbom results.ScanResult[*cyclonedx.BOM], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	if sjc.current == nil {
		return results.ErrResetConvertor
	}
	if results.ShouldUpdateStatus(sjc.current.Statuses.ScaStatusCode, &enrichedSbom.StatusCode) {
		sjc.current.Statuses.ScaStatusCode = &enrichedSbom.StatusCode
	}
	for i := range applicableScan {
		if results.ShouldUpdateStatus(sjc.current.Statuses.ApplicabilityStatusCode, &applicableScan[i].StatusCode) {
			sjc.current.Statuses.ApplicabilityStatusCode = &applicableScan[i].StatusCode
		}
	}
	return results.ForEachScaBomVulnerability(sjc.currentTarget, enrichedSbom.Scan, sjc.entitledForJas, results.ScanResultsToRuns(applicableScan),
		func(vulnerability cyclonedx.Vulnerability, component cyclonedx.Component, fixedVersions *[]cyclonedx.AffectedVersions, applicability *formats.Applicability, severity severityutils.Severity) (e error) {
			dependencies := []cyclonedx.Dependency{}
			if enrichedSbom.Scan.Dependencies != nil {
				dependencies = append(dependencies, *enrichedSbom.Scan.Dependencies...)
			}
			// Convert the CycloneDX vulnerability to a simple JSON vulnerability row
			sjc.current.Vulnerabilities = append(sjc.current.Vulnerabilities, sjc.createVulnerabilityOrViolationRowFromCdx(
				vulnerability.ID,
				vulnerability.Description,
				severity,
				applicability,
				vulnerability,
				component,
				results.GetDirectDependenciesAsComponentRows(component, *enrichedSbom.Scan.Components, dependencies),
				results.BuildImpactPath(component, *enrichedSbom.Scan.Components, dependencies...),
				fixedVersions,
				// TODO: implement JfrogResearchInformation conversion
				nil,
			))
			return
		},
	)
}

func convertToViolationContext(violation violationutils.Violation) formats.ViolationContext {
	context := formats.ViolationContext{
		Watch:   violation.Watch,
		IssueId: violation.ViolationId,
	}
	for _, policy := range violation.Policies {
		context.Policies = append(context.Policies, policy.PolicyName)
		context.FailPr = context.FailPr || policy.FailPullRequest
	}
	return context
}

func (sjc *CmdResultsSimpleJsonConverter) ParseViolations(violations violationutils.Violations) (err error) {
	if sjc.current == nil {
		return results.ErrResetConvertor
	}
	// SCA Violations
	for _, cveViolation := range violations.Sca {
		violation := sjc.createVulnerabilityOrViolationRowFromCdx(
			cveViolation.Violation.ViolationId,
			cveViolation.Vulnerability.Description,
			cveViolation.Violation.Severity,
			cveViolation.ContextualAnalysis,
			cveViolation.Vulnerability,
			cveViolation.Component,
			cveViolation.DirectComponents,
			cveViolation.ImpactPaths,
			cveViolation.FixedVersions,
			cveViolation.JfrogResearchInformation,
		)
		violation.ViolationContext = convertToViolationContext(cveViolation.Violation)
		sjc.current.SecurityViolations = append(sjc.current.SecurityViolations, violation)
	}
	// License Violations
	// Secrets Violations
	for _, jasViolation := range violations.Secrets {
		violation := createSourceCodeRow(jasViolation.Rule, jasViolation.Severity, jasViolation.Result, jasViolation.Location, []*sarif.Invocation{}, sjc.pretty)
		violation.ViolationContext = convertToViolationContext(jasViolation.Violation)
		sjc.current.SecretsViolations = append(sjc.current.SecretsViolations, violation)
	}
	// IaC Violations
	for _, jasViolation := range violations.Iac {
		violation := createSourceCodeRow(jasViolation.Rule, jasViolation.Severity, jasViolation.Result, jasViolation.Location, []*sarif.Invocation{}, sjc.pretty)
		violation.ViolationContext = convertToViolationContext(jasViolation.Violation)
		sjc.current.IacsViolations = append(sjc.current.IacsViolations, violation)
	}
	// SAST Violations
	for _, jasViolation := range violations.Sast {
		violation := createSourceCodeRow(jasViolation.Rule, jasViolation.Severity, jasViolation.Result, jasViolation.Location, []*sarif.Invocation{}, sjc.pretty)
		violation.ViolationContext = convertToViolationContext(jasViolation.Violation)
		sjc.current.SastViolations = append(sjc.current.SastViolations, violation)
	}
	return nil
}

func (sjc *CmdResultsSimpleJsonConverter) createVulnerabilityOrViolationRowFromCdx(issueId, summary string, severity severityutils.Severity, contextualAnalysis *formats.Applicability, vulnerability cyclonedx.Vulnerability, component cyclonedx.Component, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow, fixedVersions *[]cyclonedx.AffectedVersions, jfrogResearch *formats.JfrogResearchInformation) formats.VulnerabilityOrViolationRow {
	applicabilityStatus := jasutils.NotScanned
	if contextualAnalysis != nil {
		applicabilityStatus = jasutils.ConvertToApplicabilityStatus(contextualAnalysis.Status)
	}
	compName, compVersion, compType := techutils.SplitPackageURL(component.PackageURL)
	return formats.VulnerabilityOrViolationRow{
		IssueId: issueId,
		Summary: summary,
		ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
			SeverityDetails:           severityutils.GetAsDetails(severity, applicabilityStatus, sjc.pretty),
			ImpactedDependencyName:    compName,
			ImpactedDependencyVersion: compVersion,
			ImpactedDependencyType:    techutils.ConvertXrayPackageType(techutils.CdxPackageTypeToXrayPackageType(compType)),
			Components:                directComponents,
		},
		ImpactPaths:              impactPaths,
		Cves:                     results.CdxVulnToCveRows(vulnerability, contextualAnalysis),
		FixedVersions:            results.CdxToFixedVersions(fixedVersions),
		Technology:               results.GetIssueTechnology(techutils.CdxPackageTypeToXrayPackageType(compType), sjc.currentTarget.Technology),
		References:               toReferences(vulnerability),
		Applicable:               applicabilityStatus.ToString(sjc.pretty),
		JfrogResearchInformation: jfrogResearch,
	}
}

func toReferences(vulnerability cyclonedx.Vulnerability) (references []string) {
	references = []string{}
	// If vulnerability has references, we convert them to a string slice.
	if vulnerability.References == nil {
		return
	}
	for _, ref := range *vulnerability.References {
		if ref.Source != nil && ref.Source.URL != "" {
			references = append(references, ref.Source.URL)
		}
	}
	return
}

func (sjc *CmdResultsSimpleJsonConverter) parseScaViolations(target results.ScanTarget, descriptors []string, scaResponse services.ScanResponse, applicabilityRuns ...*sarif.Run) (err error) {
	if sjc.current == nil {
		return results.ErrResetConvertor
	}
	secViolationsSimpleJson, licViolationsSimpleJson, opRiskViolationsSimpleJson, err := PrepareSimpleJsonViolations(target, descriptors, scaResponse, sjc.pretty, sjc.entitledForJas, applicabilityRuns...)
	if err != nil {
		return
	}
	sjc.current.SecurityViolations = append(sjc.current.SecurityViolations, secViolationsSimpleJson...)
	sjc.current.LicensesViolations = append(sjc.current.LicensesViolations, licViolationsSimpleJson...)
	sjc.current.OperationalRiskViolations = append(sjc.current.OperationalRiskViolations, opRiskViolationsSimpleJson...)
	return
}

func (sjc *CmdResultsSimpleJsonConverter) parseScaVulnerabilities(target results.ScanTarget, descriptors []string, scaResponse services.ScanResponse, applicabilityRuns ...*sarif.Run) (err error) {
	if sjc.current == nil {
		return results.ErrResetConvertor
	}
	vulSimpleJson, err := PrepareSimpleJsonVulnerabilities(target, descriptors, scaResponse, sjc.pretty, sjc.entitledForJas, applicabilityRuns...)
	if err != nil || len(vulSimpleJson) == 0 {
		return
	}
	sjc.current.Vulnerabilities = append(sjc.current.Vulnerabilities, vulSimpleJson...)
	return
}

func (sjc *CmdResultsSimpleJsonConverter) DeprecatedParseLicenses(scaResponse results.ScanResult[services.ScanResponse]) (err error) {
	if sjc.current == nil {
		return results.ErrResetConvertor
	}
	if sjc.current.Statuses.ScaStatusCode == nil || *sjc.current.Statuses.ScaStatusCode == 0 {
		sjc.current.Statuses.ScaStatusCode = &scaResponse.StatusCode
	}
	licSimpleJson, err := PrepareSimpleJsonLicenses(sjc.currentTarget, scaResponse.Scan.Licenses)
	if err != nil || len(licSimpleJson) == 0 {
		return
	}
	sjc.current.Licenses = append(sjc.current.Licenses, licSimpleJson...)
	return
}

func (sjc *CmdResultsSimpleJsonConverter) ParseSbom(_ *cyclonedx.BOM) (err error) {
	// Not supported in the simple-json
	return
}

func (sjc *CmdResultsSimpleJsonConverter) ParseSecrets(secrets ...results.ScanResult[[]*sarif.Run]) (err error) {
	if !sjc.entitledForJas {
		return
	}
	if sjc.current == nil {
		return results.ErrResetConvertor
	}
	for i := range secrets {
		if results.ShouldUpdateStatus(sjc.current.Statuses.SecretsStatusCode, &secrets[i].StatusCode) {
			sjc.current.Statuses.SecretsStatusCode = &secrets[i].StatusCode
		}
	}
	secretsSimpleJson, err := PrepareSimpleJsonJasIssues(sjc.entitledForJas, sjc.pretty, results.ScanResultsToRuns(secrets)...)
	if err != nil || len(secretsSimpleJson) == 0 {
		return
	}
	sjc.current.SecretsVulnerabilities = append(sjc.current.SecretsVulnerabilities, secretsSimpleJson...)
	return
}

func (sjc *CmdResultsSimpleJsonConverter) ParseIacs(iacs ...results.ScanResult[[]*sarif.Run]) (err error) {
	if !sjc.entitledForJas {
		return
	}
	if sjc.current == nil {
		return results.ErrResetConvertor
	}
	for i := range iacs {
		if results.ShouldUpdateStatus(sjc.current.Statuses.IacStatusCode, &iacs[i].StatusCode) {
			sjc.current.Statuses.IacStatusCode = &iacs[i].StatusCode
		}
	}
	iacSimpleJson, err := PrepareSimpleJsonJasIssues(sjc.entitledForJas, sjc.pretty, results.ScanResultsToRuns(iacs)...)
	if err != nil || len(iacSimpleJson) == 0 {
		return
	}
	sjc.current.IacsVulnerabilities = append(sjc.current.IacsVulnerabilities, iacSimpleJson...)
	return
}

func (sjc *CmdResultsSimpleJsonConverter) ParseSast(sast ...results.ScanResult[[]*sarif.Run]) (err error) {
	if !sjc.entitledForJas {
		return
	}
	if sjc.current == nil {
		return results.ErrResetConvertor
	}
	for i := range sast {
		if results.ShouldUpdateStatus(sjc.current.Statuses.SastStatusCode, &sast[i].StatusCode) {
			sjc.current.Statuses.SastStatusCode = &sast[i].StatusCode
		}
	}
	sastSimpleJson, err := PrepareSimpleJsonJasIssues(sjc.entitledForJas, sjc.pretty, results.ScanResultsToRuns(sast)...)
	if err != nil || len(sastSimpleJson) == 0 {
		return
	}
	sjc.current.SastVulnerabilities = append(sjc.current.SastVulnerabilities, sastSimpleJson...)
	return
}

func PrepareSimpleJsonViolations(target results.ScanTarget, descriptors []string, scaResponse services.ScanResponse, pretty, jasEntitled bool, applicabilityRuns ...*sarif.Run) ([]formats.VulnerabilityOrViolationRow, []formats.LicenseViolationRow, []formats.OperationalRiskViolationRow, error) {
	var securityViolationsRows []formats.VulnerabilityOrViolationRow
	var licenseViolationsRows []formats.LicenseViolationRow
	var operationalRiskViolationsRows []formats.OperationalRiskViolationRow
	_, _, err := local.ForEachScanGraphViolation(
		target,
		descriptors,
		scaResponse.Violations,
		jasEntitled,
		applicabilityRuns,
		addSimpleJsonSecurityViolation(target, &securityViolationsRows, pretty),
		addSimpleJsonLicenseViolation(&licenseViolationsRows, pretty),
		addSimpleJsonOperationalRiskViolation(&operationalRiskViolationsRows, pretty),
	)
	return securityViolationsRows, licenseViolationsRows, operationalRiskViolationsRows, err
}

func PrepareSimpleJsonVulnerabilities(target results.ScanTarget, descriptors []string, scaResponse services.ScanResponse, pretty, entitledForJas bool, applicabilityRuns ...*sarif.Run) ([]formats.VulnerabilityOrViolationRow, error) {
	var vulnerabilitiesRows []formats.VulnerabilityOrViolationRow
	err := results.ForEachScanGraphVulnerability(
		target,
		descriptors,
		scaResponse.Vulnerabilities,
		entitledForJas,
		applicabilityRuns,
		addSimpleJsonVulnerability(target, &vulnerabilitiesRows, pretty),
	)
	return vulnerabilitiesRows, err
}

func addSimpleJsonVulnerability(target results.ScanTarget, vulnerabilitiesRows *[]formats.VulnerabilityOrViolationRow, pretty bool) results.ParseScanGraphVulnerabilityFunc {
	return func(vulnerability services.Vulnerability, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesId string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error {
		impactedPackagesName, impactedPackagesVersion, impactedPackagesType := techutils.SplitComponentId(impactedPackagesId)
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
				Technology:               results.GetIssueTechnology(vulnerability.Technology, target.Technology),
				Applicable:               applicabilityStatus.ToString(pretty),
			},
		)
		return nil
	}
}

func addSimpleJsonSecurityViolation(target results.ScanTarget, securityViolationsRows *[]formats.VulnerabilityOrViolationRow, pretty bool) local.ParseScanGraphViolationFunc {
	return func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesId string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error {
		impactedPackagesName, impactedPackagesVersion, impactedPackagesType := techutils.SplitComponentId(impactedPackagesId)
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
				FixedVersions: fixedVersion,
				Cves:          cves,
				ViolationContext: formats.ViolationContext{
					Watch:    violation.WatchName,
					Policies: results.ConvertPolicesToString(violation.Policies),
					FailPr:   violation.FailPr,
				},
				IssueId:                  violation.IssueId,
				References:               violation.References,
				JfrogResearchInformation: convertJfrogResearchInformation(violation.ExtendedInformation),
				ImpactPaths:              impactPaths,
				Technology:               results.GetIssueTechnology(violation.Technology, target.Technology),
				Applicable:               applicabilityStatus.ToString(pretty),
			},
		)
		return nil
	}
}

func addSimpleJsonLicenseViolation(licenseViolationsRows *[]formats.LicenseViolationRow, pretty bool) local.ParseScanGraphViolationFunc {
	return func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesId string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error {
		impactedPackagesName, impactedPackagesVersion, impactedPackagesType := techutils.SplitComponentId(impactedPackagesId)
		*licenseViolationsRows = append(*licenseViolationsRows,
			formats.LicenseViolationRow{
				ViolationContext: formats.ViolationContext{
					Watch:    violation.WatchName,
					Policies: results.ConvertPolicesToString(violation.Policies),
					FailPr:   violation.FailPr,
				},
				LicenseRow: formats.LicenseRow{
					LicenseKey:  getLicenseKey(violation.LicenseKey, violation.IssueId),
					LicenseName: violation.LicenseName,
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:           severityutils.GetAsDetails(severity, applicabilityStatus, pretty),
						ImpactedDependencyName:    impactedPackagesName,
						ImpactedDependencyVersion: impactedPackagesVersion,
						ImpactedDependencyType:    impactedPackagesType,
						Components:                directComponents,
					},
				},
			},
		)
		return nil
	}
}

func getLicenseKey(licenseKey, issueId string) string {
	if licenseKey == "" {
		return issueId
	}
	return licenseKey
}

func addSimpleJsonOperationalRiskViolation(operationalRiskViolationsRows *[]formats.OperationalRiskViolationRow, pretty bool) local.ParseScanGraphViolationFunc {
	return func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesId string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error {
		impactedPackagesName, impactedPackagesVersion, impactedPackagesType := techutils.SplitComponentId(impactedPackagesId)
		violationOpRiskData := getOperationalRiskViolationReadableData(violation)
		operationalRiskViolationsRow := &formats.OperationalRiskViolationRow{
			ViolationContext: formats.ViolationContext{
				Watch:    violation.WatchName,
				Policies: results.ConvertPolicesToString(violation.Policies),
			},
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
		return nil
	}
}

func PrepareSimpleJsonLicenses(target results.ScanTarget, licenses []services.License) ([]formats.LicenseRow, error) {
	var licensesRows []formats.LicenseRow
	err := results.ForEachLicense(target, licenses, addSimpleJsonLicense(&licensesRows))
	return licensesRows, err
}

func addSimpleJsonLicense(licenseViolationsRows *[]formats.LicenseRow) results.ParseLicenseFunc {
	return func(license services.License, impactedPackagesId string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error {
		impactedPackagesName, impactedPackagesVersion, impactedPackagesType := techutils.SplitComponentId(impactedPackagesId)
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

func PrepareSimpleJsonJasIssues(entitledForJas, pretty bool, jasIssues ...*sarif.Run) ([]formats.SourceCodeRow, error) {
	var rows []formats.SourceCodeRow
	err := results.ForEachJasIssue(jasIssues, entitledForJas, func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) error {
		rows = append(rows, createSourceCodeRow(rule, severity, result, location, run.Invocations, pretty))
		return nil
	})
	return rows, err
}

func createSourceCodeRow(rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location, invocations []*sarif.Invocation, pretty bool) formats.SourceCodeRow {
	return formats.SourceCodeRow{
		ScannerInfo: formats.ScannerInfo{
			RuleId:                  sarifutils.GetResultRuleId(result),
			Origin:                  sarifutils.GetRuleOrigin(rule),
			Cwe:                     sarifutils.GetRuleCWE(rule),
			ScannerDescription:      sarifutils.GetRuleFullDescription(rule),
			ScannerShortDescription: sarifutils.GetRuleShortDescription(rule),
		},
		ViolationContext: formats.ViolationContext{
			Watch:    sarifutils.GetResultWatches(result),
			IssueId:  sarifutils.GetResultIssueId(result),
			Policies: sarifutils.GetResultPolicies(result),
			FailPr:   sarifutils.GetResultFailPrValue(result),
		},
		SeverityDetails: severityutils.GetAsDetails(severity, jasutils.Applicable, pretty),
		Finding:         sarifutils.GetResultMsgText(result),
		Fingerprint:     sarifutils.GetResultFingerprint(result),
		Location: formats.Location{
			File:        sarifutils.GetRelativeLocationFileName(location, invocations),
			StartLine:   sarifutils.GetLocationStartLine(location),
			StartColumn: sarifutils.GetLocationStartColumn(location),
			EndLine:     sarifutils.GetLocationEndLine(location),
			EndColumn:   sarifutils.GetLocationEndColumn(location),
			Snippet:     sarifutils.GetLocationSnippetText(location),
		},
		Applicability: results.GetJasResultApplicability(result),
		CodeFlow:      codeFlowToLocationFlow(sarifutils.GetLocationRelatedCodeFlowsFromResult(location, result), invocations, pretty),
	}
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
					Snippet:     sarifutils.GetLocationSnippetText(stackTraceEntry.Location),
				})
			}
			flowRows = append(flowRows, rowFlow)
		}
	}
	return
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

// Returns a new slice that contains only the unique issues from the input slice
// The uniqueness of the violations is determined by the GetUniqueKey function
func removeScaDuplications(issues []formats.VulnerabilityOrViolationRow, multipleRoots bool) []formats.VulnerabilityOrViolationRow {
	var uniqueIssues = make(map[string]*formats.VulnerabilityOrViolationRow)
	for i := range issues {
		packageKey := results.GetUniqueKey(issues[i].ImpactedDependencyDetails.ImpactedDependencyName, issues[i].ImpactedDependencyDetails.ImpactedDependencyVersion, issues[i].IssueId, len(issues[i].FixedVersions) > 0)
		if uniqueIssue, exist := uniqueIssues[packageKey]; exist {
			// combine attributes from the same issue
			uniqueIssue.FixedVersions = utils.UniqueIntersection(uniqueIssue.FixedVersions, issues[i].FixedVersions...)
			uniqueIssue.ImpactPaths = AppendImpactPathsIfUnique(uniqueIssue.ImpactPaths, issues[i].ImpactPaths, multipleRoots)
			uniqueIssue.ImpactedDependencyDetails.Components = AppendComponentIfUnique(uniqueIssue.ImpactedDependencyDetails.Components, issues[i].ImpactedDependencyDetails.Components)
			continue
		}
		uniqueIssues[packageKey] = &issues[i]
	}
	// convert map to slice
	result := make([]formats.VulnerabilityOrViolationRow, 0, len(uniqueIssues))
	for _, v := range uniqueIssues {
		result = append(result, *v)
	}
	return result
}

func AppendImpactPathsIfUnique(original [][]formats.ComponentRow, toAdd [][]formats.ComponentRow, multipleRoots bool) [][]formats.ComponentRow {
	if multipleRoots {
		return AppendImpactPathsIfUniqueForMultipleRoots(original, toAdd)
	}
	impactPathMap := make(map[string][]formats.ComponentRow)
	for _, path := range original {
		// The first node component id is the key and the value is the whole path
		impactPathMap[getImpactPathKey(path)] = path
	}
	for _, path := range toAdd {
		key := getImpactPathKey(path)
		if _, exists := impactPathMap[key]; !exists {
			impactPathMap[key] = path
			original = append(original, path)
		}
	}
	return original
}

func getImpactPathKey(path []formats.ComponentRow) string {
	key := getComponentKey(path[results.RootIndex])
	if len(path) == results.DirectDependencyPathLength {
		key = getComponentKey(path[results.DirectDependencyIndex])
	}
	return key
}

func getComponentKey(component formats.ComponentRow) string {
	return results.GetDependencyId(component.Name, component.Version)
}

// getImpactPathKey return a key that is used as a key to identify and deduplicate impact paths.
// If an impact path length is equal to directDependencyPathLength, then the direct dependency is the key, and it's in the directDependencyIndex place.
func AppendImpactPathsIfUniqueForMultipleRoots(original [][]formats.ComponentRow, toAdd [][]formats.ComponentRow) [][]formats.ComponentRow {
	for targetPathIndex, targetPath := range original {
		for sourcePathIndex, sourcePath := range toAdd {
			var subset []formats.ComponentRow
			if len(sourcePath) <= len(targetPath) {
				subset = isComponentRowIsSubset(targetPath, sourcePath)
				if len(subset) != 0 {
					original[targetPathIndex] = subset
				}
			} else {
				subset = isComponentRowIsSubset(sourcePath, targetPath)
				if len(subset) != 0 {
					toAdd[sourcePathIndex] = subset
				}
			}
		}
	}
	return AppendImpactPathsIfUnique(original, toAdd, false)
}

// isComponentRowIsSubset checks if targetPath is a subset of sourcePath, and returns the subset if exists
func isComponentRowIsSubset(target []formats.ComponentRow, source []formats.ComponentRow) []formats.ComponentRow {
	var subsetImpactPath []formats.ComponentRow
	impactPathNodesMap := make(map[string]bool)
	for _, node := range target {
		impactPathNodesMap[getComponentKey(node)] = true
	}

	for _, node := range source {
		if impactPathNodesMap[getComponentKey(node)] {
			subsetImpactPath = append(subsetImpactPath, node)
		}
	}

	if len(subsetImpactPath) == len(target) || len(subsetImpactPath) == len(source) {
		return subsetImpactPath
	}
	return []formats.ComponentRow{}
}

// AppendComponentIfUnique checks if the component exists in the components (not based on location)
// Removing location information for all entries as well to combine the same components from different locations
func AppendComponentIfUnique(target []formats.ComponentRow, source []formats.ComponentRow) []formats.ComponentRow {
	directComponents := make(map[string]formats.ComponentRow)
	for i := range target {
		// Remove location information
		target[i].Location = nil
		// Add to the map if not exists
		key := getComponentKey(target[i])
		if _, exists := directComponents[key]; !exists {
			directComponents[getComponentKey(target[i])] = target[i]
		}
	}
	for i := range source {
		// Remove location information
		source[i].Location = nil
		// Add to the map if not exists
		key := getComponentKey(source[i])
		if _, exists := directComponents[key]; !exists {
			directComponents[getComponentKey(source[i])] = source[i]
		}
	}
	result := make([]formats.ComponentRow, 0, len(directComponents))
	for _, v := range directComponents {
		result = append(result, v)
	}
	return result
}

func sortResults(simpleJsonResults *formats.SimpleJsonResults) {
	if simpleJsonResults == nil {
		return
	}
	// Licenses
	if len(simpleJsonResults.Licenses) > 0 {
		sort.Slice(simpleJsonResults.Licenses, func(i, j int) bool {
			return simpleJsonResults.Licenses[i].LicenseKey < simpleJsonResults.Licenses[j].LicenseKey
		})
	}
	// Sca Vulnerabilities
	if len(simpleJsonResults.Vulnerabilities) > 0 {
		sortVulnerabilityOrViolationRows(simpleJsonResults.Vulnerabilities)
	}
	// Sca Violations
	if len(simpleJsonResults.SecurityViolations) > 0 {
		sortVulnerabilityOrViolationRows(simpleJsonResults.SecurityViolations)
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
	// Jas Vulnerabilities
	if len(simpleJsonResults.SecretsVulnerabilities) > 0 {
		sortSourceCodeRow(simpleJsonResults.SecretsVulnerabilities)
	}
	if len(simpleJsonResults.IacsVulnerabilities) > 0 {
		sortSourceCodeRow(simpleJsonResults.IacsVulnerabilities)
	}
	if len(simpleJsonResults.SastVulnerabilities) > 0 {
		sortSourceCodeRow(simpleJsonResults.SastVulnerabilities)
	}
	// Jas Violations
	if len(simpleJsonResults.SecretsViolations) > 0 {
		sortSourceCodeRow(simpleJsonResults.SecretsViolations)
	}
	if len(simpleJsonResults.IacsViolations) > 0 {
		sortSourceCodeRow(simpleJsonResults.IacsViolations)
	}
	if len(simpleJsonResults.SastViolations) > 0 {
		sortSourceCodeRow(simpleJsonResults.SastViolations)
	}
}

// sortVulnerabilityOrViolationRows is sorting in the following order:
// Severity -> Applicability -> JFrog Research Score -> XRAY ID
func sortVulnerabilityOrViolationRows(rows []formats.VulnerabilityOrViolationRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].SeverityNumValue != rows[j].SeverityNumValue {
			return rows[i].SeverityNumValue > rows[j].SeverityNumValue
		}
		if rows[i].Applicable != rows[j].Applicable {
			return jasutils.ConvertApplicableToScore(rows[i].Applicable) > jasutils.ConvertApplicableToScore(rows[j].Applicable)
		}
		priorityI := getJfrogResearchPriority(rows[i])
		priorityJ := getJfrogResearchPriority(rows[j])
		if priorityI != priorityJ {
			return priorityI > priorityJ
		}
		return rows[i].IssueId > rows[j].IssueId
	})
}

// getJfrogResearchPriority returns the score of JFrog Research Severity.
// If there is no such severity will return the normal severity score.
// When vulnerability with JFrog Research to a vulnerability without we'll compare the JFrog Research Severity to the normal severity
func getJfrogResearchPriority(vulnerabilityOrViolation formats.VulnerabilityOrViolationRow) int {
	if vulnerabilityOrViolation.JfrogResearchInformation == nil {
		return vulnerabilityOrViolation.SeverityNumValue
	}
	return vulnerabilityOrViolation.JfrogResearchInformation.SeverityNumValue
}

func sortSourceCodeRow(rows []formats.SourceCodeRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].SeverityNumValue != rows[j].SeverityNumValue {
			return rows[i].SeverityNumValue > rows[j].SeverityNumValue
		}
		if rows[i].Applicability != nil && rows[j].Applicability != nil {
			return jasutils.TokenValidationOrder[rows[i].Applicability.Status] < jasutils.TokenValidationOrder[rows[j].Applicability.Status]
		}
		return rows[i].Location.File > rows[j].Location.File
	})
}
