package simplejsonformat

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/exp/slices"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/vulnerability"
)

type CmdResultsSimpleJsonConverter struct {
	// General conversion parameters

	// Current stream parse cache information
	current *formats.SimpleJsonResults
	currentScanTarget string
	// General information on the current command results
	entitledForJas bool
	multipleRoots bool
}

func NewCmdResultsSimpleJsonConverter() *CmdResultsSimpleJsonConverter {
	return &CmdResultsSimpleJsonConverter{}
}

func (sjc *CmdResultsSimpleJsonConverter) Get() formats.SimpleJsonResults {
	if sjc.current == nil {
		return formats.SimpleJsonResults{}
	}
	return *sjc.current
}

func (sjc *CmdResultsSimpleJsonConverter) Reset(multiScanId, _ string, entitledForJas bool) error {
	sjc.current = &formats.SimpleJsonResults{MultiScanId: multiScanId}
	sjc.entitledForJas = entitledForJas
	return nil
}

func (sjc *CmdResultsSimpleJsonConverter) ParseNewScanResultsMetadata(target string, errors error) error {
	if sjc.current == nil {
		return fmt.Errorf("Reset must be called before parsing new scan results metadata")
	}
	sjc.currentScanTarget = target
	if errors != nil {
		sjc.current.Errors = append(sjc.current.Errors, formats.SimpleJsonError{FilePath: target, ErrorMessage: errors.Error()})
	}
	return nil
}

func (sjc *CmdResultsSimpleJsonConverter) ParseViolations(target string, tech techutils.Technology, violations []services.Violation, applicabilityRuns ...*sarif.Run) error {
	secViolationsJsonTable, licViolationsJsonTable, opRiskViolationsJsonTable, err := PrepareSimpleJsonViolations(violations, sjc.entitledForJas, sjc.multipleRoots, false, applicabilityRuns...)
	if err != nil {
		return err
	}
	sjc.current.SecurityViolations = append(sjc.current.SecurityViolations, secViolationsJsonTable...)
	sjc.current.LicensesViolations = append(sjc.current.LicensesViolations, licViolationsJsonTable...)
	sjc.current.OperationalRiskViolations = append(sjc.current.OperationalRiskViolations, opRiskViolationsJsonTable...)
	return nil
}

func (sjc *CmdResultsSimpleJsonConverter) ParseVulnerabilities(target string, tech techutils.Technology, vulnerabilities []services.Vulnerability, applicabilityRuns ...*sarif.Run) error {
	vulSimpleJson, err := PrepareSimpleJsonVulnerabilities(vulnerabilities, sjc.entitledForJas, sjc.multipleRoots, false, applicabilityRuns...)
	if err != nil {
		return err
	}
	sjc.current.Vulnerabilities = append(sjc.current.Vulnerabilities, vulSimpleJson...)
	return nil
}

func (sjc *CmdResultsSimpleJsonConverter) ParseLicenses(target string, tech techutils.Technology, licenses []services.License) error {
	return nil
}

func (sjc *CmdResultsSimpleJsonConverter) ParseSecrets(target string, secrets ...*sarif.Run) error {
	return nil
}

func (sjc *CmdResultsSimpleJsonConverter) ParseIacs(target string, iacs ...*sarif.Run) error {
	return nil
}

func (sjc *CmdResultsSimpleJsonConverter) ParseSast(target string, sast ...*sarif.Run) error {
	return nil
}

func PrepareSimpleJsonViolations(violations []services.Violation, jasEntitled, multipleRoots, isTable bool, applicabilityRuns ...*sarif.Run) ([]formats.VulnerabilityOrViolationRow, []formats.LicenseRow, []formats.OperationalRiskViolationRow, error) {
	var securityViolationsRows []formats.VulnerabilityOrViolationRow
	var licenseViolationsRows []formats.LicenseRow
	var operationalRiskViolationsRows []formats.OperationalRiskViolationRow

	for _, violation := range violations {
		impactedPackagesNames, impactedPackagesVersions, impactedPackagesTypes, fixedVersions, components, impactPaths, err := results.SplitComponents(violation.Components)
		if err != nil {
			return nil, nil, nil, err
		}
		cves := convertCves(violation.Cves)
		applicabilityStatus := jasutils.ApplicabilityUndetermined
		if jasEntitled && violation.ViolationType == formats.ViolationTypeSecurity.String() {
			for i := range cves {
				cves[i].Applicability = results.GetCveApplicabilityField(cves[i].Id, applicabilityRuns, violation.Components)
			}
			applicabilityStatus = results.GetApplicableCveStatus(jasEntitled, applicabilityRuns, cves)
		}
		severityInfo := utils.GetSeverityDetails(utils.ParseToSeverity(violation.Severity), applicabilityStatus)
		severityDetails := formats.SeverityDetails{Severity: severityInfo.printableTitle(isTable), SeverityNumValue: severityInfo.Priority}

		switch violation.ViolationType {
		case formats.ViolationTypeSecurity.String():
			jfrogResearchInfo := convertJfrogResearchInformation(violation.ExtendedInformation)
			for compIndex := 0; compIndex < len(impactedPackagesNames); compIndex++ {
				securityViolationsRows = append(securityViolationsRows,
					formats.VulnerabilityOrViolationRow{
						Summary: violation.Summary,
						ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
							SeverityDetails:           severityDetails,
							ImpactedDependencyName:    impactedPackagesNames[compIndex],
							ImpactedDependencyVersion: impactedPackagesVersions[compIndex],
							ImpactedDependencyType:    impactedPackagesTypes[compIndex],
							Components:                components[compIndex],
						},
						FixedVersions:            fixedVersions[compIndex],
						Cves:                     cves,
						IssueId:                  violation.IssueId,
						References:               violation.References,
						JfrogResearchInformation: jfrogResearchInfo,
						ImpactPaths:              impactPaths[compIndex],
						Technology:               techutils.Technology(violation.Technology),
						Applicable:               printApplicabilityCveValue(applicabilityStatus, isTable),
					},
				)
			}
		case formats.ViolationTypeLicense.String():
			for compIndex := 0; compIndex < len(impactedPackagesNames); compIndex++ {
				licenseViolationsRows = append(licenseViolationsRows,
					formats.LicenseRow{
						LicenseKey: violation.LicenseKey,
						ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
							SeverityDetails:           severityDetails,
							ImpactedDependencyName:    impactedPackagesNames[compIndex],
							ImpactedDependencyVersion: impactedPackagesVersions[compIndex],
							ImpactedDependencyType:    impactedPackagesTypes[compIndex],
							Components:                components[compIndex],
						},
					},
				)
			}
		case formats.ViolationTypeOperationalRisk.String():
			violationOpRiskData := getOperationalRiskViolationReadableData(violation)
			for compIndex := 0; compIndex < len(impactedPackagesNames); compIndex++ {
				operationalRiskViolationsRow := &formats.OperationalRiskViolationRow{
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:           severityDetails,
						ImpactedDependencyName:    impactedPackagesNames[compIndex],
						ImpactedDependencyVersion: impactedPackagesVersions[compIndex],
						ImpactedDependencyType:    impactedPackagesTypes[compIndex],
						Components:                components[compIndex],
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
				operationalRiskViolationsRows = append(operationalRiskViolationsRows, *operationalRiskViolationsRow)
			}
		default:
			// Unsupported type, ignore
		}
	}

	// Sort the rows by severity and whether the row contains fixed versions
	sortVulnerabilityOrViolationRows(securityViolationsRows)
	sort.Slice(licenseViolationsRows, func(i, j int) bool {
		return licenseViolationsRows[i].SeverityNumValue > licenseViolationsRows[j].SeverityNumValue
	})
	sort.Slice(operationalRiskViolationsRows, func(i, j int) bool {
		return operationalRiskViolationsRows[i].SeverityNumValue > operationalRiskViolationsRows[j].SeverityNumValue
	})

	return securityViolationsRows, licenseViolationsRows, operationalRiskViolationsRows, nil
}

func sortVulnerabilityOrViolationRows(rows []formats.VulnerabilityOrViolationRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].SeverityNumValue != rows[j].SeverityNumValue {
			return rows[i].SeverityNumValue > rows[j].SeverityNumValue
		}
		return len(rows[i].FixedVersions) > 0 && len(rows[j].FixedVersions) > 0
	})
}

func convertCves(cves []services.Cve) []formats.CveRow {
	var cveRows []formats.CveRow
	for _, cveObj := range cves {
		cveRows = append(cveRows, formats.CveRow{Id: cveObj.Id, CvssV2: cveObj.CvssV2Score, CvssV3: cveObj.CvssV3Score})
	}
	return cveRows
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

func PrepareSimpleJsonVulnerabilities(vulnerabilities []services.Vulnerability, entitledForJas, multipleRoots, isTable bool, applicabilityRuns ...*sarif.Run) ([]formats.VulnerabilityOrViolationRow, error) {
	return nil, nil
}






// Prepare vulnerabilities for all non-table formats (without style or emoji)
func PrepareVulnerabilities(vulnerabilities []services.Vulnerability, cmdResults *results.ScanCommandResults, multipleRoots, simplifiedOutput bool) ([]formats.VulnerabilityOrViolationRow, error) {
	return prepareVulnerabilities(vulnerabilities, cmdResults, multipleRoots, false, simplifiedOutput)
}

func prepareVulnerabilities(vulnerabilities []services.Vulnerability, cmdResults *results.ScanCommandResults, multipleRoots, isTable, simplifiedOutput bool) ([]formats.VulnerabilityOrViolationRow, error) {
	if simplifiedOutput {
		vulnerabilities = simplifyVulnerabilities(vulnerabilities, multipleRoots)
	}
	var vulnerabilitiesRows []formats.VulnerabilityOrViolationRow
	for _, vulnerability := range vulnerabilities {
		impactedPackagesNames, impactedPackagesVersions, impactedPackagesTypes, fixedVersions, components, impactPaths, err := splitComponents(vulnerability.Components)
		if err != nil {
			return nil, err
		}
		cves := convertCves(vulnerability.Cves)
		if cmdResults.ExtendedScanResults.EntitledForJas {
			for i := range cves {
				cves[i].Applicability = GetCveApplicabilityField(cves[i].Id, cmdResults.ExtendedScanResults.ApplicabilityScanResults, vulnerability.Components)
			}
		}
		applicabilityStatus := getApplicableCveStatus(cmdResults.ExtendedScanResults.EntitledForJas, cmdResults.ExtendedScanResults.ApplicabilityScanResults, cves)
		currSeverity := GetSeverity(vulnerability.Severity, applicabilityStatus)
		jfrogResearchInfo := convertJfrogResearchInformation(vulnerability.ExtendedInformation)
		for compIndex := 0; compIndex < len(impactedPackagesNames); compIndex++ {
			vulnerabilitiesRows = append(vulnerabilitiesRows,
				formats.VulnerabilityOrViolationRow{
					Summary: vulnerability.Summary,
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:           formats.SeverityDetails{Severity: currSeverity.printableTitle(isTable), SeverityNumValue: currSeverity.NumValue()},
						ImpactedDependencyName:    impactedPackagesNames[compIndex],
						ImpactedDependencyVersion: impactedPackagesVersions[compIndex],
						ImpactedDependencyType:    impactedPackagesTypes[compIndex],
						Components:                components[compIndex],
					},
					FixedVersions:            fixedVersions[compIndex],
					Cves:                     cves,
					IssueId:                  vulnerability.IssueId,
					References:               vulnerability.References,
					JfrogResearchInformation: jfrogResearchInfo,
					ImpactPaths:              impactPaths[compIndex],
					Technology:               techutils.Technology(vulnerability.Technology),
					Applicable:               printApplicabilityCveValue(applicabilityStatus, isTable),
				},
			)
		}
	}

	sortVulnerabilityOrViolationRows(vulnerabilitiesRows)
	return vulnerabilitiesRows, nil
}

func (rw *ResultsWriter) convertScanToSimpleJson() (formats.SimpleJsonResults, error) {
	jsonTable, err := ConvertXrayScanToSimpleJson(rw.commandResults, rw.isMultipleRoots, rw.includeLicenses, false, nil)
	if err != nil {
		return formats.SimpleJsonResults{}, err
	}
	
	if len(rw.commandResults.GetJasScansResults(jasutils.Secrets)) > 0 {
		jsonTable.Secrets = conversion.PrepareSecrets(rw.commandResults.GetJasScansResults(jasutils.Secrets))
	}
	if len(rw.commandResults.GetJasScansResults(jasutils.IaC)) > 0 {
		jsonTable.Iacs = conversion.PrepareIacs(rw.commandResults.GetJasScansResults(jasutils.IaC))
	}
	if len(rw.commandResults.GetJasScansResults(jasutils.Sast)) > 0 {
		jsonTable.Sast = conversion.PrepareSast(rw.commandResults.GetJasScansResults(jasutils.Sast))
	}
	jsonTable.Errors = rw.simpleJsonError

	return jsonTable, nil
}


func ConvertXrayScanToSimpleJson(results *results.ScanCommandResults, isMultipleRoots, includeLicenses, simplifiedOutput bool, allowedLicenses []string) (formats.SimpleJsonResults, error) {
	violations, vulnerabilities, licenses := SplitScaScanResults(results)// SplitScanResults(results.ScaResults)
	jsonTable := formats.SimpleJsonResults{}
	if len(vulnerabilities) > 0 {
		vulJsonTable, err := PrepareVulnerabilities(vulnerabilities, results, isMultipleRoots, simplifiedOutput)
		if err != nil {
			return formats.SimpleJsonResults{}, err
		}
		jsonTable.Vulnerabilities = vulJsonTable
	}
	if includeLicenses || len(allowedLicenses) > 0 {
		licJsonTable, err := PrepareLicenses(licenses)
		if err != nil {
			return formats.SimpleJsonResults{}, err
		}
		if includeLicenses {
			jsonTable.Licenses = licJsonTable
		}
		jsonTable.LicensesViolations = GetViolatedLicenses(allowedLicenses, licJsonTable)
	}
	if len(violations) > 0 {
		secViolationsJsonTable, licViolationsJsonTable, opRiskViolationsJsonTable, err := PrepareViolations(violations, results, isMultipleRoots, simplifiedOutput)
		if err != nil {
			return formats.SimpleJsonResults{}, err
		}
		jsonTable.SecurityViolations = secViolationsJsonTable
		jsonTable.LicensesViolations = licViolationsJsonTable
		jsonTable.OperationalRiskViolations = opRiskViolationsJsonTable
	}
	jsonTable.MultiScanId = results.MultiScanId
	return jsonTable, nil
}

func GetViolatedLicenses(allowedLicenses []string, licenses []formats.LicenseRow) (violatedLicenses []formats.LicenseRow) {
	if len(allowedLicenses) == 0 {
		return
	}
	for _, license := range licenses {
		if !slices.Contains(allowedLicenses, license.LicenseKey) {
			violatedLicenses = append(violatedLicenses, license)
		}
	}
	return
}

// Prepare violations for all non-table formats (without style or emoji)
func PrepareViolations(violations []services.Violation, cmdResults *results.ScanCommandResults, multipleRoots, simplifiedOutput bool) ([]formats.VulnerabilityOrViolationRow, []formats.LicenseRow, []formats.OperationalRiskViolationRow, error) {
	return prepareViolations(violations, cmdResults, multipleRoots, false, simplifiedOutput)
}

func prepareViolations(violations []services.Violation, cmdResults *results.ScanCommandResults, multipleRoots, isTable, simplifiedOutput bool) ([]formats.VulnerabilityOrViolationRow, []formats.LicenseRow, []formats.OperationalRiskViolationRow, error) {
	if simplifiedOutput {
		violations = simplifyViolations(violations, multipleRoots)
	}
	var securityViolationsRows []formats.VulnerabilityOrViolationRow
	var licenseViolationsRows []formats.LicenseRow
	var operationalRiskViolationsRows []formats.OperationalRiskViolationRow
	for _, violation := range violations {
		impactedPackagesNames, impactedPackagesVersions, impactedPackagesTypes, fixedVersions, components, impactPaths, err := splitComponents(violation.Components)
		if err != nil {
			return nil, nil, nil, err
		}
		switch violation.ViolationType {
		case formats.ViolationTypeSecurity.String():
			cves := convertCves(violation.Cves)
			if cmdResults.ExtendedScanResults.EntitledForJas {
				for i := range cves {
					cves[i].Applicability = GetCveApplicabilityField(cves[i].Id, cmdResults.ExtendedScanResults.ApplicabilityScanResults, violation.Components)
				}
			}
			applicabilityStatus := getApplicableCveStatus(cmdResults.ExtendedScanResults.EntitledForJas, cmdResults.ExtendedScanResults.ApplicabilityScanResults, cves)
			currSeverity := GetSeverity(violation.Severity, applicabilityStatus)
			jfrogResearchInfo := convertJfrogResearchInformation(violation.ExtendedInformation)
			for compIndex := 0; compIndex < len(impactedPackagesNames); compIndex++ {
				securityViolationsRows = append(securityViolationsRows,
					formats.VulnerabilityOrViolationRow{
						Summary: violation.Summary,
						ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
							SeverityDetails:           formats.SeverityDetails{Severity: currSeverity.printableTitle(isTable), SeverityNumValue: currSeverity.NumValue()},
							ImpactedDependencyName:    impactedPackagesNames[compIndex],
							ImpactedDependencyVersion: impactedPackagesVersions[compIndex],
							ImpactedDependencyType:    impactedPackagesTypes[compIndex],
							Components:                components[compIndex],
						},
						FixedVersions:            fixedVersions[compIndex],
						Cves:                     cves,
						IssueId:                  violation.IssueId,
						References:               violation.References,
						JfrogResearchInformation: jfrogResearchInfo,
						ImpactPaths:              impactPaths[compIndex],
						Technology:               techutils.Technology(violation.Technology),
						Applicable:               printApplicabilityCveValue(applicabilityStatus, isTable),
					},
				)
			}
		case formats.ViolationTypeLicense.String():
			currSeverity := GetSeverity(violation.Severity, jasutils.ApplicabilityUndetermined)
			for compIndex := 0; compIndex < len(impactedPackagesNames); compIndex++ {
				licenseViolationsRows = append(licenseViolationsRows,
					formats.LicenseRow{
						LicenseKey: violation.LicenseKey,
						ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
							SeverityDetails:           formats.SeverityDetails{Severity: currSeverity.printableTitle(isTable), SeverityNumValue: currSeverity.NumValue()},
							ImpactedDependencyName:    impactedPackagesNames[compIndex],
							ImpactedDependencyVersion: impactedPackagesVersions[compIndex],
							ImpactedDependencyType:    impactedPackagesTypes[compIndex],
							Components:                components[compIndex],
						},
					},
				)
			}
		case formats.ViolationTypeOperationalRisk.String():
			currSeverity := GetSeverity(violation.Severity, jasutils.ApplicabilityUndetermined)
			violationOpRiskData := getOperationalRiskViolationReadableData(violation)
			for compIndex := 0; compIndex < len(impactedPackagesNames); compIndex++ {
				operationalRiskViolationsRow := &formats.OperationalRiskViolationRow{
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:           formats.SeverityDetails{Severity: currSeverity.printableTitle(isTable), SeverityNumValue: currSeverity.NumValue()},
						ImpactedDependencyName:    impactedPackagesNames[compIndex],
						ImpactedDependencyVersion: impactedPackagesVersions[compIndex],
						ImpactedDependencyType:    impactedPackagesTypes[compIndex],
						Components:                components[compIndex],
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
				operationalRiskViolationsRows = append(operationalRiskViolationsRows, *operationalRiskViolationsRow)
			}
		default:
			// Unsupported type, ignore
		}
	}

	// Sort the rows by severity and whether the row contains fixed versions
	sortVulnerabilityOrViolationRows(securityViolationsRows)
	sort.Slice(licenseViolationsRows, func(i, j int) bool {
		return licenseViolationsRows[i].SeverityNumValue > licenseViolationsRows[j].SeverityNumValue
	})
	sort.Slice(operationalRiskViolationsRows, func(i, j int) bool {
		return operationalRiskViolationsRows[i].SeverityNumValue > operationalRiskViolationsRows[j].SeverityNumValue
	})

	return securityViolationsRows, licenseViolationsRows, operationalRiskViolationsRows, nil
}