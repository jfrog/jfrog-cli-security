package formats

import (
	"strconv"
	"strings"

	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
)

// For binary scans
func ConvertSecurityTableRowToScanTableRow(tableRows []scaVulnerabilityOrViolationTableRow) (scanTableRows []vulnerabilityScanTableRow) {
	for i := range tableRows {
		scanTableRows = append(scanTableRows, vulnerabilityScanTableRow{
			severity:               tableRows[i].severity,
			severityNumValue:       tableRows[i].severityNumValue,
			applicable:             tableRows[i].applicable,
			impactedPackageName:    tableRows[i].impactedDependencyName,
			impactedPackageVersion: tableRows[i].impactedDependencyVersion,
			ImpactedPackageType:    tableRows[i].impactedDependencyType,
			fixedVersions:          tableRows[i].fixedVersions,
			directPackages:         convertToComponentScanTableRow(tableRows[i].directDependencies),
			cves:                   tableRows[i].cves,
			issueId:                tableRows[i].issueId,
		})
	}
	return
}

// For binary scans
func ConvertLicenseViolationTableRowToScanTableRow(tableRows []licenseViolationTableRow) (scanTableRows []licenseViolationScanTableRow) {
	for i := range tableRows {
		scanTableRows = append(scanTableRows, licenseViolationScanTableRow{
			licenseKey:             tableRows[i].licenseKey,
			severity:               tableRows[i].severity,
			severityNumValue:       tableRows[i].severityNumValue,
			impactedPackageName:    tableRows[i].impactedDependencyName,
			impactedPackageVersion: tableRows[i].impactedDependencyVersion,
			impactedDependencyType: tableRows[i].impactedDependencyType,
			directDependencies:     convertToComponentScanTableRow(tableRows[i].directDependencies),
		})
	}
	return
}

func ConvertOperationalRiskTableRowToScanTableRow(tableRows []operationalRiskViolationTableRow) (scanTableRows []operationalRiskViolationScanTableRow) {
	for i := range tableRows {
		scanTableRows = append(scanTableRows, operationalRiskViolationScanTableRow{
			Severity:               tableRows[i].Severity,
			severityNumValue:       tableRows[i].severityNumValue,
			impactedPackageName:    tableRows[i].impactedDependencyName,
			impactedPackageVersion: tableRows[i].impactedDependencyVersion,
			impactedDependencyType: tableRows[i].impactedDependencyType,
			directDependencies:     convertToComponentScanTableRow(tableRows[i].directDependencies),
			isEol:                  tableRows[i].isEol,
			cadence:                tableRows[i].cadence,
			commits:                tableRows[i].Commits,
			committers:             tableRows[i].committers,
			newerVersions:          tableRows[i].newerVersions,
			latestVersion:          tableRows[i].latestVersion,
			riskReason:             tableRows[i].riskReason,
			eolMessage:             tableRows[i].eolMessage,
		})
	}
	return
}

func ConvertLicenseTableRowToScanTableRow(tableRows []licenseTableRow) (scanTableRows []licenseScanTableRow) {
	for i := range tableRows {
		scanTableRows = append(scanTableRows, licenseScanTableRow{
			licenseKey:             tableRows[i].licenseKey,
			directDependencies:     convertToComponentScanTableRow(tableRows[i].directDependencies),
			impactedPackageName:    tableRows[i].impactedDependencyName,
			impactedPackageVersion: tableRows[i].impactedDependencyVersion,
			impactedDependencyType: tableRows[i].impactedDependencyType,
		})
	}
	return
}

func convertToComponentScanTableRow(rows []directDependenciesTableRow) (tableRows []directPackagesTableRow) {
	for i := range rows {
		tableRows = append(tableRows, directPackagesTableRow{
			name:    rows[i].name,
			version: rows[i].version,
		})
	}
	return
}

func ConvertToScaVulnerabilityOrViolationTableRow(rows []VulnerabilityOrViolationRow) (tableRows []scaVulnerabilityOrViolationTableRow) {
	for i := range rows {
		tableRows = append(tableRows, scaVulnerabilityOrViolationTableRow{
			severity:                  rows[i].Severity,
			severityNumValue:          rows[i].SeverityNumValue,
			applicable:                rows[i].Applicable,
			impactedDependencyName:    rows[i].ImpactedDependencyName,
			impactedDependencyVersion: rows[i].ImpactedDependencyVersion,
			impactedDependencyType:    rows[i].ImpactedDependencyType,
			fixedVersions:             strings.Join(rows[i].FixedVersions, "\n"),
			directDependencies:        convertToComponentTableRow(rows[i].Components),
			cves:                      convertToCveTableRow(rows[i].Cves),
			issueId:                   rows[i].IssueId,
			watch:                     rows[i].Watch,
		})
	}
	return
}

func ConvertToLicenseViolationTableRow(rows []LicenseViolationRow) (tableRows []licenseViolationTableRow) {
	for i := range rows {
		tableRows = append(tableRows, licenseViolationTableRow{
			licenseKey:                rows[i].LicenseKey,
			severity:                  rows[i].Severity,
			severityNumValue:          rows[i].SeverityNumValue,
			impactedDependencyName:    rows[i].ImpactedDependencyName,
			impactedDependencyVersion: rows[i].ImpactedDependencyVersion,
			impactedDependencyType:    rows[i].ImpactedDependencyType,
			directDependencies:        convertToComponentTableRow(rows[i].Components),
			watch:                     rows[i].Watch,
		})
	}
	return
}

func ConvertToLicenseTableRow(rows []LicenseRow) (tableRows []licenseTableRow) {
	for i := range rows {
		tableRows = append(tableRows, licenseTableRow{
			licenseKey:                rows[i].LicenseKey,
			impactedDependencyName:    rows[i].ImpactedDependencyName,
			impactedDependencyVersion: rows[i].ImpactedDependencyVersion,
			impactedDependencyType:    rows[i].ImpactedDependencyType,
			directDependencies:        convertToComponentTableRow(rows[i].Components),
		})
	}
	return
}

func ConvertToOperationalRiskViolationTableRow(rows []OperationalRiskViolationRow) (tableRows []operationalRiskViolationTableRow) {
	for i := range rows {
		tableRows = append(tableRows, operationalRiskViolationTableRow{
			Severity:                  rows[i].Severity,
			severityNumValue:          rows[i].SeverityNumValue,
			impactedDependencyName:    rows[i].ImpactedDependencyName,
			impactedDependencyVersion: rows[i].ImpactedDependencyVersion,
			impactedDependencyType:    rows[i].ImpactedDependencyType,
			directDependencies:        convertToComponentTableRow(rows[i].Components),
			isEol:                     rows[i].IsEol,
			cadence:                   rows[i].Cadence,
			Commits:                   rows[i].Commits,
			committers:                rows[i].Committers,
			newerVersions:             rows[i].NewerVersions,
			latestVersion:             rows[i].LatestVersion,
			riskReason:                rows[i].RiskReason,
			eolMessage:                rows[i].EolMessage,
		})
	}
	return
}

func ConvertToSecretsTableRow(rows []SourceCodeRow) (tableRows []secretsTableRow) {
	for i := range rows {
		var status string
		var info string
		if rows[i].Applicability != nil {
			status = rows[i].Applicability.Status
			info = rows[i].Applicability.ScannerDescription
		}
		tableRows = append(tableRows, secretsTableRow{
			severity:        rows[i].Severity,
			file:            rows[i].File,
			lineColumn:      strconv.Itoa(rows[i].StartLine) + ":" + strconv.Itoa(rows[i].StartColumn),
			secret:          rows[i].Snippet,
			tokenValidation: jasutils.TokenValidationStatus(status).ToString(),
			tokenInfo:       info,
			watch:           rows[i].Watch,
		})

	}
	return
}

func ConvertToMaliciousTableRow(rows []SourceCodeRow) (tableRows []maliciousTableRow) {
	for i := range rows {
		tableRows = append(tableRows, maliciousTableRow{
			severity:      rows[i].Severity,
			file:          rows[i].File,
			lineColumn:    strconv.Itoa(rows[i].StartLine) + ":" + strconv.Itoa(rows[i].StartColumn),
			evidence:      rows[i].Snippet,
			maliciousType: rows[i].Finding,
		})

	}
	return
}

func ConvertToIacOrSastTableRow(rows []SourceCodeRow) (tableRows []iacOrSastTableRow) {
	for i := range rows {
		tableRows = append(tableRows, iacOrSastTableRow{
			severity:   rows[i].Severity,
			file:       rows[i].File,
			lineColumn: strconv.Itoa(rows[i].StartLine) + ":" + strconv.Itoa(rows[i].StartColumn),
			finding:    rows[i].Finding,
			watch:      rows[i].Watch,
		})
	}
	return
}

func convertToComponentTableRow(rows []ComponentRow) (tableRows []directDependenciesTableRow) {
	for i := range rows {
		tableRows = append(tableRows, directDependenciesTableRow{
			name:    rows[i].Name,
			version: rows[i].Version,
		})
	}
	return
}

func convertToCveTableRow(rows []CveRow) (tableRows []cveTableRow) {
	for i := range rows {
		tableRows = append(tableRows, cveTableRow{
			id:     rows[i].Id,
			cvssV2: rows[i].CvssV2,
			cvssV3: rows[i].CvssV3,
		})
	}
	return
}
