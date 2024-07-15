package formats

import (
	"strconv"
	"strings"
)

func ConvertSecurityTableRowToScanTableRow(tableRows []vulnerabilityTableRow) (scanTableRows []vulnerabilityScanTableRow) {
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

func ConvertToVulnerabilityTableRow(rows []VulnerabilityOrViolationRow) (tableRows []vulnerabilityTableRow) {
	for i := range rows {
		tableRows = append(tableRows, vulnerabilityTableRow{
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
		})
	}
	return
}

// func ConvertToVulnerabilityScanTableRow(rows []VulnerabilityOrViolationRow) (tableRows []vulnerabilityScanTableRow) {
// 	for i := range rows {
// 		tableRows = append(tableRows, vulnerabilityScanTableRow{
// 			severity:               rows[i].Severity,
// 			severityNumValue:       rows[i].SeverityNumValue,
// 			applicable:             rows[i].Applicable,
// 			impactedPackageName:    rows[i].ImpactedDependencyName,
// 			impactedPackageVersion: rows[i].ImpactedDependencyVersion,
// 			ImpactedPackageType:    rows[i].ImpactedDependencyType,
// 			fixedVersions:          strings.Join(rows[i].FixedVersions, "\n"),
// 			directPackages:         convertToComponentScanTableRow(rows[i].Components),
// 			cves:                   convertToCveTableRow(rows[i].Cves),
// 			issueId:                rows[i].IssueId,
// 		})
// 	}
// 	return
// }

func ConvertToLicenseViolationTableRow(rows []LicenseRow) (tableRows []licenseViolationTableRow) {
	for i := range rows {
		tableRows = append(tableRows, licenseViolationTableRow{
			licenseKey:                rows[i].LicenseKey,
			severity:                  rows[i].Severity,
			severityNumValue:          rows[i].SeverityNumValue,
			impactedDependencyName:    rows[i].ImpactedDependencyName,
			impactedDependencyVersion: rows[i].ImpactedDependencyVersion,
			impactedDependencyType:    rows[i].ImpactedDependencyType,
			directDependencies:        convertToComponentTableRow(rows[i].Components),
		})
	}
	return
}

// func ConvertToLicenseViolationScanTableRow(rows []LicenseRow) (tableRows []licenseViolationScanTableRow) {
// 	for i := range rows {
// 		tableRows = append(tableRows, licenseViolationScanTableRow{
// 			licenseKey:             rows[i].LicenseKey,
// 			severity:               rows[i].Severity,
// 			severityNumValue:       rows[i].SeverityNumValue,
// 			impactedPackageName:    rows[i].ImpactedDependencyName,
// 			impactedPackageVersion: rows[i].ImpactedDependencyVersion,
// 			impactedDependencyType: rows[i].ImpactedDependencyType,
// 			directDependencies:     convertToComponentScanTableRow(rows[i].Components),
// 		})
// 	}
// 	return
// }

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

// func ConvertToLicenseScanTableRow(rows []LicenseRow) (tableRows []licenseScanTableRow) {
// 	for i := range rows {
// 		tableRows = append(tableRows, licenseScanTableRow{
// 			licenseKey:             rows[i].LicenseKey,
// 			impactedPackageName:    rows[i].ImpactedDependencyName,
// 			impactedPackageVersion: rows[i].ImpactedDependencyVersion,
// 			impactedDependencyType: rows[i].ImpactedDependencyType,
// 			directDependencies:     convertToComponentScanTableRow(rows[i].Components),
// 		})
// 	}
// 	return
// }

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

// func ConvertToOperationalRiskViolationScanTableRow(rows []OperationalRiskViolationRow) (tableRows []operationalRiskViolationScanTableRow) {
// 	for i := range rows {
// 		tableRows = append(tableRows, operationalRiskViolationScanTableRow{
// 			Severity:               rows[i].Severity,
// 			severityNumValue:       rows[i].SeverityNumValue,
// 			impactedPackageName:    rows[i].ImpactedDependencyName,
// 			impactedPackageVersion: rows[i].ImpactedDependencyVersion,
// 			impactedDependencyType: rows[i].ImpactedDependencyType,
// 			directDependencies:     convertToComponentScanTableRow(rows[i].Components),
// 			isEol:                  rows[i].IsEol,
// 			cadence:                rows[i].Cadence,
// 			commits:                rows[i].Commits,
// 			committers:             rows[i].Committers,
// 			newerVersions:          rows[i].NewerVersions,
// 			latestVersion:          rows[i].LatestVersion,
// 			riskReason:             rows[i].RiskReason,
// 			eolMessage:             rows[i].EolMessage,
// 		})
// 	}
// 	return
// }

func ConvertToSecretsTableRow(rows []SourceCodeRow) (tableRows []secretsTableRow) {
	for i := range rows {
		tableRows = append(tableRows, secretsTableRow{
			severity:   rows[i].Severity,
			file:       rows[i].File,
			lineColumn: strconv.Itoa(rows[i].StartLine) + ":" + strconv.Itoa(rows[i].StartColumn),
			secret:     rows[i].Snippet,
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

// func convertToComponentScanTableRow(rows []ComponentRow) (tableRows []directPackagesTableRow) {
// 	for i := range rows {
// 		tableRows = append(tableRows, directPackagesTableRow{
// 			name:    rows[i].Name,
// 			version: rows[i].Version,
// 		})
// 	}
// 	return
// }

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
