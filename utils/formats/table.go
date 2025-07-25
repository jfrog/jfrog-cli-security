package formats

// Structs in this file are used for the 'table' format output of scan/audit commands.
// Annotations are as described in the tableutils.PrintTable description.
// Use the conversion methods in this package to convert from the API structs to the table structs.

type ResultsTables struct {
	// Licenses
	LicensesTable []licenseTableRow
	// SBOM (Software Bill of Materials)
	SbomTable []SbomTableRow
	// Sca tables
	SecurityVulnerabilitiesTable   []scaVulnerabilityOrViolationTableRow
	SecurityViolationsTable        []scaVulnerabilityOrViolationTableRow
	LicenseViolationsTable         []licenseViolationTableRow
	OperationalRiskViolationsTable []operationalRiskViolationTableRow
	// Iac tables
	IacVulnerabilitiesTable []iacOrSastTableRow
	IacViolationsTable      []iacOrSastTableRow
	// Sast tables
	SastVulnerabilitiesTable []iacOrSastTableRow
	SastViolationsTable      []iacOrSastTableRow
	// Secrets
	SecretsVulnerabilitiesTable []secretsTableRow
	SecretsViolationsTable      []secretsTableRow
}

// Used for vulnerabilities and security violations
type scaVulnerabilityOrViolationTableRow struct {
	cves       []cveTableRow `embed-table:"true"`
	severity   string        `col-name:"Severity"`
	applicable string        `col-name:"Contextual\nAnalysis" omitempty:"true"`
	// For sorting
	severityNumValue          int
	directDependencies        []directDependenciesTableRow `embed-table:"true"`
	impactedDependencyName    string                       `col-name:"Affected\nComponent\nName"`
	impactedDependencyVersion string                       `col-name:"Affected\nComponent\nVersion"`
	fixedVersions             string                       `col-name:"Fixed\nVersions"`
	impactedDependencyType    string                       `col-name:"Type"`
	watch                     string                       `col-name:"Watch Name" omitempty:"true"`
	issueId                   string                       `col-name:"Issue ID" extended:"true"`
}

// For Binary scans
type vulnerabilityScanTableRow struct {
	cves       []cveTableRow `embed-table:"true"`
	severity   string        `col-name:"Severity"`
	applicable string        `col-name:"Contextual\nAnalysis" omitempty:"true"`
	// For sorting
	severityNumValue       int
	directPackages         []directPackagesTableRow `embed-table:"true"`
	impactedPackageName    string                   `col-name:"Affected\nComponent\nName"`
	impactedPackageVersion string                   `col-name:"Affected\nComponent\nVersion"`
	fixedVersions          string                   `col-name:"Fixed\nVersions"`
	ImpactedPackageType    string                   `col-name:"Type"`
	issueId                string                   `col-name:"Issue ID" extended:"true"`
}

type SbomTableRow struct {
	Component   string `col-name:"Component"`
	Version     string `col-name:"Version"`
	PackageType string `col-name:"Type"`
	Relation    string `col-name:"Relation"`
	// For sorting
	RelationPriority int
}

type licenseTableRow struct {
	licenseKey                string                       `col-name:"License"`
	directDependencies        []directDependenciesTableRow `embed-table:"true"`
	impactedDependencyName    string                       `col-name:"Impacted\nDependency"`
	impactedDependencyVersion string                       `col-name:"Impacted\nDependency\nVersion"`
	impactedDependencyType    string                       `col-name:"Type"`
}

type licenseScanTableRow struct {
	licenseKey             string                   `col-name:"License"`
	directDependencies     []directPackagesTableRow `embed-table:"true"`
	impactedPackageName    string                   `col-name:"Impacted\nPackage"`
	impactedPackageVersion string                   `col-name:"Impacted\nPackage\nVersion"`
	impactedDependencyType string                   `col-name:"Type"`
}

type licenseViolationTableRow struct {
	licenseKey string `col-name:"License"`
	severity   string `col-name:"Severity"`
	// For sorting
	severityNumValue          int
	directDependencies        []directDependenciesTableRow `embed-table:"true"`
	impactedDependencyName    string                       `col-name:"Impacted\nDependency"`
	impactedDependencyVersion string                       `col-name:"Impacted\nDependency\nVersion"`
	impactedDependencyType    string                       `col-name:"Type"`
	watch                     string                       `col-name:"Watch Name"`
}

type licenseViolationScanTableRow struct {
	licenseKey string `col-name:"License"`
	severity   string `col-name:"Severity"`
	// For sorting
	severityNumValue       int
	directDependencies     []directPackagesTableRow `embed-table:"true"`
	impactedPackageName    string                   `col-name:"Impacted\nPackage"`
	impactedPackageVersion string                   `col-name:"Impacted\nPackage\nVersion"`
	impactedDependencyType string                   `col-name:"Type"`
}

type operationalRiskViolationTableRow struct {
	Severity string `col-name:"Severity"`
	// For sorting
	severityNumValue          int
	directDependencies        []directDependenciesTableRow `embed-table:"true"`
	impactedDependencyName    string                       `col-name:"Impacted\nDependency"`
	impactedDependencyVersion string                       `col-name:"Impacted\nDependency\nVersion"`
	impactedDependencyType    string                       `col-name:"Type"`
	riskReason                string                       `col-name:"Risk\nReason"`
	isEol                     string                       `col-name:"Is\nEnd\nOf\nLife" extended:"true"`
	eolMessage                string                       `col-name:"End\nOf\nLife\nMessage" extended:"true"`
	cadence                   string                       `col-name:"Cadence"  extended:"true"`
	Commits                   string                       `col-name:"Commits"  extended:"true"`
	committers                string                       `col-name:"Committers"  extended:"true"`
	newerVersions             string                       `col-name:"Newer\nVersions" extended:"true"`
	latestVersion             string                       `col-name:"Latest\nVersion" extended:"true"`
}

type operationalRiskViolationScanTableRow struct {
	Severity string `col-name:"Severity"`
	// For sorting
	severityNumValue       int
	directDependencies     []directPackagesTableRow `embed-table:"true"`
	impactedPackageName    string                   `col-name:"Impacted\nPackage"`
	impactedPackageVersion string                   `col-name:"Impacted\nPackage\nVersion"`
	impactedDependencyType string                   `col-name:"Type"`
	riskReason             string                   `col-name:"Risk\nReason"`
	isEol                  string                   `col-name:"Is\nEnd\nOf\nLife" extended:"true"`
	eolMessage             string                   `col-name:"End\nOf\nLife\nMessage" extended:"true"`
	cadence                string                   `col-name:"Cadence"  extended:"true"`
	commits                string                   `col-name:"Commits"  extended:"true"`
	committers             string                   `col-name:"Committers"  extended:"true"`
	newerVersions          string                   `col-name:"Newer\nVersions" extended:"true"`
	latestVersion          string                   `col-name:"Latest\nVersion" extended:"true"`
}

type directDependenciesTableRow struct {
	name    string `col-name:"Direct\nDependency"`
	version string `col-name:"Direct\nDependency\nVersion"`
}

type directPackagesTableRow struct {
	name    string `col-name:"Direct\nPackage"`
	version string `col-name:"Direct\nPackage\nVersion"`
}

type cveTableRow struct {
	id     string `col-name:"CVE"`
	cvssV2 string `col-name:"CVSS\nv2" extended:"true"`
	cvssV3 string `col-name:"CVSS\nv3" extended:"true"`
}

type secretsTableRow struct {
	severity        string `col-name:"Severity"`
	file            string `col-name:"File"`
	lineColumn      string `col-name:"Line:Column"`
	origin          string `col-name:"Origin" omitempty:"true"`
	secret          string `col-name:"Secret"`
	tokenValidation string `col-name:"Token Validation" omitempty:"true"`
	tokenInfo       string `col-name:"Token Info" omitempty:"true"`
	watch           string `col-name:"Watch Name" omitempty:"true"`
}

type iacOrSastTableRow struct {
	severity   string `col-name:"Severity"`
	file       string `col-name:"File"`
	lineColumn string `col-name:"Line:Column"`
	finding    string `col-name:"Finding"`
	watch      string `col-name:"Watch Name" omitempty:"true"`
}
