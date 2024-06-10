package tableformat

import (
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/exp/maps"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-cli-security/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"

	"github.com/gookit/color"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

const (
	rootIndex                  = 0
	directDependencyIndex      = 1
	directDependencyPathLength = 2
	nodeModules                = "node_modules"
	NpmPackageTypeIdentifier   = "npm://"
)

type CmdResultsTableConverter struct {
	current *formats.TableResults
	entitledForJas bool
}

func NewCmdResultsTableConverter() *CmdResultsTableConverter {
	return &CmdResultsTableConverter{}
}

func (tc *CmdResultsTableConverter) GetForSourceCode() *formats.TableResults {
	if tc.current == nil {
		return &formats.TableResults{}
	}
	return tc.current
}

func (tc *CmdResultsTableConverter) GetForBinary() formats.ScanTableResults {
	tableResults := tc.GetForSourceCode()
	if tableResults == nil {
		return formats.ScanTableResults{}
	}
	scanTableResults := formats.ScanTableResults{
		SecurityVulnerabilitiesTable: formats.ConvertToVulnerabilityTableRow(tableResults.SecurityVulnerabilitiesTable),
	}
	return scanTableResults
}

func (tc *CmdResultsTableConverter) Reset(multiScanId, _ string, entitledForJas bool) error {
	sjc.current = &formats.SimpleJsonResults{MultiScanId: multiScanId}
	sjc.entitledForJas = entitledForJas
	return nil
}

func (tc *CmdResultsTableConverter) ParseNewScanResultsMetadata(target string, errors error) error {
	return nil
}

func (tc *CmdResultsTableConverter) ParseViolations(target string, tech techutils.Technology, violations []services.Violation, applicabilityRuns ...*sarif.Run) error {
	return nil
}

func (tc *CmdResultsTableConverter) ParseVulnerabilities(target string, tech techutils.Technology, vulnerabilities []services.Vulnerability, applicabilityRuns ...*sarif.Run) error {
	return nil
}

func (tc *CmdResultsTableConverter) ParseLicenses(target string, tech techutils.Technology, licenses []services.License) error {
	return nil
}

func (tc *CmdResultsTableConverter) ParseSecrets(target string, secrets ...*sarif.Run) error {
	return nil
}

func (tc *CmdResultsTableConverter) ParseIacs(target string, iacs ...*sarif.Run) error {
	return nil
}

func (tc *CmdResultsTableConverter) ParseSast(target string, sast ...*sarif.Run) error {
	return nil
}

// PrintViolationsTable prints the violations in 4 tables: security violations, license compliance violations, operational risk violations and ignore rule URLs.
// Set multipleRoots to true in case the given violations array contains (or may contain) results of several projects or files (like in binary scan).
// In case multipleRoots is true, the field Component will show the root of each impact path, otherwise it will show the root's child.
// In case one (or more) of the violations contains the field FailBuild set to true, CliError with exit code 3 will be returned.
// Set printExtended to true to print fields with 'extended' tag.
// If the scan argument is set to true, print the scan tables.
func PrintViolationsTable(violations []services.Violation, cmdResults *results.ScanCommandResults, multipleRoots, printExtended bool, scanType services.ScanType) error {
	securityViolationsRows, licenseViolationsRows, operationalRiskViolationsRows, err := prepareViolations(violations, cmdResults, multipleRoots, true, true)
	if err != nil {
		return err
	}
	// Print tables, if scan is true; print the scan tables.
	if scanType == services.Binary {
		err = coreutils.PrintTable(formats.ConvertToVulnerabilityScanTableRow(securityViolationsRows), "Security Violations", "No security violations were found", printExtended)
		if err != nil {
			return err
		}
		err = coreutils.PrintTable(formats.ConvertToLicenseViolationScanTableRow(licenseViolationsRows), "License Compliance Violations", "No license compliance violations were found", printExtended)
		if err != nil {
			return err
		}
		if len(operationalRiskViolationsRows) > 0 {
			return coreutils.PrintTable(formats.ConvertToOperationalRiskViolationScanTableRow(operationalRiskViolationsRows), "Operational Risk Violations", "No operational risk violations were found", printExtended)
		}
	} else {
		err = coreutils.PrintTable(formats.ConvertToVulnerabilityTableRow(securityViolationsRows), "Security Violations", "No security violations were found", printExtended)
		if err != nil {
			return err
		}
		err = coreutils.PrintTable(formats.ConvertToLicenseViolationTableRow(licenseViolationsRows), "License Compliance Violations", "No license compliance violations were found", printExtended)
		if err != nil {
			return err
		}
		if len(operationalRiskViolationsRows) > 0 {
			return coreutils.PrintTable(formats.ConvertToOperationalRiskViolationTableRow(operationalRiskViolationsRows), "Operational Risk Violations", "No operational risk violations were found", printExtended)
		}
	}
	return nil
}

// PrintVulnerabilitiesTable prints the vulnerabilities in a table.
// Set multipleRoots to true in case the given vulnerabilities array contains (or may contain) results of several projects or files (like in binary scan).
// In case multipleRoots is true, the field Component will show the root of each impact path, otherwise it will show the root's child.
// Set printExtended to true to print fields with 'extended' tag.
// If the scan argument is set to true, print the scan tables.
func PrintVulnerabilitiesTable(vulnerabilities []services.Vulnerability, cmdResults *results.ScanCommandResults, multipleRoots, printExtended bool, scanType services.ScanType) error {
	vulnerabilitiesRows, err := prepareVulnerabilities(vulnerabilities, cmdResults, multipleRoots, true, true)
	if err != nil {
		return err
	}

	if scanType == services.Binary {
		return coreutils.PrintTable(formats.ConvertToVulnerabilityScanTableRow(vulnerabilitiesRows), "Vulnerable Components", "✨ No vulnerable components were found ✨", printExtended)
	}
	var emptyTableMessage string
	if len(cmdResults.ScaResults) > 0 {
		emptyTableMessage = "✨ No vulnerable dependencies were found ✨"
	} else {
		emptyTableMessage = coreutils.PrintYellow("🔧 Couldn't determine a package manager or build tool used by this project 🔧")
	}
	return coreutils.PrintTable(formats.ConvertToVulnerabilityTableRow(vulnerabilitiesRows), "Vulnerable Dependencies", emptyTableMessage, printExtended)
}





// PrintLicensesTable prints the licenses in a table.
// Set multipleRoots to true in case the given licenses array contains (or may contain) results of several projects or files (like in binary scan).
// In case multipleRoots is true, the field Component will show the root of each impact path, otherwise it will show the root's child.
// Set printExtended to true to print fields with 'extended' tag.
// If the scan argument is set to true, print the scan tables.
func PrintLicensesTable(licenses []services.License, printExtended bool, scanType services.ScanType) error {
	licensesRows, err := PrepareLicenses(licenses)
	if err != nil {
		return err
	}
	if scanType == services.Binary {
		return coreutils.PrintTable(formats.ConvertToLicenseScanTableRow(licensesRows), "Licenses", "No licenses were found", printExtended)
	}
	return coreutils.PrintTable(formats.ConvertToLicenseTableRow(licensesRows), "Licenses", "No licenses were found", printExtended)
}

func PrepareLicenses(licenses []services.License) ([]formats.LicenseRow, error) {
	var licensesRows []formats.LicenseRow
	for _, license := range licenses {
		impactedPackagesNames, impactedPackagesVersions, impactedPackagesTypes, _, components, impactPaths, err := splitComponents(license.Components)
		if err != nil {
			return nil, err
		}
		for compIndex := 0; compIndex < len(impactedPackagesNames); compIndex++ {
			licensesRows = append(licensesRows,
				formats.LicenseRow{
					LicenseKey:  license.Key,
					ImpactPaths: impactPaths[compIndex],
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						ImpactedDependencyName:    impactedPackagesNames[compIndex],
						ImpactedDependencyVersion: impactedPackagesVersions[compIndex],
						ImpactedDependencyType:    impactedPackagesTypes[compIndex],
						Components:                components[compIndex],
					},
				},
			)
		}
	}

	return licensesRows, nil
}

// Prepare secrets for all non-table formats (without style or emoji)
func PrepareSecrets(secrets []*sarif.Run) []formats.SourceCodeRow {
	return prepareSecrets(secrets, false)
}

func prepareSecrets(secrets []*sarif.Run, isTable bool) []formats.SourceCodeRow {
	var secretsRows []formats.SourceCodeRow
	for _, secretRun := range secrets {
		for _, secretResult := range secretRun.Results {
			currSeverity := GetSeverity(sarifutils.GetResultSeverity(secretResult), jasutils.Applicable)
			for _, location := range secretResult.Locations {
				secretsRows = append(secretsRows,
					formats.SourceCodeRow{
						SeverityDetails: formats.SeverityDetails{Severity: currSeverity.printableTitle(isTable), SeverityNumValue: currSeverity.NumValue()},
						Finding:         sarifutils.GetResultMsgText(secretResult),
						Location: formats.Location{
							File:        sarifutils.GetRelativeLocationFileName(location, secretRun.Invocations),
							StartLine:   sarifutils.GetLocationStartLine(location),
							StartColumn: sarifutils.GetLocationStartColumn(location),
							EndLine:     sarifutils.GetLocationEndLine(location),
							EndColumn:   sarifutils.GetLocationEndColumn(location),
							Snippet:     sarifutils.GetLocationSnippet(location),
						},
					},
				)
			}
		}
	}

	sort.Slice(secretsRows, func(i, j int) bool {
		return secretsRows[i].SeverityNumValue > secretsRows[j].SeverityNumValue
	})

	return secretsRows
}

func PrintSecretsTable(secrets []*sarif.Run, entitledForSecretsScan bool) error {
	if entitledForSecretsScan {
		secretsRows := prepareSecrets(secrets, true)
		log.Output()
		return coreutils.PrintTable(formats.ConvertToSecretsTableRow(secretsRows), "Secret Detection",
			"✨ No secrets were found ✨", false)
	}
	return nil
}

// Prepare iacs for all non-table formats (without style or emoji)
func PrepareIacs(iacs []*sarif.Run) []formats.SourceCodeRow {
	return prepareIacs(iacs, false)
}

func prepareIacs(iacs []*sarif.Run, isTable bool) []formats.SourceCodeRow {
	var iacRows []formats.SourceCodeRow
	for _, iacRun := range iacs {
		for _, iacResult := range iacRun.Results {
			scannerDescription := ""
			if rule, err := iacRun.GetRuleById(*iacResult.RuleID); err == nil {
				scannerDescription = sarifutils.GetRuleFullDescription(rule)
			}
			currSeverity := GetSeverity(sarifutils.GetResultSeverity(iacResult), jasutils.Applicable)
			for _, location := range iacResult.Locations {
				iacRows = append(iacRows,
					formats.SourceCodeRow{
						SeverityDetails:    formats.SeverityDetails{Severity: currSeverity.printableTitle(isTable), SeverityNumValue: currSeverity.NumValue()},
						Finding:            sarifutils.GetResultMsgText(iacResult),
						ScannerDescription: scannerDescription,
						Location: formats.Location{
							File:        sarifutils.GetRelativeLocationFileName(location, iacRun.Invocations),
							StartLine:   sarifutils.GetLocationStartLine(location),
							StartColumn: sarifutils.GetLocationStartColumn(location),
							EndLine:     sarifutils.GetLocationEndLine(location),
							EndColumn:   sarifutils.GetLocationEndColumn(location),
							Snippet:     sarifutils.GetLocationSnippet(location),
						},
					},
				)
			}
		}
	}

	sort.Slice(iacRows, func(i, j int) bool {
		return iacRows[i].SeverityNumValue > iacRows[j].SeverityNumValue
	})

	return iacRows
}

func PrintIacTable(iacs []*sarif.Run, entitledForIacScan bool) error {
	if entitledForIacScan {
		iacRows := prepareIacs(iacs, true)
		log.Output()
		return coreutils.PrintTable(formats.ConvertToIacOrSastTableRow(iacRows), "Infrastructure as Code Vulnerabilities",
			"✨ No Infrastructure as Code vulnerabilities were found ✨", false)
	}
	return nil
}

func PrepareSast(sasts []*sarif.Run) []formats.SourceCodeRow {
	return prepareSast(sasts, false)
}

func prepareSast(sasts []*sarif.Run, isTable bool) []formats.SourceCodeRow {
	var sastRows []formats.SourceCodeRow
	for _, sastRun := range sasts {
		for _, sastResult := range sastRun.Results {
			scannerDescription := ""
			if rule, err := sastRun.GetRuleById(*sastResult.RuleID); err == nil {
				scannerDescription = sarifutils.GetRuleFullDescription(rule)
			}
			currSeverity := GetSeverity(sarifutils.GetResultSeverity(sastResult), jasutils.Applicable)

			for _, location := range sastResult.Locations {
				codeFlows := sarifutils.GetLocationRelatedCodeFlowsFromResult(location, sastResult)
				sastRows = append(sastRows,
					formats.SourceCodeRow{
						SeverityDetails:    formats.SeverityDetails{Severity: currSeverity.printableTitle(isTable), SeverityNumValue: currSeverity.NumValue()},
						ScannerDescription: scannerDescription,
						Finding:            sarifutils.GetResultMsgText(sastResult),
						Location: formats.Location{
							File:        sarifutils.GetRelativeLocationFileName(location, sastRun.Invocations),
							StartLine:   sarifutils.GetLocationStartLine(location),
							StartColumn: sarifutils.GetLocationStartColumn(location),
							EndLine:     sarifutils.GetLocationEndLine(location),
							EndColumn:   sarifutils.GetLocationEndColumn(location),
							Snippet:     sarifutils.GetLocationSnippet(location),
						},
						CodeFlow: codeFlowToLocationFlow(codeFlows, sastRun.Invocations, isTable),
					},
				)
			}
		}
	}

	sort.Slice(sastRows, func(i, j int) bool {
		return sastRows[i].SeverityNumValue > sastRows[j].SeverityNumValue
	})

	return sastRows
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

func PrintSastTable(sast []*sarif.Run, entitledForSastScan bool) error {
	if entitledForSastScan {
		sastRows := prepareSast(sast, true)
		log.Output()
		return coreutils.PrintTable(formats.ConvertToIacOrSastTableRow(sastRows), "Static Application Security Testing (SAST)",
			"✨ No Static Application Security Testing vulnerabilities were found ✨", false)
	}
	return nil
}







type TableSeverity struct {
	formats.SeverityDetails
	style color.Style
	emoji string
}

func (s *TableSeverity) printableTitle(isTable bool) string {
	if isTable && (log.IsStdOutTerminal() && log.IsColorsSupported() || os.Getenv("GITLAB_CI") != "") {
		return s.style.Render(s.emoji + s.Severity)
	}
	return s.Severity
}

var Severities = map[string]map[jasutils.ApplicabilityStatus]*TableSeverity{
	"Critical": {
		jasutils.Applicable:                {SeverityDetails: formats.SeverityDetails{Severity: "Critical", SeverityNumValue: 20}, emoji: "💀", style: color.New(color.BgLightRed, color.LightWhite)},
		jasutils.ApplicabilityUndetermined: {SeverityDetails: formats.SeverityDetails{Severity: "Critical", SeverityNumValue: 19}, emoji: "💀", style: color.New(color.BgLightRed, color.LightWhite)},
		jasutils.NotCovered:                {SeverityDetails: formats.SeverityDetails{Severity: "Critical", SeverityNumValue: 18}, emoji: "💀", style: color.New(color.BgLightRed, color.LightWhite)},
		jasutils.NotApplicable:             {SeverityDetails: formats.SeverityDetails{Severity: "Critical", SeverityNumValue: 5}, emoji: "💀", style: color.New(color.Gray)},
	},
	"High": {
		jasutils.Applicable:                {SeverityDetails: formats.SeverityDetails{Severity: "High", SeverityNumValue: 17}, emoji: "🔥", style: color.New(color.Red)},
		jasutils.ApplicabilityUndetermined: {SeverityDetails: formats.SeverityDetails{Severity: "High", SeverityNumValue: 16}, emoji: "🔥", style: color.New(color.Red)},
		jasutils.NotCovered:                {SeverityDetails: formats.SeverityDetails{Severity: "High", SeverityNumValue: 15}, emoji: "🔥", style: color.New(color.Red)},
		jasutils.NotApplicable:             {SeverityDetails: formats.SeverityDetails{Severity: "High", SeverityNumValue: 4}, emoji: "🔥", style: color.New(color.Gray)},
	},
	"Medium": {
		jasutils.Applicable:                {SeverityDetails: formats.SeverityDetails{Severity: "Medium", SeverityNumValue: 14}, emoji: "🎃", style: color.New(color.Yellow)},
		jasutils.ApplicabilityUndetermined: {SeverityDetails: formats.SeverityDetails{Severity: "Medium", SeverityNumValue: 13}, emoji: "🎃", style: color.New(color.Yellow)},
		jasutils.NotCovered:                {SeverityDetails: formats.SeverityDetails{Severity: "Medium", SeverityNumValue: 12}, emoji: "🎃", style: color.New(color.Yellow)},
		jasutils.NotApplicable:             {SeverityDetails: formats.SeverityDetails{Severity: "Medium", SeverityNumValue: 3}, emoji: "🎃", style: color.New(color.Gray)},
	},
	"Low": {
		jasutils.Applicable:                {SeverityDetails: formats.SeverityDetails{Severity: "Low", SeverityNumValue: 11}, emoji: "👻"},
		jasutils.ApplicabilityUndetermined: {SeverityDetails: formats.SeverityDetails{Severity: "Low", SeverityNumValue: 10}, emoji: "👻"},
		jasutils.NotCovered:                {SeverityDetails: formats.SeverityDetails{Severity: "Low", SeverityNumValue: 9}, emoji: "👻"},
		jasutils.NotApplicable:             {SeverityDetails: formats.SeverityDetails{Severity: "Low", SeverityNumValue: 2}, emoji: "👻", style: color.New(color.Gray)},
	},
	"Unknown": {
		jasutils.Applicable:                {SeverityDetails: formats.SeverityDetails{Severity: "Unknown", SeverityNumValue: 8}, emoji: "😐"},
		jasutils.ApplicabilityUndetermined: {SeverityDetails: formats.SeverityDetails{Severity: "Unknown", SeverityNumValue: 7}, emoji: "😐"},
		jasutils.NotCovered:                {SeverityDetails: formats.SeverityDetails{Severity: "Unknown", SeverityNumValue: 6}, emoji: "😐"},
		jasutils.NotApplicable:             {SeverityDetails: formats.SeverityDetails{Severity: "Unknown", SeverityNumValue: 1}, emoji: "😐", style: color.New(color.Gray)},
	},
}

func (s *TableSeverity) NumValue() int {
	return s.SeverityNumValue
}

func (s *TableSeverity) Emoji() string {
	return s.emoji
}

func GetSeveritiesFormat(severity string) (string, error) {
	formattedSeverity := cases.Title(language.Und).String(severity)
	if formattedSeverity != "" && Severities[formattedSeverity][Applicable] == nil {
		return "", errorutils.CheckErrorf("only the following severities are supported: " + coreutils.ListToText(maps.Keys(Severities)))
	}

	return formattedSeverity, nil
}

func GetSeverity(severityTitle string, applicable ApplicabilityStatus) *TableSeverity {
	if Severities[severityTitle] == nil {
		return &TableSeverity{SeverityDetails: formats.SeverityDetails{Severity: severityTitle}}
	}

	switch applicable {
	case NotApplicable:
		return Severities[severityTitle][NotApplicable]
	case Applicable:
		return Severities[severityTitle][Applicable]
	case ApplicabilityUndetermined:
		return Severities[severityTitle][ApplicabilityUndetermined]
	default:
		return Severities[severityTitle][NotCovered]
	}
}














func printApplicabilityCveValue(applicabilityStatus ApplicabilityStatus, isTable bool) string {
	if isTable && (log.IsStdOutTerminal() && log.IsColorsSupported() || os.Getenv("GITLAB_CI") != "") {
		if applicabilityStatus == Applicable {
			return color.New(color.Red).Render(applicabilityStatus)
		} else if applicabilityStatus == NotApplicable {
			return color.New(color.Green).Render(applicabilityStatus)
		}
	}
	return applicabilityStatus.String()
}







