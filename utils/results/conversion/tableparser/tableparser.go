package tableparser

import (
	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/simplejsonparser"

	"github.com/jfrog/jfrog-client-go/xray/services"
)

type CmdResultsTableConverter struct {
	simpleJsonConvertor *simplejsonparser.CmdResultsSimpleJsonConverter
	// If supported, pretty print the output in the tables
	pretty bool
}

func NewCmdResultsTableConverter(pretty bool) *CmdResultsTableConverter {
	return &CmdResultsTableConverter{pretty: pretty, simpleJsonConvertor: simplejsonparser.NewCmdResultsSimpleJsonConverter(pretty, true)}
}

func (tc *CmdResultsTableConverter) Get() (formats.ResultsTables, error) {
	simpleJsonFormat, err := tc.simpleJsonConvertor.Get()
	if err != nil {
		return formats.ResultsTables{}, err
	}
	return formats.ResultsTables{
		LicensesTable:                  formats.ConvertToLicenseTableRow(simpleJsonFormat.Licenses),
		SecurityVulnerabilitiesTable:   formats.ConvertToScaVulnerabilityOrViolationTableRow(simpleJsonFormat.Vulnerabilities),
		SecurityViolationsTable:        formats.ConvertToScaVulnerabilityOrViolationTableRow(simpleJsonFormat.SecurityViolations),
		LicenseViolationsTable:         formats.ConvertToLicenseViolationTableRow(simpleJsonFormat.LicensesViolations),
		OperationalRiskViolationsTable: formats.ConvertToOperationalRiskViolationTableRow(simpleJsonFormat.OperationalRiskViolations),
		SecretsVulnerabilitiesTable:    formats.ConvertToSecretsTableRow(simpleJsonFormat.SecretsVulnerabilities),
		SecretsViolationsTable:         formats.ConvertToSecretsTableRow(simpleJsonFormat.SecretsViolations),
		IacVulnerabilitiesTable:        formats.ConvertToIacOrSastTableRow(simpleJsonFormat.IacsVulnerabilities),
		IacViolationsTable:             formats.ConvertToIacOrSastTableRow(simpleJsonFormat.IacsViolations),
		SastVulnerabilitiesTable:       formats.ConvertToIacOrSastTableRow(simpleJsonFormat.SastVulnerabilities),
		SastViolationsTable:            formats.ConvertToIacOrSastTableRow(simpleJsonFormat.SastViolations),
		MaliciousVulnerabilitiesTable:  formats.ConvertToMaliciousTableRow(simpleJsonFormat.MaliciousVulnerabilities),
		MaliciousViolationsTable:       formats.ConvertToMaliciousTableRow(simpleJsonFormat.MaliciousViolations),
	}, nil
}

func (tc *CmdResultsTableConverter) Reset(cmdType utils.CommandType, multiScanId, xrayVersion string, entitledForJas, multipleTargets bool, generalError error) (err error) {
	return tc.simpleJsonConvertor.Reset(cmdType, multiScanId, xrayVersion, entitledForJas, multipleTargets, generalError)
}

func (tc *CmdResultsTableConverter) ParseNewTargetResults(target results.ScanTarget, errors ...error) (err error) {
	return tc.simpleJsonConvertor.ParseNewTargetResults(target, errors...)
}

func (tc *CmdResultsTableConverter) ParseScaIssues(target results.ScanTarget, violations bool, scaResponse results.ScanResult[services.ScanResponse], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	return tc.simpleJsonConvertor.ParseScaIssues(target, violations, scaResponse, applicableScan...)
}

func (tc *CmdResultsTableConverter) ParseLicenses(target results.ScanTarget, scaResponse results.ScanResult[services.ScanResponse]) (err error) {
	return tc.simpleJsonConvertor.ParseLicenses(target, scaResponse)
}

func (tc *CmdResultsTableConverter) ParseSecrets(target results.ScanTarget, isViolationsResults bool, secrets []results.ScanResult[[]*sarif.Run]) (err error) {
	return tc.simpleJsonConvertor.ParseSecrets(target, isViolationsResults, secrets)
}

func (tc *CmdResultsTableConverter) ParseMalicious(target results.ScanTarget, isViolationsResults bool, maliciousFindings []results.ScanResult[[]*sarif.Run]) (err error) {
	return tc.simpleJsonConvertor.ParseMalicious(target, isViolationsResults, maliciousFindings)
}

func (tc *CmdResultsTableConverter) ParseIacs(target results.ScanTarget, isViolationsResults bool, iacs []results.ScanResult[[]*sarif.Run]) (err error) {
	return tc.simpleJsonConvertor.ParseIacs(target, isViolationsResults, iacs)
}

func (tc *CmdResultsTableConverter) ParseSast(target results.ScanTarget, isViolationsResults bool, sast []results.ScanResult[[]*sarif.Run]) (err error) {
	return tc.simpleJsonConvertor.ParseSast(target, isViolationsResults, sast)
}
