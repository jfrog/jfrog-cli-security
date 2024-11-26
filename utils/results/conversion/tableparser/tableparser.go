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
		SecurityVulnerabilitiesTable:   formats.ConvertToVulnerabilityTableRow(simpleJsonFormat.Vulnerabilities),
		SecurityViolationsTable:        formats.ConvertToVulnerabilityTableRow(simpleJsonFormat.SecurityViolations),
		LicenseViolationsTable:         formats.ConvertToLicenseViolationTableRow(simpleJsonFormat.LicensesViolations),
		OperationalRiskViolationsTable: formats.ConvertToOperationalRiskViolationTableRow(simpleJsonFormat.OperationalRiskViolations),
		SecretsVulnerabilitiesTable:    formats.ConvertToSecretsTableRow(simpleJsonFormat.SecretsVulnerabilities),
		SecretsViolationsTable:         formats.ConvertToSecretsTableRow(simpleJsonFormat.SecretsViolations),
		IacVulnerabilitiesTable:        formats.ConvertToIacOrSastTableRow(simpleJsonFormat.IacsVulnerabilities),
		IacViolationsTable:             formats.ConvertToIacOrSastTableRow(simpleJsonFormat.IacsViolations),
		SastVulnerabilitiesTable:       formats.ConvertToIacOrSastTableRow(simpleJsonFormat.SastVulnerabilities),
		SastViolationsTable:            formats.ConvertToIacOrSastTableRow(simpleJsonFormat.SastViolations),
	}, nil
}

func (tc *CmdResultsTableConverter) Reset(cmdType utils.CommandType, multiScanId, xrayVersion string, entitledForJas, multipleTargets bool, generalError error) (err error) {
	return tc.simpleJsonConvertor.Reset(cmdType, multiScanId, xrayVersion, entitledForJas, multipleTargets, generalError)
}

func (tc *CmdResultsTableConverter) ParseNewTargetResults(target results.ScanTarget, errors ...error) (err error) {
	return tc.simpleJsonConvertor.ParseNewTargetResults(target, errors...)
}

func (tc *CmdResultsTableConverter) ParseScaViolations(target results.ScanTarget, scaResponse services.ScanResponse, applicabilityRuns ...*sarif.Run) (err error) {
	return tc.simpleJsonConvertor.ParseScaViolations(target, scaResponse, applicabilityRuns...)
}

func (tc *CmdResultsTableConverter) ParseScaVulnerabilities(target results.ScanTarget, scaResponse services.ScanResponse, applicabilityRuns ...*sarif.Run) (err error) {
	return tc.simpleJsonConvertor.ParseScaVulnerabilities(target, scaResponse, applicabilityRuns...)
}

func (tc *CmdResultsTableConverter) ParseLicenses(target results.ScanTarget, licenses []services.License) (err error) {
	return tc.simpleJsonConvertor.ParseLicenses(target, licenses)
}

func (tc *CmdResultsTableConverter) ParseSecrets(target results.ScanTarget, isViolationsResults bool, secrets ...*sarif.Run) (err error) {
	return tc.simpleJsonConvertor.ParseSecrets(target, isViolationsResults, secrets...)
}

func (tc *CmdResultsTableConverter) ParseIacs(target results.ScanTarget, isViolationsResults bool, iacs ...*sarif.Run) (err error) {
	return tc.simpleJsonConvertor.ParseIacs(target, isViolationsResults, iacs...)
}

func (tc *CmdResultsTableConverter) ParseSast(target results.ScanTarget, isViolationsResults bool, sast ...*sarif.Run) (err error) {
	return tc.simpleJsonConvertor.ParseSast(target, isViolationsResults, sast...)
}
