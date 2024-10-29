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
		SecurityVulnerabilitiesTable:   formats.ConvertToVulnerabilityTableRow(simpleJsonFormat.Vulnerabilities),
		SecurityViolationsTable:        formats.ConvertToVulnerabilityTableRow(simpleJsonFormat.SecurityViolations),
		LicenseViolationsTable:         formats.ConvertToLicenseViolationTableRow(simpleJsonFormat.LicensesViolations),
		LicensesTable:                  formats.ConvertToLicenseTableRow(simpleJsonFormat.Licenses),
		OperationalRiskViolationsTable: formats.ConvertToOperationalRiskViolationTableRow(simpleJsonFormat.OperationalRiskViolations),
		SecretsTable:                   formats.ConvertToSecretsTableRow(simpleJsonFormat.Secrets),
		IacTable:                       formats.ConvertToIacOrSastTableRow(simpleJsonFormat.Iacs),
		SastTable:                      formats.ConvertToIacOrSastTableRow(simpleJsonFormat.Sast),
	}, nil
}

func (tc *CmdResultsTableConverter) Reset(cmdType utils.CommandType, multiScanId, xrayVersion string, entitledForJas, multipleTargets bool, generalError error) (err error) {
	return tc.simpleJsonConvertor.Reset(cmdType, multiScanId, xrayVersion, entitledForJas, multipleTargets, generalError)
}

func (tc *CmdResultsTableConverter) ParseNewTargetResults(target results.ScanTarget, errors ...error) (err error) {
	return tc.simpleJsonConvertor.ParseNewTargetResults(target, errors...)
}

func (tc *CmdResultsTableConverter) ParseViolations(target results.ScanTarget, scaResponse services.ScanResponse, applicabilityRuns ...*sarif.Run) (err error) {
	return tc.simpleJsonConvertor.ParseViolations(target, scaResponse, applicabilityRuns...)
}

func (tc *CmdResultsTableConverter) ParseVulnerabilities(target results.ScanTarget, scaResponse services.ScanResponse, applicabilityRuns ...*sarif.Run) (err error) {
	return tc.simpleJsonConvertor.ParseVulnerabilities(target, scaResponse, applicabilityRuns...)
}

func (tc *CmdResultsTableConverter) ParseLicenses(target results.ScanTarget, licenses []services.License) (err error) {
	return tc.simpleJsonConvertor.ParseLicenses(target, licenses)
}

func (tc *CmdResultsTableConverter) ParseSecrets(target results.ScanTarget, secrets ...*sarif.Run) (err error) {
	return tc.simpleJsonConvertor.ParseSecrets(target, secrets...)
}

func (tc *CmdResultsTableConverter) ParseIacs(target results.ScanTarget, iacs ...*sarif.Run) (err error) {
	return tc.simpleJsonConvertor.ParseIacs(target, iacs...)
}

func (tc *CmdResultsTableConverter) ParseSast(target results.ScanTarget, sast ...*sarif.Run) (err error) {
	return tc.simpleJsonConvertor.ParseSast(target, sast...)
}
