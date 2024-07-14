package tableparser

import (
	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/simplejsonparser"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"

	"github.com/jfrog/jfrog-client-go/xray/services"
)

type CmdResultsTableConverter struct {
	simpleJsonConvertor *simplejsonparser.CmdResultsSimpleJsonConverter
	// If supported, pretty print the output in the tables
	pretty bool
}

func NewCmdResultsTableConverter(pretty bool) *CmdResultsTableConverter {
	return &CmdResultsTableConverter{pretty: pretty, simpleJsonConvertor: simplejsonparser.NewCmdResultsSimpleJsonConverter(pretty)}
}

func (tc *CmdResultsTableConverter) Get() *formats.ResultsTables {
	simpleJsonFormat := tc.simpleJsonConvertor.Get()
	if simpleJsonFormat == nil {
		return &formats.ResultsTables{}
	}
	return &formats.ResultsTables{
		SecurityVulnerabilitiesTable:   formats.ConvertToVulnerabilityTableRow(simpleJsonFormat.Vulnerabilities),
		LicenseViolationsTable:         formats.ConvertToLicenseViolationTableRow(simpleJsonFormat.LicensesViolations),
		OperationalRiskViolationsTable: formats.ConvertToOperationalRiskViolationTableRow(simpleJsonFormat.OperationalRiskViolations),
		SecretsTable:                   formats.ConvertToSecretsTableRow(simpleJsonFormat.Secrets),
		IacTable:                       formats.ConvertToIacOrSastTableRow(simpleJsonFormat.Iacs),
		SastTable:                      formats.ConvertToIacOrSastTableRow(simpleJsonFormat.Sast),
	}
}

func (tc *CmdResultsTableConverter) Reset(multiScanId, xrayVersion string, entitledForJas bool) (err error) {
	return tc.simpleJsonConvertor.Reset(multiScanId, xrayVersion, entitledForJas)
}

func (tc *CmdResultsTableConverter) ParseNewScanResultsMetadata(target string, errors ...error) (err error) {
	return tc.simpleJsonConvertor.ParseNewScanResultsMetadata(target, errors...)
}

func (tc *CmdResultsTableConverter) ParseViolations(target string, tech techutils.Technology, violations []services.Violation, applicabilityRuns ...*sarif.Run) (err error) {
	return tc.simpleJsonConvertor.ParseViolations(target, tech, violations, applicabilityRuns...)
}

func (tc *CmdResultsTableConverter) ParseVulnerabilities(target string, tech techutils.Technology, vulnerabilities []services.Vulnerability, applicabilityRuns ...*sarif.Run) (err error) {
	return tc.simpleJsonConvertor.ParseVulnerabilities(target, tech, vulnerabilities, applicabilityRuns...)
}

func (tc *CmdResultsTableConverter) ParseLicenses(target string, tech techutils.Technology, licenses []services.License) (err error) {
	return tc.simpleJsonConvertor.ParseLicenses(target, tech, licenses)
}

func (tc *CmdResultsTableConverter) ParseSecrets(target string, secrets ...*sarif.Run) (err error) {
	return tc.simpleJsonConvertor.ParseSecrets(target, secrets...)
}

func (tc *CmdResultsTableConverter) ParseIacs(target string, iacs ...*sarif.Run) (err error) {
	return tc.simpleJsonConvertor.ParseIacs(target, iacs...)
}

func (tc *CmdResultsTableConverter) ParseSast(target string, sast ...*sarif.Run) (err error) {
	return tc.simpleJsonConvertor.ParseSast(target, sast...)
}
