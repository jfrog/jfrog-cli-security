package tableparser

import (
	"sort"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/exp/maps"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/simplejsonparser"

	"github.com/jfrog/jfrog-client-go/xray/services"
)

type CmdResultsTableConverter struct {
	simpleJsonConvertor *simplejsonparser.CmdResultsSimpleJsonConverter
	sbomInfo            map[string]results.SbomEntry
	// If supported, pretty print the output in the tables
	pretty bool
}

func NewCmdResultsTableConverter(pretty bool) *CmdResultsTableConverter {
	return &CmdResultsTableConverter{pretty: pretty, simpleJsonConvertor: simplejsonparser.NewCmdResultsSimpleJsonConverter(pretty, true), sbomInfo: make(map[string]results.SbomEntry)}
}

func (tc *CmdResultsTableConverter) Get() (formats.ResultsTables, error) {
	simpleJsonFormat, err := tc.simpleJsonConvertor.Get()
	if err != nil {
		return formats.ResultsTables{}, err
	}
	return formats.ResultsTables{
		LicensesTable: formats.ConvertToLicenseTableRow(simpleJsonFormat.Licenses),
		SbomTable:     convertToSbomTableRow(maps.Values(tc.sbomInfo)),

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

func (tc *CmdResultsTableConverter) ParseIacs(target results.ScanTarget, isViolationsResults bool, iacs []results.ScanResult[[]*sarif.Run]) (err error) {
	return tc.simpleJsonConvertor.ParseIacs(target, isViolationsResults, iacs)
}

func (tc *CmdResultsTableConverter) ParseSast(target results.ScanTarget, isViolationsResults bool, sast []results.ScanResult[[]*sarif.Run]) (err error) {
	return tc.simpleJsonConvertor.ParseSast(target, isViolationsResults, sast)
}

func (tc *CmdResultsTableConverter) ParseSbom(target results.ScanTarget, sbom results.Sbom) (err error) {
	for _, entry := range sbom.Components {
		if parsedEntry, exists := tc.sbomInfo[entry.String()]; exists {
			if entry.Direct && !parsedEntry.Direct {
				// If the entry is direct, we want to override the existing entry
				tc.sbomInfo[entry.String()] = entry
			}
			continue
		}
		// If the entry does not exist, we want to add it
		tc.sbomInfo[entry.String()] = entry
	}
	return
}

func convertToSbomTableRow(rows []results.SbomEntry) (tableRows []formats.SbomTableRow) {
	for _, entry := range rows {
		tableRows = append(tableRows, formats.SbomTableRow{
			Component:   entry.Component,
			PackageType: entry.Type,
			Direct:      entry.Direct,
			Version:     entry.Version,
		})
	}
	// Sort the table by direct dependencies, then by component name
	sort.Slice(tableRows, func(i, j int) bool {
		if tableRows[i].Direct == tableRows[j].Direct {
			return tableRows[i].Component < tableRows[j].Component
		}
		return tableRows[i].Direct
	})
	return
}
