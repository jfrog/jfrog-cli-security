package tableparser

import (
	"sort"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/simplejsonparser"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"

	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type CmdResultsTableConverter struct {
	simpleJsonConvertor *simplejsonparser.CmdResultsSimpleJsonConverter
	sbomRows            []formats.SbomTableRow
	// If supported, pretty print the output in the tables
	pretty bool
}

func NewCmdResultsTableConverter(pretty bool) *CmdResultsTableConverter {
	return &CmdResultsTableConverter{pretty: pretty, simpleJsonConvertor: simplejsonparser.NewCmdResultsSimpleJsonConverter(pretty, true), sbomRows: []formats.SbomTableRow{}}
}

func (tc *CmdResultsTableConverter) Get() (formats.ResultsTables, error) {
	simpleJsonFormat, err := tc.simpleJsonConvertor.Get()
	if err != nil {
		return formats.ResultsTables{}, err
	}
	sortSbom(tc.sbomRows)
	return formats.ResultsTables{
		LicensesTable: formats.ConvertToLicenseTableRow(simpleJsonFormat.Licenses),
		SbomTable:     tc.sbomRows,

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

func (tc *CmdResultsTableConverter) DeprecatedParseScaIssues(target results.ScanTarget, violations bool, scaResponse results.ScanResult[services.ScanResponse], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	return tc.simpleJsonConvertor.DeprecatedParseScaIssues(target, violations, scaResponse, applicableScan...)
}

func (tc *CmdResultsTableConverter) DeprecatedParseLicenses(target results.ScanTarget, scaResponse results.ScanResult[services.ScanResponse]) (err error) {
	return tc.simpleJsonConvertor.DeprecatedParseLicenses(target, scaResponse)
}

func (tc *CmdResultsTableConverter) ParseSbomLicenses(target results.ScanTarget, components []cyclonedx.Component, dependencies ...cyclonedx.Dependency) (err error) {
	return tc.simpleJsonConvertor.ParseSbomLicenses(target, components, dependencies...)
}

func (tc *CmdResultsTableConverter) ParseCVEs(target results.ScanTarget, enrichedSbom results.ScanResult[*cyclonedx.BOM], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	return tc.simpleJsonConvertor.ParseCVEs(target, enrichedSbom, applicableScan...)
}

func (tc *CmdResultsTableConverter) ParseViolations(target results.ScanTarget, violations []services.Violation, applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	return tc.simpleJsonConvertor.ParseViolations(target, violations, applicableScan...)
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

func (tc *CmdResultsTableConverter) ParseSbom(_ results.ScanTarget, sbom *cyclonedx.BOM) (err error) {
	if sbom == nil || sbom.Components == nil {
		return nil
	}
	err = results.ForEachSbomComponent(sbom, func(component cyclonedx.Component, relatedDependencies *cyclonedx.Dependency, relation cdxutils.ComponentRelation) error {
		if relation == cdxutils.UnknownRelation {
			if relation == cdxutils.UnknownRelation {
				log.Debug("Component %s (%s) has an unknown relation in the SBOM. It will not be included in the results table.", component.Name, component.PackageURL)
			}
			// No need to show the component as an entry
			return nil
		}
		relationStr := ""
		relationPriority := 0
		switch relation {
		case cdxutils.RootRelation:
			relationStr = "Root"
			relationPriority = 3
		case cdxutils.DirectRelation:
			relationStr = "Direct"
			relationPriority = 2
		case cdxutils.TransitiveRelation:
			relationStr = "Transitive"
			relationPriority = 1
		}
		compName, compVersion, compType := techutils.SplitPackageURL(component.PackageURL)
		tc.sbomRows = append(tc.sbomRows, formats.SbomTableRow{
			Component:   compName,
			Version:     compVersion,
			PackageType: techutils.ConvertXrayPackageType(compType),
			Relation:    relationStr,
			// For sorting
			RelationPriority: relationPriority,
		})
		return nil
	})
	return
}

func sortSbom(components []formats.SbomTableRow) {
	sort.Slice(components, func(i, j int) bool {
		if components[i].RelationPriority == components[j].RelationPriority {
			if components[i].Component == components[j].Component {
				if components[i].Version == components[j].Version {
					// Last order by type
					return components[i].PackageType < components[j].PackageType
				}
				// Third order by version
				return components[i].Version > components[j].Version
			}
			// Second order by component
			return components[i].Component < components[j].Component
		}
		// First order by direct components
		return components[i].RelationPriority > components[j].RelationPriority
	})
}
