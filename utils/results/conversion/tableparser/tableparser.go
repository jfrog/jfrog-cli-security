package tableparser

import (
	"sort"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
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
		MaliciousVulnerabilitiesTable:  formats.ConvertToMaliciousTableRow(simpleJsonFormat.MaliciousVulnerabilities),
	}, nil
}

func (tc *CmdResultsTableConverter) Reset(metadata results.ResultsMetaData, statusCodes results.ResultsStatus, multipleTargets bool) (err error) {
	return tc.simpleJsonConvertor.Reset(metadata, statusCodes, multipleTargets)
}

func (tc *CmdResultsTableConverter) ParseNewTargetResults(target results.ScanTarget, errors ...error) (err error) {
	return tc.simpleJsonConvertor.ParseNewTargetResults(target, errors...)
}

func (tc *CmdResultsTableConverter) DeprecatedParseScaVulnerabilities(descriptors []string, scaResponse services.ScanResponse, applicableScan ...[]*sarif.Run) (err error) {
	return tc.simpleJsonConvertor.DeprecatedParseScaVulnerabilities(descriptors, scaResponse, applicableScan...)
}

func (tc *CmdResultsTableConverter) DeprecatedParseLicenses(scaResponse services.ScanResponse) (err error) {
	return tc.simpleJsonConvertor.DeprecatedParseLicenses(scaResponse)
}

func (tc *CmdResultsTableConverter) ParseSbomLicenses(sbom *cyclonedx.BOM) (err error) {
	return tc.simpleJsonConvertor.ParseSbomLicenses(sbom)
}

func (tc *CmdResultsTableConverter) ParseCVEs(enrichedSbom *cyclonedx.BOM, applicableScan ...[]*sarif.Run) (err error) {
	return tc.simpleJsonConvertor.ParseCVEs(enrichedSbom, applicableScan...)
}

func (tc *CmdResultsTableConverter) ParseViolations(violations violationutils.Violations) (err error) {
	return tc.simpleJsonConvertor.ParseViolations(violations)
}

func (tc *CmdResultsTableConverter) ParseSecrets(secrets ...[]*sarif.Run) (err error) {
	return tc.simpleJsonConvertor.ParseSecrets(secrets...)
}

func (tc *CmdResultsTableConverter) ParseIacs(iacs ...[]*sarif.Run) (err error) {
	return tc.simpleJsonConvertor.ParseIacs(iacs...)
}

func (tc *CmdResultsTableConverter) ParseSast(sast ...[]*sarif.Run) (err error) {
	return tc.simpleJsonConvertor.ParseSast(sast...)
}

func (tc *CmdResultsTableConverter) ParseMalicious(malicious ...[]*sarif.Run) (err error) {
	return tc.simpleJsonConvertor.ParseMalicious(malicious...)
}

func (tc *CmdResultsTableConverter) ParseSbom(sbom *cyclonedx.BOM) (err error) {
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
