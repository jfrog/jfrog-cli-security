package cyclonedxparser

import (
	"fmt"
	"os"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
)

const (
	// <FILE_REF>#L<START_LINE>C<START_COLUMN>-L<END_LINE>C<END_COLUMN>
	locationIdTemplate = "%s#L%dC%d-L%dC%d"
	// <SCAN_TYPE> + locationIdTemplate
	jasIssueLocationPropertyTemplate = "jfrog:%s:location:" + locationIdTemplate
)

type CmdResultsCycloneDxConverter struct {
	entitledForJas bool

	targetsComponent map[string]cyclonedx.Component
	bom              *cyclonedx.BOM
}

func NewCmdResultsCycloneDxConverter() *CmdResultsCycloneDxConverter {
	return &CmdResultsCycloneDxConverter{}
}

func (cdc *CmdResultsCycloneDxConverter) Get() (bom *cyclonedx.BOM, err error) {
	if cdc.bom == nil {
		return cyclonedx.NewBOM(), nil
	}
	bom = cdc.bom
	bom.Metadata.Component, err = cdc.getMetadataComponent()
	return
}

func (cdc *CmdResultsCycloneDxConverter) Reset(cmdType utils.CommandType, multiScanId, xrayVersion string, entitledForJas, multipleTargets bool, generalError error) (err error) {
	cdc.entitledForJas = entitledForJas
	// Reset the BOM
	cdc.bom = cyclonedx.NewBOM()
	cdc.bom.SerialNumber = cdxutils.GetSerialNumber(multiScanId)
	cdc.bom.Metadata = &cyclonedx.Metadata{
		Timestamp: time.Now().Format(time.RFC3339),
		Authors:   &[]cyclonedx.OrganizationalContact{{Name: "JFrog"}},
	}
	cdc.targetsComponent = make(map[string]cyclonedx.Component)
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseNewTargetResults(target results.ScanTarget, errors ...error) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	cdc.setTargetComponent(target.Target, cdxutils.CreateFileOrDirComponent(target.Target))
	return
}

func (cdc *CmdResultsCycloneDxConverter) DeprecatedParseScaIssues(target results.ScanTarget, violations bool, scaResponse results.ScanResult[services.ScanResponse], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	return
}

func (cdc *CmdResultsCycloneDxConverter) DeprecatedParseLicenses(target results.ScanTarget, scaResponse results.ScanResult[services.ScanResponse]) (err error) {
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseSbom(_ results.ScanTarget, sbom *cyclonedx.BOM) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	if sbom == nil {
		return
	}
	// Append the information from the sbom to the current BOM
	cdc.appendMetadata(sbom.Metadata)
	cdc.appendComponents(sbom.Components)
	cdc.appendDependencies(sbom.Dependencies)
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseSbomLicenses(target results.ScanTarget, components []cyclonedx.Component, dependencies ...cyclonedx.Dependency) (err error) {
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseCVEs(target results.ScanTarget, enrichedSbom results.ScanResult[*cyclonedx.BOM], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseSecrets(target results.ScanTarget, violations bool, secrets []results.ScanResult[[]*sarif.Run]) (err error) {
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseIacs(target results.ScanTarget, violations bool, iacs []results.ScanResult[[]*sarif.Run]) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	if violations {
		// IAC violations are not supported in CycloneDX
		log.Debug("IAC violations are not supported in CycloneDX. Skipping IAC violations parsing.")
		return nil
	}
	// return
	source := cdc.addJasService(iacs)
	return results.ForEachJasIssue(results.ScanResultsToRuns(iacs), cdc.entitledForJas, func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) (e error) {
		affectedComponent := cdc.getOrCreateJasComponent(getRelativePath(location, target))
		// Create a new JAS vulnerability, add it to the BOM and return it
		ratings := []cyclonedx.VulnerabilityRating{severityutils.CreateSeverityRating(severity, jasutils.Applicable, source)}
		jasIssue := cdc.getOrCreateJasIssue(sarifutils.GetResultRuleId(result), sarifutils.GetRuleScannerId(rule), sarifutils.GetResultMsgText(result), sarifutils.GetRuleShortDescriptionText(rule), source, sarifutils.GetRuleCWE(rule), ratings)
		// Add the location to the vulnerability
		addFileIssueAffects(jasIssue, *affectedComponent, cyclonedx.Property{
			Name: fmt.Sprintf(
				jasIssueLocationPropertyTemplate, "iac", affectedComponent.BOMRef,
				sarifutils.GetLocationStartLine(location), sarifutils.GetLocationStartColumn(location), sarifutils.GetLocationEndLine(location), sarifutils.GetLocationEndColumn(location),
			),
			Value: sarifutils.GetLocationSnippetText(location),
		})
		return
	})
}

func (cdc *CmdResultsCycloneDxConverter) ParseSast(target results.ScanTarget, violations bool, sast []results.ScanResult[[]*sarif.Run]) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	if violations {
		// IAC violations are not supported in CycloneDX
		log.Debug("SAST violations are not supported in CycloneDX. Skipping SAST violations parsing.")
		return nil
	}
	source := cdc.addJasService(sast)
	return results.ForEachJasIssue(results.ScanResultsToRuns(sast), cdc.entitledForJas, func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) (e error) {
		affectedComponent := cdc.getOrCreateJasComponent(getRelativePath(location, target))
		// Create a new JAS vulnerability, add it to the BOM and return it
		ratings := []cyclonedx.VulnerabilityRating{severityutils.CreateSeverityRating(severity, jasutils.Applicable, source)}
		jasIssue := cdc.getOrCreateJasIssue(sarifutils.GetResultRuleId(result), sarifutils.GetRuleScannerId(rule), sarifutils.GetResultMsgText(result), sarifutils.GetRuleShortDescriptionText(rule), source, sarifutils.GetRuleCWE(rule), ratings)
		// Add the location to the vulnerability
		addFileIssueAffects(jasIssue, *affectedComponent, cyclonedx.Property{
			Name: fmt.Sprintf(
				jasIssueLocationPropertyTemplate, "sast", affectedComponent.BOMRef,
				sarifutils.GetLocationStartLine(location), sarifutils.GetLocationStartColumn(location), sarifutils.GetLocationEndLine(location), sarifutils.GetLocationEndColumn(location),
			),
			Value: sarifutils.GetLocationSnippetText(location),
		})
		return
	})
}

func (cdc *CmdResultsCycloneDxConverter) ParseViolations(target results.ScanTarget, violations []services.Violation, applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	// Violations are not supported in CycloneDX
	log.Debug("Violations are not supported in CycloneDX. Skipping violations parsing.")
	return
}

func (cdc *CmdResultsCycloneDxConverter) getMetadataComponent() (component *cyclonedx.Component, err error) {
	if len(cdc.targetsComponent) == 0 {
		// No targets
		return
	}
	if len(cdc.targetsComponent) == 1 {
		for _, target := range cdc.targetsComponent {
			// Single target - return the only component
			return &target, nil
		}
	}
	// Multiple targets, main component is the current working directory
	currentWd, err := os.Getwd()
	if err != nil {
		return
	}
	wdComponent := cdxutils.CreateFileOrDirComponent(currentWd)
	for _, target := range cdc.targetsComponent {
		if target.BOMRef == wdComponent.BOMRef {
			// The current working directory is already the main component
			continue
		}
		if wdComponent.Components == nil {
			wdComponent.Components = &[]cyclonedx.Component{}
		}
		// Add the target component as a sub-component of the current working directory
		*wdComponent.Components = append(*wdComponent.Components, target)
	}
	component = &wdComponent
	return
}

func (cdc *CmdResultsCycloneDxConverter) appendMetadata(metadata *cyclonedx.Metadata) {
	if metadata == nil {
		return
	}
	if metadata.Tools != nil && metadata.Tools.Services != nil && len(*metadata.Tools.Services) > 0 {
		for _, service := range *metadata.Tools.Services {
			cdxutils.AddServiceToBomIfNotExists(cdc.bom, service)
		}
	}
	// Resolve the target path from the SBOM metadata component if it exists and set it as the target component.
	if metadata.Component != nil && metadata.Component.Type == cyclonedx.ComponentTypeFile {
		cdc.setTargetComponent(metadata.Component.Name, *metadata.Component)
	}
}

func (cdc *CmdResultsCycloneDxConverter) setTargetComponent(target string, component cyclonedx.Component) {
	cdc.targetsComponent[target] = component
}

func (cdc *CmdResultsCycloneDxConverter) addJasService(runs []results.ScanResult[[]*sarif.Run]) (service *cyclonedx.Service) {
	for _, runInfo := range runs {
		for _, run := range runInfo.Scan {
			// Add tool if missing
			if run == nil || run.Tool.Driver == nil {
				continue
			}
			service = &cyclonedx.Service{
				Name:    sarifutils.GetRunToolName(run),
				Version: sarifutils.GetToolVersion(run),
			}
			cdxutils.AddServiceToBomIfNotExists(cdc.bom, *service)
		}
	}
	return
}

func (cdc *CmdResultsCycloneDxConverter) appendComponents(components *[]cyclonedx.Component) {
	if cdc.bom == nil || components == nil || len(*components) == 0 {
		// No components to append
		return
	}
	if cdc.bom.Components == nil {
		cdc.bom.Components = &[]cyclonedx.Component{}
	}
	for _, component := range *components {
		if cdxutils.SearchComponentByRef(cdc.bom.Components, component.BOMRef) != nil {
			// The component is already in the BOM
			continue
		}
		// Append the component to the BOM
		*cdc.bom.Components = append(*cdc.bom.Components, component)
	}
}

func (cdc *CmdResultsCycloneDxConverter) appendDependencies(dependencies *[]cyclonedx.Dependency) {
	if cdc.bom == nil || dependencies == nil || len(*dependencies) == 0 {
		// No dependencies to append
		return
	}
	if cdc.bom.Dependencies == nil {
		cdc.bom.Dependencies = &[]cyclonedx.Dependency{}
	}
	for _, dependency := range *dependencies {
		if cdxutils.SearchDependencyEntry(cdc.bom.Dependencies, dependency.Ref) != nil {
			// The dependency is already in the BOM
			continue
		}
		// Append the dependency to the BOM
		*cdc.bom.Dependencies = append(*cdc.bom.Dependencies, dependency)
	}
}

func (cdc *CmdResultsCycloneDxConverter) getOrCreateJasComponent(filePathOrUri string) (component *cyclonedx.Component) {
	if component = cdxutils.SearchComponentByRef(cdc.bom.Components, cdxutils.GetFileRef(filePathOrUri)); component != nil {
		return
	}
	if cdc.bom.Components == nil {
		cdc.bom.Components = &[]cyclonedx.Component{}
	}
	*cdc.bom.Components = append(*cdc.bom.Components, cdxutils.CreateFileOrDirComponent(filePathOrUri))
	return &(*cdc.bom.Components)[len(*cdc.bom.Components)-1]
}

func (cdc *CmdResultsCycloneDxConverter) getOrCreateJasIssue(ref, id, msg, description string, source *cyclonedx.Service, cwe []string, ratings []cyclonedx.VulnerabilityRating, properties ...cyclonedx.Property) (vulnerability *cyclonedx.Vulnerability) {
	if vulnerability = cdxutils.SearchVulnerabilityByRef(cdc.bom, ref); vulnerability != nil {
		return
	}
	// Create a new SCA vulnerability, add it to the BOM and return it
	if cdc.bom.Vulnerabilities == nil {
		cdc.bom.Vulnerabilities = &[]cyclonedx.Vulnerability{}
	}
	params := cdxutils.CdxVulnerabilityParams{
		Ref:         ref,
		ID:          id,
		Description: description,
		Details:     msg,
		Service:     source,
		CWE:         cwe,
		Ratings:     ratings,
	}
	*cdc.bom.Vulnerabilities = append(*cdc.bom.Vulnerabilities, cdxutils.CreateBaseVulnerability(params, properties...))
	return &(*cdc.bom.Vulnerabilities)[len(*cdc.bom.Vulnerabilities)-1]
}

func addFileIssueAffects(issue *cyclonedx.Vulnerability, fileComponent cyclonedx.Component, properties ...cyclonedx.Property) {
	cdxutils.AttachComponentAffects(issue, fileComponent, func(affectedComponent cyclonedx.Component) cyclonedx.Affects {
		return cyclonedx.Affects{Ref: affectedComponent.BOMRef}
	}, properties...)
}

func getRelativePath(location *sarif.Location, target results.ScanTarget) (relativePath string) {
	return sarifutils.ExtractRelativePath(sarifutils.GetLocationFileName(location), target.Target)
}
