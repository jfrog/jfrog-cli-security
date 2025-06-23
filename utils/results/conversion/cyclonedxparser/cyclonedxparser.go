package cyclonedxparser

import (
	"fmt"
	"os"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

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
	bom            *cyclonedx.BOM
	entitledForJas bool
}

func NewCmdResultsCycloneDxConverter() *CmdResultsCycloneDxConverter {
	return &CmdResultsCycloneDxConverter{}
}

func (cdc *CmdResultsCycloneDxConverter) Get() (*cyclonedx.BOM, error) {
	if cdc.bom == nil {
		return cyclonedx.NewBOM(), nil
	}
	return cdc.bom, nil
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
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseNewTargetResults(target results.ScanTarget, errors ...error) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	component := cdxutils.CreateFileOrDirComponent(target.Target)
	if cdc.bom.Metadata.Component == nil {
		// Single target
		cdc.bom.Metadata.Component = &component
		return
	}
	// Multiple targets
	if cdc.bom.Metadata.Component.Components == nil || len(*cdc.bom.Metadata.Component.Components) == 0 {
		if cdc.bom.Metadata.Component.BOMRef == component.BOMRef {
			// The component is already in the BOM
			return
		}
		// The component is not in the BOM, Convert from single target to multiple targets
		if currentWd, e := os.Getwd(); e != nil {
			return e
		} else {
			wdComponent := cdxutils.CreateFileOrDirComponent(currentWd)
			// Add the old main component as a sub-component
			wdComponent.Components = &[]cyclonedx.Component{*cdc.bom.Metadata.Component}
			// Set the current working directory as the main component
			cdc.bom.Metadata.Component = &wdComponent
		}
	}
	for _, existingComponent := range *cdc.bom.Metadata.Component.Components {
		if existingComponent.BOMRef == component.BOMRef {
			// The component is already in the BOM
			return
		}
	}
	// The component is not in the BOM, Add the new sub-component
	*cdc.bom.Metadata.Component.Components = append(*cdc.bom.Metadata.Component.Components, component)
	return
}

func (cdc *CmdResultsCycloneDxConverter) DeprecatedParseScaIssues(target results.ScanTarget, violations bool, scaResponse results.ScanResult[services.ScanResponse], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	return
}

func (cdc *CmdResultsCycloneDxConverter) DeprecatedParseLicenses(target results.ScanTarget, scaResponse results.ScanResult[services.ScanResponse]) (err error) {
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseSbom(target results.ScanTarget, sbom *cyclonedx.BOM) (err error) {
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
		return nil
	}
	// return
	source := cdc.addJasService(iacs)
	return results.ForEachJasIssue(results.ScanResultsToRuns(iacs), cdc.entitledForJas, func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) (e error) {
		// Create or get the affected component
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
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseViolations(target results.ScanTarget, violations []services.Violation, applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	return
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
