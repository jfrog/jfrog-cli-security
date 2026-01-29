package cyclonedxparser

import (
	"fmt"
	"os"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xscServices "github.com/jfrog/jfrog-client-go/xsc/services"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
)

const (
	// When template is used, provide <SCAN_TYPE>, locationIdTemplate
	jasIssueLocationPropertyTemplate = "jfrog:%s:location:" + results.LocationIdTemplate
	// Properties for secret validation
	secretValidationPropertyTemplate         = "jfrog:secret-validation:status:" + results.LocationIdTemplate
	secretValidationMetadataPropertyTemplate = "jfrog:secret-validation:metadata:" + results.LocationIdTemplate
	// Git context property
	gitContextProperty = "jfrog:git:context"
)

type CmdResultsCycloneDxConverter struct {
	entitledForJas                 bool
	gitContext                     *xscServices.XscGitInfoContext
	xrayVersion                    string
	parseSastResultDirectlyIntoCDX bool

	targetsComponent map[string]cyclonedx.Component
	currentTarget    results.ScanTarget
	bom              *cdxutils.FullBOM
}

func NewCmdResultsCycloneDxConverter(parseSast bool) *CmdResultsCycloneDxConverter {
	return &CmdResultsCycloneDxConverter{
		parseSastResultDirectlyIntoCDX: parseSast,
	}
}

func (cdc *CmdResultsCycloneDxConverter) Get() (bom *cdxutils.FullBOM, err error) {
	if cdc.bom == nil {
		return &cdxutils.FullBOM{BOM: *cyclonedx.NewBOM()}, nil
	}
	bom = cdc.bom
	bom.Metadata.Component, err = cdc.getMetadataComponent()
	// Append git context to the BOM metadata if exists
	if cdc.gitContext != nil {
		if gitContextStr, err := utils.GetAsJsonString(cdc.gitContext, true, true); err != nil {
			log.Warn("Failed to serialize git context to JSON: %v", err)
		} else {
			bom.Metadata.Component.Properties = cdxutils.AppendProperties(bom.Metadata.Component.Properties, cyclonedx.Property{
				Name:  gitContextProperty,
				Value: gitContextStr,
			})
		}
	}
	return
}

func (cdc *CmdResultsCycloneDxConverter) Reset(metadata results.ResultsMetaData, statusCodes results.ResultsStatus, multipleTargets bool) (err error) {
	cdc.entitledForJas = metadata.EntitledForJas
	cdc.gitContext = metadata.GitContext
	cdc.xrayVersion = metadata.XrayVersion
	// Reset the BOM
	cdc.bom = &cdxutils.FullBOM{BOM: *cyclonedx.NewBOM()}
	cdc.bom.SerialNumber = cdxutils.GetSerialNumber(metadata.MultiScanId)
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
	cdc.currentTarget = target
	cdc.setTargetComponent(target.Target, cdxutils.CreateFileOrDirComponent(target.Target))
	return
}

func (cdc *CmdResultsCycloneDxConverter) DeprecatedParseScaVulnerabilities(descriptors []string, scaResponse services.ScanResponse, applicableScan ...[]*sarif.Run) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	cdc.addXrayToolIfMissing()
	cdc.addJasService(applicableScan)
	return results.ForEachScanGraphVulnerability(cdc.currentTarget, descriptors, scaResponse.Vulnerabilities, cdc.entitledForJas, results.CollectRuns(applicableScan...), results.ParseScanGraphVulnerabilityToSbom(&cdc.bom.BOM))
}

func (cdc *CmdResultsCycloneDxConverter) DeprecatedParseLicenses(scaResponse services.ScanResponse) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	cdc.addXrayToolIfMissing()
	return results.ForEachLicense(cdc.currentTarget, scaResponse.Licenses, results.ParseScanGraphLicenseToSbom(&cdc.bom.BOM))
}

func (cdc *CmdResultsCycloneDxConverter) ParseSbom(sbom *cyclonedx.BOM) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	if sbom == nil {
		return
	}
	// Append the information from the sbom to the current BOM
	cdc.appendMetadata(sbom.Metadata)
	cdxutils.AppendComponents(&cdc.bom.BOM, sbom.Components)
	cdxutils.AppendDependencies(&cdc.bom.BOM, sbom.Dependencies)
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseSbomLicenses(_ *cyclonedx.BOM) (err error) {
	// In CycloneDX, licenses are part of the components and dependencies, so we don't need to parse them separately.
	return nil
}

func (cdc *CmdResultsCycloneDxConverter) ParseCVEs(enrichedSbom *cyclonedx.BOM, applicableScan ...[]*sarif.Run) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	if enrichedSbom == nil || enrichedSbom.Vulnerabilities == nil || len(*enrichedSbom.Vulnerabilities) == 0 {
		// No vulnerabilities to parse
		return
	}
	cdc.addJasService(applicableScan)
	return results.ForEachScaBomVulnerability(cdc.currentTarget, enrichedSbom, cdc.entitledForJas, results.CollectRuns(applicableScan...),
		func(vulnToParse cyclonedx.Vulnerability, compToParse cyclonedx.Component, fixedVersion *[]cyclonedx.AffectedVersions, applicability *formats.Applicability, severity severityutils.Severity) (e error) {
			// Add the vulnerability related component if it is not already existing
			cdc.getOrCreateScaComponent(compToParse)
			// Add the vulnerability to the BOM if it is not already existing
			vulnerability := cdc.getOrCreateScaIssue(vulnToParse)
			// Attach JAS information to the vulnerability
			results.AttachApplicabilityToVulnerability(&cdc.bom.BOM, vulnerability, applicability)
			return
		},
	)
}

func (cdc *CmdResultsCycloneDxConverter) ParseSecrets(secrets ...[]*sarif.Run) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	source := cdc.addJasService(secrets)
	return results.ForEachJasIssue(results.CollectRuns(secrets...), cdc.entitledForJas, func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) (e error) {
		startLine := sarifutils.GetLocationStartLine(location)
		startColumn := sarifutils.GetLocationStartColumn(location)
		endLine := sarifutils.GetLocationEndLine(location)
		endColumn := sarifutils.GetLocationEndColumn(location)
		// Create or get the affected component
		affectedComponent := cdc.getOrCreateFileComponent(getRelativePath(location, cdc.currentTarget))
		// Create a new JAS vulnerability, add it to the BOM and return it
		properties := []cyclonedx.Property{}
		applicabilityStatus := jasutils.NotScanned
		if secretValidation := results.GetJasResultApplicability(result); secretValidation != nil {
			// Secret validation results exist
			applicabilityStatus = jasutils.ConvertToApplicabilityStatus(secretValidation.Status)
			properties = append(properties, cyclonedx.Property{
				Name:  fmt.Sprintf(secretValidationPropertyTemplate, affectedComponent.BOMRef, startLine, startColumn, endLine, endColumn),
				Value: secretValidation.Status,
			})
			if secretValidation.ScannerDescription != "" {
				properties = append(properties, cyclonedx.Property{
					Name:  fmt.Sprintf(secretValidationMetadataPropertyTemplate, affectedComponent.BOMRef, startLine, startColumn, endLine, endColumn),
					Value: secretValidation.ScannerDescription,
				})
			}
		}
		ratings := []cyclonedx.VulnerabilityRating{severityutils.CreateSeverityRating(severity, applicabilityStatus, source)}
		jasIssue := cdc.getOrCreateJasIssue(sarifutils.GetResultRuleId(result), getSecretScannerRuleId(rule), sarifutils.GetResultMsgText(result), sarifutils.GetRuleShortDescriptionText(rule), source, sarifutils.GetRuleCWE(rule), ratings)
		// Add the location to the vulnerability
		properties = append(properties, cyclonedx.Property{
			Name:  fmt.Sprintf(jasIssueLocationPropertyTemplate, "secret", affectedComponent.BOMRef, startLine, startColumn, endLine, endColumn),
			Value: sarifutils.GetLocationSnippetText(location),
		})
		results.AddFileIssueAffects(jasIssue, *affectedComponent, properties...)
		return
	})
}

func getSecretScannerRuleId(rule *sarif.ReportingDescriptor) string {
	ruleId := sarifutils.GetRuleScannerId(rule)
	if ruleId == "" {
		return ""
	}
	return fmt.Sprintf("EXP-%s", ruleId)
}

func (cdc *CmdResultsCycloneDxConverter) ParseIacs(iacs ...[]*sarif.Run) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	// return
	source := cdc.addJasService(iacs)
	return results.ForEachJasIssue(results.CollectRuns(iacs...), cdc.entitledForJas, func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) (e error) {
		affectedComponent := cdc.getOrCreateFileComponent(getRelativePath(location, cdc.currentTarget))
		// Create a new JAS vulnerability, add it to the BOM and return it
		ratings := []cyclonedx.VulnerabilityRating{severityutils.CreateSeverityRating(severity, jasutils.Applicable, source)}
		jasIssue := cdc.getOrCreateJasIssue(sarifutils.GetResultRuleId(result), sarifutils.GetRuleScannerId(rule), sarifutils.GetResultMsgText(result), sarifutils.GetRuleShortDescriptionText(rule), source, sarifutils.GetRuleCWE(rule), ratings)
		// Add the location to the vulnerability
		results.AddFileIssueAffects(jasIssue, *affectedComponent, cyclonedx.Property{
			Name: fmt.Sprintf(
				jasIssueLocationPropertyTemplate, "iac", affectedComponent.BOMRef,
				sarifutils.GetLocationStartLine(location), sarifutils.GetLocationStartColumn(location), sarifutils.GetLocationEndLine(location), sarifutils.GetLocationEndColumn(location),
			),
			Value: sarifutils.GetLocationSnippetText(location),
		})
		return
	})
}

func (cdc *CmdResultsCycloneDxConverter) ParseMalicious(malicious ...[]*sarif.Run) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	source := cdc.addJasService(malicious)
	return results.ForEachJasIssue(results.CollectRuns(malicious...), cdc.entitledForJas, func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) (e error) {
		affectedComponent := cdc.getOrCreateFileComponent(getRelativePath(location, cdc.currentTarget))
		// Create a new JAS vulnerability, add it to the BOM and return it
		ratings := []cyclonedx.VulnerabilityRating{severityutils.CreateSeverityRating(severity, jasutils.Applicable, source)}
		jasIssue := cdc.getOrCreateJasIssue(sarifutils.GetResultRuleId(result), sarifutils.GetRuleScannerId(rule), sarifutils.GetResultMsgText(result), sarifutils.GetRuleShortDescriptionText(rule), source, sarifutils.GetRuleCWE(rule), ratings)
		// Add the location to the vulnerability
		results.AddFileIssueAffects(jasIssue, *affectedComponent, cyclonedx.Property{
			Name: fmt.Sprintf(
				jasIssueLocationPropertyTemplate, "malicious-code", affectedComponent.BOMRef,
				sarifutils.GetLocationStartLine(location), sarifutils.GetLocationStartColumn(location), sarifutils.GetLocationEndLine(location), sarifutils.GetLocationEndColumn(location),
			),
			Value: sarifutils.GetLocationSnippetText(location),
		})
		return
	})
}

func (cdc *CmdResultsCycloneDxConverter) ParseSast(sast ...[]*sarif.Run) (err error) {
	if cdc.bom == nil {
		return results.ErrResetConvertor
	}
	source := cdc.addJasService(sast)
	if !cdc.parseSastResultDirectlyIntoCDX {
		// SAST parsing is disabled, add the runs without parsing the issues
		cdc.bom.Sast = append(cdc.bom.Sast, results.CollectRuns(sast...)...)
		return
	}
	return results.ForEachJasIssue(results.CollectRuns(sast...), cdc.entitledForJas, func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) (e error) {
		affectedComponent := cdc.getOrCreateFileComponent(getRelativePath(location, cdc.currentTarget))
		// Create a new JAS vulnerability, add it to the BOM and return it
		ratings := []cyclonedx.VulnerabilityRating{severityutils.CreateSeverityRating(severity, jasutils.Applicable, source)}
		jasIssue := cdc.getOrCreateJasIssue(sarifutils.GetResultRuleId(result), sarifutils.GetRuleScannerId(rule), sarifutils.GetResultMsgText(result), sarifutils.GetRuleShortDescriptionText(rule), source, sarifutils.GetRuleCWE(rule), ratings)
		// Add the location to the vulnerability
		results.AddFileIssueAffects(jasIssue, *affectedComponent, cyclonedx.Property{
			Name: fmt.Sprintf(
				jasIssueLocationPropertyTemplate, "sast", affectedComponent.BOMRef,
				sarifutils.GetLocationStartLine(location), sarifutils.GetLocationStartColumn(location), sarifutils.GetLocationEndLine(location), sarifutils.GetLocationEndColumn(location),
			),
			Value: sarifutils.GetLocationSnippetText(location),
		})
		return
	})
}

func (cdc *CmdResultsCycloneDxConverter) ParseViolations(violations violationutils.Violations) (err error) {
	// Violations are not supported in CycloneDX
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
			cdxutils.AddServiceToBomIfNotExists(&cdc.bom.BOM, service)
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

func (cdc *CmdResultsCycloneDxConverter) addJasService(runs [][]*sarif.Run) (service *cyclonedx.Service) {
	for _, runInfo := range runs {
		for _, run := range runInfo {
			// Add tool if missing
			if run == nil || run.Tool.Driver == nil {
				continue
			}
			service = &cyclonedx.Service{
				Name:    sarifutils.GetRunToolName(run),
				Version: sarifutils.GetToolVersion(run),
			}
			cdxutils.AddServiceToBomIfNotExists(&cdc.bom.BOM, *service)
		}
	}
	return
}

func (cdc *CmdResultsCycloneDxConverter) getOrCreateFileComponent(filePathOrUri string) (component *cyclonedx.Component) {
	if component = cdxutils.SearchComponentByRef(cdc.bom.Components, cdxutils.GetFileRef(filePathOrUri)); component != nil {
		return
	}
	if cdc.bom.Components == nil {
		cdc.bom.Components = &[]cyclonedx.Component{}
	}
	*cdc.bom.Components = append(*cdc.bom.Components, cdxutils.CreateFileOrDirComponent(filePathOrUri))
	return &(*cdc.bom.Components)[len(*cdc.bom.Components)-1]
}

func (cdc *CmdResultsCycloneDxConverter) getOrCreateJasIssue(ref, id, msg, description string, source *cyclonedx.Service, cwe []string, ratings []cyclonedx.VulnerabilityRating) (vulnerability *cyclonedx.Vulnerability) {
	if vulnerability = cdxutils.SearchVulnerabilityByRef(&cdc.bom.BOM, ref); vulnerability != nil {
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
	*cdc.bom.Vulnerabilities = append(*cdc.bom.Vulnerabilities, cdxutils.CreateBaseVulnerability(params))
	return &(*cdc.bom.Vulnerabilities)[len(*cdc.bom.Vulnerabilities)-1]
}

func (cdc *CmdResultsCycloneDxConverter) getOrCreateScaComponent(compToParse cyclonedx.Component) (component *cyclonedx.Component) {
	if component = cdxutils.SearchComponentByRef(cdc.bom.Components, compToParse.BOMRef); component != nil {
		// The component is already in the BOM
		return
	}
	// The component is not in the BOM, add it
	if cdc.bom.Components == nil {
		cdc.bom.Components = &[]cyclonedx.Component{}
	}
	*cdc.bom.Components = append(*cdc.bom.Components, compToParse)
	return &(*cdc.bom.Components)[len(*cdc.bom.Components)-1]
}

func (cdc *CmdResultsCycloneDxConverter) getOrCreateScaIssue(vulnToParse cyclonedx.Vulnerability) (vulnerability *cyclonedx.Vulnerability) {
	if vulnerability = cdxutils.SearchVulnerabilityByRef(&cdc.bom.BOM, vulnToParse.BOMRef); vulnerability != nil {
		return
	}
	// Add the vulnerability to the BOM
	if cdc.bom.Vulnerabilities == nil {
		cdc.bom.Vulnerabilities = &[]cyclonedx.Vulnerability{}
	}
	*cdc.bom.Vulnerabilities = append(*cdc.bom.Vulnerabilities, vulnToParse)
	vulnerability = &(*cdc.bom.Vulnerabilities)[len(*cdc.bom.Vulnerabilities)-1]
	// Ensure the source is set for the vulnerability
	if vulnerability.Source == nil {
		vulnerability.Source = &cyclonedx.Source{Name: cdc.addXrayToolIfMissing().Name}
	} else if source := cdxutils.SearchForServiceByName(&cdc.bom.BOM, vulnerability.Source.Name); source == nil {
		cdxutils.AddServiceToBomIfNotExists(&cdc.bom.BOM, cyclonedx.Service{Name: vulnerability.Source.Name})
	}
	return
}

func (cdc *CmdResultsCycloneDxConverter) addXrayToolIfMissing() (service *cyclonedx.Service) {
	if service = cdxutils.SearchForServiceByName(&cdc.bom.BOM, utils.XrayToolName); service != nil || cdc.bom == nil {
		// The service is already in the BOM
		return
	}
	service = &cyclonedx.Service{
		Name:    utils.XrayToolName,
		Version: cdc.xrayVersion,
	}
	cdxutils.AddServiceToBomIfNotExists(&cdc.bom.BOM, *service)
	return
}

func getRelativePath(location *sarif.Location, target results.ScanTarget) (relativePath string) {
	return utils.GetRelativePath(sarifutils.GetLocationFileName(location), utils.ToURI(target.Target))
}
