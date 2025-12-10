package remediation

import (
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray"
	"github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
)

func AttachFixedVersionsToVulnerabilities(xrayManager *xray.XrayServicesManager, bom *cyclonedx.BOM) error {
	if bom.Vulnerabilities == nil || len(*bom.Vulnerabilities) == 0 {
		log.Debug("No vulnerabilities found in the SBOM, skipping attaching fixed versions")
		return nil
	}
	// Remediate the CVE by forcing the transitive dependency to a specific fix-version
	remediationOptions, err := xrayManager.RemediationByCve(bom)
	if err != nil {
		return fmt.Errorf("failed to get remediation options from Xray: %w", err)
	}
	log.Verbose(fmt.Sprintf("Remediation options received from Xray: %+v", remediationOptions))
	// Right now, we only support QuickestFixStrategy (fixing the actual component to a specific version)
	strategy := utils.QuickestFixStrategy
	for _, vulnerability := range *bom.Vulnerabilities {
		matchVulnerabilityToRemediationOptions(bom, &vulnerability, remediationOptions, strategy)
	}
	return nil
}

func matchVulnerabilityToRemediationOptions(bom *cyclonedx.BOM, vulnerability *cyclonedx.Vulnerability, remediationOptions utils.CveRemediationResponse, strategy utils.FixStrategy) {
	if vulnerability.Affects == nil || len(*vulnerability.Affects) == 0 {
		log.Debug("No affected components found for vulnerability " + vulnerability.ID + ", skipping attaching fixed versions")
		return
	}
	if cveRemediationOptions, found := remediationOptions[vulnerability.ID]; found {
		for i, affect := range *vulnerability.Affects {
			// Lets find the remediation for this specific component
			affectComponent := cdxutils.SearchComponentByRef(bom.Components, affect.Ref)
			if affectComponent == nil {
				log.Debug("Affected component " + affect.Ref + " not found in BOM components, skipping attaching fixed versions for vulnerability " + vulnerability.ID)
				continue
			}
			// Convert remediation steps to fixed versions affected versions
			for _, step := range getAffectComponentCveRemediationStepsByFixedVersion(vulnerability.ID, *affectComponent, cveRemediationOptions, strategy) {
				cdxutils.AppendAffectedVersionsIfNotExists(&affect, cyclonedx.AffectedVersions{
					Version: step.UpgradeTo.Version,
					Status:  cyclonedx.VulnerabilityStatusNotAffected,
				})
			}
			(*vulnerability.Affects)[i] = affect
		}
	} else {
		log.Debug("No remediation options found for vulnerability " + vulnerability.ID)
	}
}

func getAffectComponentCveRemediationStepsByFixedVersion(cve string, component cyclonedx.Component, cveRemediationOptions []utils.Option, strategy utils.FixStrategy) (steps []utils.OptionStep) {
	for _, cveRemediationOption := range cveRemediationOptions {
		if cveRemediationOption.Type != utils.InLock {
			// We only want InLock remediation type (forcing the actual component to a specific fix version)
			continue
		}
		stepsMap, found := cveRemediationOption.Steps[strategy]
		if !found || len(stepsMap) == 0 {
			log.Debug(fmt.Sprintf("No remediation steps found for strategy '%d' for component '%s' in vulnerability '%s'", strategy, component.Name, cve))
			continue
		}
		for _, step := range stepsMap {
			if step.StepType == utils.NoFixVersion {
				log.Debug(fmt.Sprintf("No fix version available for component '%s' in vulnerability '%s'", component.Name, cve))
				continue
			} else if step.StepType == utils.PackageNotFound {
				log.Debug(fmt.Sprintf("Component '%s' not found in catalog for vulnerability '%s'", component.Name, cve))
				continue
			}
			// We only want FixVersion step type
			if step.StepType == utils.FixVersion && step.PkgVersion.Name == component.Name && step.PkgVersion.Version == component.Version {
				steps = append(steps, step)
			}
		}
	}
	if len(steps) == 0 {
		log.Debug(fmt.Sprintf("No remediation steps by forcing fixed version found for component '%s' in vulnerability '%s'", component.Name, cve))
	}
	return
}
