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
	for _, vulnerability := range *bom.Vulnerabilities {
		if vulnerability.Affects == nil || len(*vulnerability.Affects) == 0 {
			log.Debug("No affected components found for vulnerability " + vulnerability.ID + ", skipping attaching fixed versions")
			continue
		}
		if cveRemediationOptions, found := remediationOptions[vulnerability.ID]; found {
			for _, affect := range *vulnerability.Affects {
				// Lets find the remediation for this specific component
				affectComponent := cdxutils.SearchComponentByRef(bom.Components, affect.Ref)
				if affectComponent == nil {
					log.Debug("Affected component " + affect.Ref + " not found in BOM components, skipping attaching fixed versions for vulnerability " + vulnerability.ID)
					continue
				}
				steps := getAffectComponentCveRemediationStepsByFixedVersion(*affectComponent, cveRemediationOptions)
				if len(steps) == 0 {
					log.Debug("No remediation steps by forcing fixed version found for component " + affect.Ref + " in vulnerability " + vulnerability.ID)
					continue
				}
				// Convert remediation steps to fixed versions affected versions
				for _, step := range steps {
					cdxutils.AppendAffectedVersions(&affect, cyclonedx.AffectedVersions{
						Version: step.UpgradeTo.Version,
						Status:  cyclonedx.VulnerabilityStatusNotAffected,
					})
				}
			}
		} else {
			log.Debug("No remediation options found for vulnerability " + vulnerability.ID)
		}
	}
	return nil
}

func getAffectComponentCveRemediationStepsByFixedVersion(component cyclonedx.Component, cveRemediationOptions []utils.Option) (steps []utils.OptionStep) {
	for _, cveRemediationOption := range cveRemediationOptions {
		if cveRemediationOption.Type != utils.InLock {
			// We only want InLock remediation type (forcing the actual component to a specific fix version)
			continue
		}
		for _, step := range cveRemediationOption.Steps {
			if step.StepType != utils.FixVersion {
				// We only want FixVersion step type
				continue
			}
			if step.PkgVersion.Name == component.Name && step.PkgVersion.Version == component.Version {
				// This step is relevant for the affected component
				steps = append(steps, step)
			}
		}
	}
	return
}
