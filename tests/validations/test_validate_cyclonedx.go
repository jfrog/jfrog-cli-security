package validations

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/stretchr/testify/assert"
)

func VerifyCycloneDxResults(t *testing.T, content string, params ValidationParams) {
	var results *cdxutils.FullBOM
	err := json.Unmarshal([]byte(content), &results)
	assert.NoError(t, err, "Failed to unmarshal content to json.")
	params.Actual = results
	ValidateCommandCycloneDxOutput(t, params)
}

// ValidateCommandCycloneDxOutput validates the CycloneDX BOM output against expected values.
func ValidateCommandCycloneDxOutput(t *testing.T, params ValidationParams) {
	results, ok := params.Actual.(*cdxutils.FullBOM)
	if assert.True(t, ok, "Actual result is not of type *cyclonedx.BOM") {
		ValidateCycloneDxIssuesCount(t, params, results)
		if params.ExactResultsMatch && params.Expected != nil {
			expectedResults, ok := params.Expected.(*cdxutils.FullBOM)
			if assert.True(t, ok, "Expected content is not of type *cyclonedx.BOM") {
				assert.Equal(t, expectedResults, results, "CycloneDX BOM output does not match expected values")
			}
		}
	}
}

func ValidateCycloneDxIssuesCount(t *testing.T, params ValidationParams, content *cdxutils.FullBOM) {
	actualValues := validationCountActualValues{}

	actualValues.SbomComponents, actualValues.RootComponents, actualValues.DirectComponents, actualValues.TransitiveComponents, actualValues.Licenses = countSbomComponents(&content.BOM)
	actualValues.ScaVulnerabilities, actualValues.ApplicableVulnerabilities, actualValues.UndeterminedVulnerabilities, actualValues.NotCoveredVulnerabilities, actualValues.NotApplicableVulnerabilities, actualValues.MissingContextVulnerabilities = countScaVulnerabilities(&content.BOM)
	actualValues.SastVulnerabilities, actualValues.SecretsVulnerabilities, actualValues.IacVulnerabilities, actualValues.InactiveSecretsVulnerabilities = countJasVulnerabilities(content)

	actualValues.Vulnerabilities = actualValues.ScaVulnerabilities + actualValues.SastVulnerabilities + actualValues.SecretsVulnerabilities + actualValues.IacVulnerabilities

	ValidateCount(t, "cyclonedx BOM", params, actualValues)
}

func countSbomComponents(content *cyclonedx.BOM) (sbomComponents, rootComponents, directComponents, transitiveComponents, licenses int) {
	if content == nil || content.Components == nil {
		return
	}
	parsedLicenses := datastructures.MakeSet[string]()
	for _, component := range *content.Components {
		if component.Licenses != nil {
			for _, license := range *component.Licenses {
				if license.License != nil && license.License.ID != "" {
					parsedLicenses.Add(license.License.ID)
				}
			}
		}
		relation := cdxutils.GetComponentRelation(content, component.BOMRef, true)
		if relation == cdxutils.UnknownRelation {
			continue
		}
		if relation == cdxutils.RootRelation {
			rootComponents++
		}
		if relation == cdxutils.DirectRelation {
			directComponents++
		}
		if relation == cdxutils.TransitiveRelation {
			transitiveComponents++
		}
	}
	sbomComponents = len(*content.Components)
	licenses = parsedLicenses.Size()
	return
}

func countScaVulnerabilities(content *cyclonedx.BOM) (scaVulnerabilities, applicableVulnerabilities, undeterminedVulnerabilities, notCoveredVulnerabilities, notApplicableVulnerabilities, missingContextVulnerabilities int) {
	if content == nil || content.Vulnerabilities == nil {
		return
	}
	for _, vulnerability := range *content.Vulnerabilities {
		if !strings.HasPrefix(vulnerability.BOMRef, "CVE-") && !strings.HasPrefix(vulnerability.BOMRef, "XRAY-") {
			// Not SCA vulnerabilities
			continue
		}
		// Count Unique CVE vulnerabilities
		scaVulnerabilities++
		if statusProperty := cdxutils.GetProperty(vulnerability.Properties, results.ApplicabilityStatusPropertyName); statusProperty != nil {
			switch jasutils.ConvertToApplicabilityStatus(statusProperty.Value) {
			case jasutils.Applicable:
				applicableVulnerabilities++
			case jasutils.NotApplicable:
				notApplicableVulnerabilities++
			case jasutils.ApplicabilityUndetermined:
				undeterminedVulnerabilities++
			case jasutils.NotCovered:
				notCoveredVulnerabilities++
			case jasutils.MissingContext:
				missingContextVulnerabilities++
			}
		}
	}
	return
}

func countJasVulnerabilities(content *cdxutils.FullBOM) (sastVulnerabilities, secretsVulnerabilities, iacVulnerabilities, inactiveSecretsVulnerabilities int) {
	if content == nil || content.Vulnerabilities == nil {
		return
	}
	for _, vulnerability := range *content.Vulnerabilities {
		if strings.HasPrefix(vulnerability.BOMRef, "CVE-") || strings.HasPrefix(vulnerability.BOMRef, "XRAY-") {
			// SCA vulnerabilities
			continue
		}
		if vulnerability.Affects == nil || len(*vulnerability.Affects) == 0 || vulnerability.Properties == nil {
			continue
		}
		for _, property := range *vulnerability.Properties {
			if strings.HasPrefix(property.Name, "jfrog:sast:location:") {
				sastVulnerabilities++
			}
			if strings.HasPrefix(property.Name, "jfrog:iac:location:") {
				iacVulnerabilities++
			}
			if strings.HasPrefix(property.Name, "jfrog:secret:location:") {
				secretsVulnerabilities++
			}
			if strings.HasPrefix(property.Name, "jfrog:secret-validation:status:") {
				if jasutils.Inactive == jasutils.TokenValidationStatus(property.Value) {
					inactiveSecretsVulnerabilities++
				}
			}
		}
	}
	sarifSastVuln, sarifSastViolations := countJasResults(content.Sast)
	sastVulnerabilities += sarifSastVuln
	secretsVulnerabilities += sarifSastViolations
	return
}
