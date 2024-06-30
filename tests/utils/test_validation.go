package utils

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils"

	clientUtils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

func ValidateXrayVersion(t *testing.T, minVersion string) {
	xrayVersion, err := getXrayVersion()
	if err != nil {
		assert.NoError(t, err)
		return
	}
	err = clientUtils.ValidateMinimumVersion(clientUtils.Xray, xrayVersion.GetVersion(), minVersion)
	if err != nil {
		t.Skip(err)
	}
}

func ValidateXscVersion(t *testing.T, minVersion string) {
	xscVersion, err := getXscVersion()
	if err != nil {
		t.Skip(err)
	}
	err = clientUtils.ValidateMinimumVersion(clientUtils.Xsc, xscVersion.GetVersion(), minVersion)
	if err != nil {
		t.Skip(err)
	}
}

func VerifyJsonScanResults(t *testing.T, content string, minViolations, minVulnerabilities, minLicenses int) {
	var results []services.ScanResponse
	err := json.Unmarshal([]byte(content), &results)
	if assert.NoError(t, err) {
		var violations []services.Violation
		var vulnerabilities []services.Vulnerability
		var licenses []services.License
		for _, result := range results {
			violations = append(violations, result.Violations...)
			vulnerabilities = append(vulnerabilities, result.Vulnerabilities...)
			licenses = append(licenses, result.Licenses...)
		}
		assert.True(t, len(violations) >= minViolations, fmt.Sprintf("Expected at least %d violations in scan results, but got %d violations.", minViolations, len(violations)))
		assert.True(t, len(vulnerabilities) >= minVulnerabilities, fmt.Sprintf("Expected at least %d vulnerabilities in scan results, but got %d vulnerabilities.", minVulnerabilities, len(vulnerabilities)))
		assert.True(t, len(licenses) >= minLicenses, fmt.Sprintf("Expected at least %d Licenses in scan results, but got %d Licenses.", minLicenses, len(licenses)))
	}
}

func VerifySimpleJsonScanResults(t *testing.T, content string, minViolations, minVulnerabilities, minLicenses int) {
	var results formats.SimpleJsonResults
	err := json.Unmarshal([]byte(content), &results)
	if assert.NoError(t, err) {
		assert.GreaterOrEqual(t, len(results.SecurityViolations), minViolations)
		assert.GreaterOrEqual(t, len(results.Vulnerabilities), minVulnerabilities)
		assert.GreaterOrEqual(t, len(results.Licenses), minLicenses)
	}
}

func VerifySimpleJsonJasResults(t *testing.T, content string, minSastViolations, minIacViolations, minSecrets,
	minApplicable, minUndetermined, minNotCovered, minNotApplicable int) {
	var results formats.SimpleJsonResults
	err := json.Unmarshal([]byte(content), &results)
	if assert.NoError(t, err) {
		assert.GreaterOrEqual(t, len(results.Sast), minSastViolations, "Found less sast then expected")
		assert.GreaterOrEqual(t, len(results.Secrets), minSecrets, "Found less secrets then expected")
		assert.GreaterOrEqual(t, len(results.Iacs), minIacViolations, "Found less IaC then expected")
		var applicableResults, undeterminedResults, notCoveredResults, notApplicableResults int
		for _, vuln := range results.Vulnerabilities {
			switch vuln.Applicable {
			case string(utils.NotApplicable):
				notApplicableResults++
			case string(utils.Applicable):
				applicableResults++
			case string(utils.NotCovered):
				notCoveredResults++
			case string(utils.ApplicabilityUndetermined):
				undeterminedResults++
			}
		}
		assert.GreaterOrEqual(t, applicableResults, minApplicable, "Found less applicableResults then expected")
		assert.GreaterOrEqual(t, undeterminedResults, minUndetermined, "Found less undeterminedResults then expected")
		assert.GreaterOrEqual(t, notCoveredResults, minNotCovered, "Found less notCoveredResults then expected")
		assert.GreaterOrEqual(t, notApplicableResults, minNotApplicable, "Found less notApplicableResults then expected")
	}
}
