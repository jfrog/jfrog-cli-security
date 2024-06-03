package main

import (
	"errors"
	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestReportError(t *testing.T) {
	serverDetails := &config.ServerDetails{
		Url:            *tests.JfrogUrl,
		ArtifactoryUrl: *tests.JfrogUrl + tests.ArtifactoryEndpoint,
		XrayUrl:        *tests.JfrogUrl + tests.XrayEndpoint,
		AccessToken:    *tests.JfrogAccessToken,
		ServerId:       tests.ServerId,
	}

	// Prior to initiating the test, we verify whether Xsc is enabled for the customer. If not, the test is skipped.
	xscManager, err := utils.CreateXscServiceManager(serverDetails)
	assert.NoError(t, err)

	if !utils.IsReportLogErrorEventPossible(xscManager) {
		t.Skip("Skipping test since Xsc server is not enabled or below minimal required version")
	}

	errorToReport := errors.New("THIS IS NOT A REAL ERROR! This Error is posted as part of TestReportError test")
	assert.NoError(t, utils.ReportError(serverDetails, errorToReport, "cli"))
}

func TestXscAuditNpmJson(t *testing.T) {
	// Make sure the audit request will work with xsc and not xray
	err := os.Setenv("JFROG_CLI_REPORT_USAGE", "")
	assert.NoError(t, err)
	defer func() {
		err = os.Setenv("JFROG_CLI_REPORT_USAGE", "false")
		assert.NoError(t, err)
	}()
	output := testAuditNpm(t, string(format.Json))
	securityTestUtils.VerifyJsonScanResults(t, output, 1, 1, 1)

}

func TestXscAuditNpmSimpleJson(t *testing.T) {
	// Make sure the audit request will work with xsc and not xray
	err := os.Setenv("JFROG_CLI_REPORT_USAGE", "")
	assert.NoError(t, err)
	defer func() {
		err = os.Setenv("JFROG_CLI_REPORT_USAGE", "false")
		assert.NoError(t, err)
	}()
	output := testAuditNpm(t, string(format.SimpleJson))
	securityTestUtils.VerifySimpleJsonScanResults(t, output, 1, 1, 1)

}
