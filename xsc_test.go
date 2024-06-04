package main

import (
	"errors"
	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
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

func initXscTest(t *testing.T) func() {
	// Make sure the audit request will work with xsc and not xray
	assert.NoError(t, os.Setenv(coreutils.ReportUsage, ""))
	return func() {
		assert.NoError(t, os.Setenv(coreutils.ReportUsage, "false"))
	}
}

// In the npm tests we use a watch flag, so we would get only violations
func TestXscAuditNpmJsonWithWatch(t *testing.T) {
	restoreFunc := initXscTest(t)
	defer restoreFunc()
	output := testAuditNpm(t, string(format.Json))
	securityTestUtils.VerifyJsonScanResults(t, output, 1, 0, 1)
}

func TestXscAuditNpmSimpleJsonWithWatch(t *testing.T) {
	restoreFunc := initXscTest(t)
	defer restoreFunc()
	output := testAuditNpm(t, string(format.SimpleJson))
	securityTestUtils.VerifySimpleJsonScanResults(t, output, 1, 0, 1)
}

func TestXscAuditMavenJson(t *testing.T) {
	restoreFunc := initXscTest(t)
	defer restoreFunc()
	output := testXscAuditMaven(t, string(format.Json))
	securityTestUtils.VerifyJsonScanResults(t, output, 0, 1, 1)
}

func TestXscAuditMavenSimpleJson(t *testing.T) {
	restoreFunc := initXscTest(t)
	defer restoreFunc()
	output := testXscAuditMaven(t, string(format.SimpleJson))
	securityTestUtils.VerifySimpleJsonScanResults(t, output, 0, 1, 1)
}
