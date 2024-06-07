package runner

import (
	"github.com/jfrog/jfrog-cli-core/v2/common/cliutils"
	"os"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/jas/applicability"
	"github.com/jfrog/jfrog-cli-security/jas/secrets"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"
)

func TestGetExtendedScanResults_AnalyzerManagerDoesntExist(t *testing.T) {
	securityParallelRunnerForTest := utils.CreateSecurityParallelRunner(cliutils.Threads)
	tmpDir, err := fileutils.CreateTempDir()
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()
	assert.NoError(t, err)
	assert.NoError(t, os.Setenv(coreutils.HomeDir, tmpDir))
	defer func() {
		assert.NoError(t, os.Unsetenv(coreutils.HomeDir))
	}()
	scanResults := &utils.Results{ScaResults: []*utils.ScaScanResult{{Technology: techutils.Yarn, XrayResults: jas.FakeBasicXrayResults}}, ExtendedScanResults: &utils.ExtendedScanResults{}}
	err = RunJasScannersAndSetResults(securityParallelRunnerForTest, scanResults, scanResults.GetScaScannedTechnologies(), &[]string{"issueId_1_direct_dependency", "issueId_2_direct_dependency"}, &jas.FakeServerDetails, nil, false, "", applicability.ApplicabilityScannerType, secrets.SecretsScannerType, securityParallelRunnerForTest.AddErrorToChan)
	// Expect error:
	assert.Error(t, err)
}

func TestGetExtendedScanResults_ServerNotValid(t *testing.T) {
	securityParallelRunnerForTest := utils.CreateSecurityParallelRunner(cliutils.Threads)
	scanResults := &utils.Results{ScaResults: []*utils.ScaScanResult{{Technology: techutils.Pip, XrayResults: jas.FakeBasicXrayResults}}, ExtendedScanResults: &utils.ExtendedScanResults{}}
	err := RunJasScannersAndSetResults(securityParallelRunnerForTest, scanResults, scanResults.GetScaScannedTechnologies(), &[]string{"issueId_1_direct_dependency", "issueId_2_direct_dependency"}, nil, nil, false, "", applicability.ApplicabilityScannerType, secrets.SecretsScannerType, securityParallelRunnerForTest.AddErrorToChan)
	assert.NoError(t, err)
}

func TestGetExtendedScanResults_AnalyzerManagerReturnsError(t *testing.T) {
	securityParallelRunnerForTest := utils.CreateSecurityParallelRunner(cliutils.Threads)
	assert.NoError(t, utils.DownloadAnalyzerManagerIfNeeded(0))

	scanResults := &utils.Results{ScaResults: []*utils.ScaScanResult{{Technology: techutils.Yarn, XrayResults: jas.FakeBasicXrayResults}}, ExtendedScanResults: &utils.ExtendedScanResults{}}
	err := RunJasScannersAndSetResults(securityParallelRunnerForTest, scanResults, scanResults.GetScaScannedTechnologies(), &[]string{"issueId_2_direct_dependency", "issueId_1_direct_dependency"}, &jas.FakeServerDetails, nil, false, "", applicability.ApplicabilityScannerType, secrets.SecretsScannerType, securityParallelRunnerForTest.AddErrorToChan)

	// Expect error:
	assert.ErrorContains(t, err, "failed to run Applicability scan")
}
