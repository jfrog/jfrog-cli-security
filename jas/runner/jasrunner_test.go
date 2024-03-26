package runner

import (
	"os"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/jas/applicability"
	"github.com/jfrog/jfrog-cli-security/jas/secrets"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"
)

func TestGetExtendedScanResults_AnalyzerManagerDoesntExist(t *testing.T) {
	tmpDir, err := fileutils.CreateTempDir()
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()
	assert.NoError(t, err)
	assert.NoError(t, os.Setenv(coreutils.HomeDir, tmpDir))
	defer func() {
		assert.NoError(t, os.Unsetenv(coreutils.HomeDir))
	}()
	scanResults := &utils.Results{ScaResults: []utils.ScaScanResult{{Technology: coreutils.Yarn, XrayResults: jas.FakeBasicXrayResults}}, ExtendedScanResults: &utils.ExtendedScanResults{}}
	err = RunJasScannersAndSetResults(scanResults, []string{"issueId_1_direct_dependency", "issueId_2_direct_dependency"}, &jas.FakeServerDetails, nil, nil, false, applicability.ApplicabilityScannerType, secrets.SecretsScannerType)
	// Expect error:
	assert.Error(t, err)
}

func TestGetExtendedScanResults_ServerNotValid(t *testing.T) {
	scanResults := &utils.Results{ScaResults: []utils.ScaScanResult{{Technology: coreutils.Pip, XrayResults: jas.FakeBasicXrayResults}}, ExtendedScanResults: &utils.ExtendedScanResults{}}
	err := RunJasScannersAndSetResults(scanResults, []string{"issueId_1_direct_dependency", "issueId_2_direct_dependency"}, nil, nil, nil, false, applicability.ApplicabilityScannerType, secrets.SecretsScannerType)
	assert.NoError(t, err)
}

func TestGetExtendedScanResults_AnalyzerManagerReturnsError(t *testing.T) {
	assert.NoError(t, utils.DownloadAnalyzerManagerIfNeeded())

	scanResults := &utils.Results{ScaResults: []utils.ScaScanResult{{Technology: coreutils.Yarn, XrayResults: jas.FakeBasicXrayResults}}, ExtendedScanResults: &utils.ExtendedScanResults{}}
	err := RunJasScannersAndSetResults(scanResults, []string{"issueId_2_direct_dependency", "issueId_1_direct_dependency"}, &jas.FakeServerDetails, nil, nil, false, applicability.ApplicabilityScannerType, secrets.SecretsScannerType)

	// Expect error:
	assert.ErrorContains(t, err, "failed to run Applicability scan")
}
