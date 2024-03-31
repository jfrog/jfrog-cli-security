package audit

import (
	"github.com/jfrog/jfrog-cli-security/commands/audit/jas"
	"os"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"
)

func TestGetExtendedScanResults_AnalyzerManagerDoesntExist(t *testing.T) {
	aduit := utils.NewAuditParallelRunner()
	tmpDir, err := fileutils.CreateTempDir()
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()
	assert.NoError(t, err)
	assert.NoError(t, os.Setenv(coreutils.HomeDir, tmpDir))
	defer func() {
		assert.NoError(t, os.Unsetenv(coreutils.HomeDir))
	}()
	scanResults := &utils.Results{ScaResults: []*utils.ScaScanResult{{Technology: coreutils.Yarn, XrayResults: jas.FakeBasicXrayResults}}, ExtendedScanResults: &utils.ExtendedScanResults{}}
	err = RunJasScannersAndSetResults(&aduit, scanResults, []string{"issueId_1_direct_dependency", "issueId_2_direct_dependency"}, &jas.FakeServerDetails, nil, nil, false, NewAuditParams())
	// Expect error:
	assert.Error(t, err)
}

func TestGetExtendedScanResults_ServerNotValid(t *testing.T) {
	auditParallelRunnerForTest := utils.NewAuditParallelRunner()
	scanResults := &utils.Results{ScaResults: []*utils.ScaScanResult{{Technology: coreutils.Pip, XrayResults: jas.FakeBasicXrayResults}}, ExtendedScanResults: &utils.ExtendedScanResults{}}
	err := RunJasScannersAndSetResults(&auditParallelRunnerForTest, scanResults, []string{"issueId_1_direct_dependency", "issueId_2_direct_dependency"}, nil, nil, nil, false, NewAuditParams())
	assert.NoError(t, err)
}

func TestGetExtendedScanResults_AnalyzerManagerReturnsError(t *testing.T) {
	auditParallelRunnerForTest := utils.NewAuditParallelRunner()

	assert.NoError(t, utils.DownloadAnalyzerManagerIfNeeded(0))

	scanResults := &utils.Results{ScaResults: []*utils.ScaScanResult{{Technology: coreutils.Yarn, XrayResults: jas.FakeBasicXrayResults}}, ExtendedScanResults: &utils.ExtendedScanResults{}}
	err := RunJasScannersAndSetResults(&auditParallelRunnerForTest, scanResults, []string{"issueId_2_direct_dependency", "issueId_1_direct_dependency"}, &jas.FakeServerDetails, nil, nil, false, NewAuditParams())

	// Expect error:
	assert.ErrorContains(t, err, "failed to run Applicability scan")
}
