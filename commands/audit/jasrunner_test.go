package audit

import (
	"github.com/jfrog/jfrog-cli-security/commands/audit/jas"
	"github.com/jfrog/jfrog-cli-security/commands/audit/jas/applicability"
	"os"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"
)

func TestGetExtendedScanResults_AnalyzerManagerDoesntExist(t *testing.T) {
	auditParallelRunnerForTest := utils.NewAuditParallelRunner()
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

	auditParamsForTest := NewAuditParams().SetThirdPartyApplicabilityScan(false)
	auditParamsForTest.AuditBasicParams.AppendDependenciesForApplicabilityScan([]string{"issueId_1_direct_dependency", "issueId_2_direct_dependency"})

	err = RunJasScannersAndSetResults(&auditParallelRunnerForTest, scanResults, &jas.FakeServerDetails, auditParamsForTest)
	// Expect error:
	assert.Error(t, err)
}

func TestGetExtendedScanResults_ServerNotValid(t *testing.T) {
	auditParallelRunnerForTest := utils.NewAuditParallelRunner()
	scanResults := &utils.Results{ScaResults: []*utils.ScaScanResult{{Technology: coreutils.Pip, XrayResults: jas.FakeBasicXrayResults}}, ExtendedScanResults: &utils.ExtendedScanResults{}}
	auditParamsForTest := NewAuditParams().SetThirdPartyApplicabilityScan(false)
	auditParamsForTest.AuditBasicParams.AppendDependenciesForApplicabilityScan([]string{"issueId_1_direct_dependency", "issueId_2_direct_dependency"})
	err := RunJasScannersAndSetResults(&auditParallelRunnerForTest, scanResults, nil, auditParamsForTest)
	assert.NoError(t, err)
}

func TestGetExtendedScanResults_AnalyzerManagerReturnsError(t *testing.T) {
	auditParallelRunnerForTest := utils.NewAuditParallelRunner()

	assert.NoError(t, utils.DownloadAnalyzerManagerIfNeeded(0))

	scanner, _ := jas.NewJasScanner(nil, &jas.FakeServerDetails)
	err := applicability.RunApplicabilityScan(&auditParallelRunnerForTest, jas.FakeBasicXrayResults, []string{"issueId_2_direct_dependency", "issueId_1_direct_dependency"},
		[]coreutils.Technology{coreutils.Yarn}, scanner, false, &utils.ExtendedScanResults{}, scanner.JFrogAppsConfig.Modules[0], 0)

	// Expect error:
	assert.ErrorContains(t, err, "failed to run Applicability scan")
}
