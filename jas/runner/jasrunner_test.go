package runner

import (
	"os"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/common/cliutils"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/jas/applicability"
	"github.com/jfrog/jfrog-cli-security/jas/secrets"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"
)

func TestJasRunner_AnalyzerManagerNotExist(t *testing.T) {
	tmpDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()
	assert.NoError(t, os.Setenv(coreutils.HomeDir, tmpDir))
	defer func() {
		assert.NoError(t, os.Unsetenv(coreutils.HomeDir))
	}()
	scanner, err := jas.CreateJasScanner(&jas.FakeServerDetails, false, "", jas.GetAnalyzerManagerXscEnvVars(""))
	assert.NoError(t, err)
	if scanner.AnalyzerManager.AnalyzerManagerFullPath, err = jas.GetAnalyzerManagerExecutable(); err != nil {
		return
	}
	assert.Error(t, err)
	assert.NotNil(t, scanner)
	assert.ErrorContains(t, err, "unable to locate the analyzer manager package. Advanced security scans cannot be performed without this package")
}

func TestJasRunner(t *testing.T) {
	assert.NoError(t, jas.DownloadAnalyzerManagerIfNeeded(0))
	securityParallelRunnerForTest := utils.CreateSecurityParallelRunner(cliutils.Threads)
	targetResults := results.NewCommandResults(utils.SourceCode).SetEntitledForJas(true).SetSecretValidation(true).NewScanResults(results.ScanTarget{Target: "target", Technology: techutils.Pip})

	jasScanner, err := jas.CreateJasScanner(&jas.FakeServerDetails, false, "", jas.GetAnalyzerManagerXscEnvVars("", targetResults.GetTechnologies()...))
	assert.NoError(t, err)

	targetResults.NewScaScanResults(jas.FakeBasicXrayResults[0])
	testParams := JasRunnerParams{
		Runner:             securityParallelRunnerForTest,
		Scanner:            jasScanner,
		ScanResults:        targetResults,
		ScansToPreform:     utils.GetAllSupportedScans(),
		ApplicableScanType: applicability.ApplicabilityScannerType,
		SecretsScanType:    secrets.SecretsScannerType,
		DirectDependencies: &[]string{"issueId_1_direct_dependency", "issueId_2_direct_dependency"},
	}
	assert.NoError(t, AddJasScannersTasks(testParams))
}

func TestJasRunner_AnalyzerManagerReturnsError(t *testing.T) {
	assert.NoError(t, jas.DownloadAnalyzerManagerIfNeeded(0))

	jfrogAppsConfigForTest, _ := jas.CreateJFrogAppsConfig(nil)
	scanner, _ := jas.CreateJasScanner(&jas.FakeServerDetails, false, "", jas.GetAnalyzerManagerXscEnvVars(""))
	_, err := applicability.RunApplicabilityScan(jas.FakeBasicXrayResults, []string{"issueId_2_direct_dependency", "issueId_1_direct_dependency"}, scanner, false, applicability.ApplicabilityScannerType, jfrogAppsConfigForTest.Modules[0], 0)
	// Expect error:
	assert.ErrorContains(t, err, "failed to run Applicability scan")
}
