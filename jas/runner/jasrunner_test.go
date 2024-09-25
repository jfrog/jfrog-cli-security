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
	scanner, err := jas.CreateJasScanner(nil, &jas.FakeServerDetails, "", jas.GetAnalyzerManagerXscEnvVars("", false))
	assert.NoError(t, err)
	if scanner.AnalyzerManager.AnalyzerManagerFullPath, err = jas.GetAnalyzerManagerExecutable(); err != nil {
		return
	}
	assert.Error(t, err)
	assert.NotNil(t, scanner)
	assert.ErrorContains(t, err, "unable to locate the analyzer manager package. Advanced security scans cannot be performed without this package")
}

func TestJasRunner(t *testing.T) {
	securityParallelRunnerForTest := utils.CreateSecurityParallelRunner(cliutils.Threads)
	scanResults := &utils.Results{ScaResults: []*utils.ScaScanResult{{Technology: techutils.Pip, XrayResults: jas.FakeBasicXrayResults}}, ExtendedScanResults: &utils.ExtendedScanResults{}}

	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig(nil)
	assert.NoError(t, err)
	jasScanner, err := jas.CreateJasScanner(jfrogAppsConfigForTest, &jas.FakeServerDetails, "", jas.GetAnalyzerManagerXscEnvVars("", false, scanResults.GetScaScannedTechnologies()...))
	assert.NoError(t, err)
	err = AddJasScannersTasks(securityParallelRunnerForTest, scanResults, &[]string{"issueId_1_direct_dependency", "issueId_2_direct_dependency"}, false, jasScanner, applicability.ApplicabilityScannerType, secrets.SecretsScannerType, securityParallelRunnerForTest.AddErrorToChan, utils.GetAllSupportedScans(), nil, "")
	assert.NoError(t, err)
}

func TestJasRunner_AnalyzerManagerReturnsError(t *testing.T) {
	assert.NoError(t, jas.DownloadAnalyzerManagerIfNeeded(0))

	jfrogAppsConfigForTest, _ := jas.CreateJFrogAppsConfig(nil)
	scanner, _ := jas.CreateJasScanner(nil, &jas.FakeServerDetails, "", jas.GetAnalyzerManagerXscEnvVars("", false))
	_, err := applicability.RunApplicabilityScan(jas.FakeBasicXrayResults, []string{"issueId_2_direct_dependency", "issueId_1_direct_dependency"},
		scanner, false, applicability.ApplicabilityScannerType, jfrogAppsConfigForTest.Modules[0], 0)
	// Expect error:
	assert.ErrorContains(t, err, "failed to run Applicability scan")
}
