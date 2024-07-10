package runner

import (
	"os"
	"testing"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
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

func TestGetExtendedScanResults_AnalyzerManagerDoesntExist(t *testing.T) {
	tmpDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()
	assert.NoError(t, os.Setenv(coreutils.HomeDir, tmpDir))
	defer func() {
		assert.NoError(t, os.Unsetenv(coreutils.HomeDir))
	}()
	scanner := &jas.JasScanner{}
	_, err = jas.CreateJasScanner(scanner, &jas.FakeServerDetails, jas.GetAnalyzerManagerXscEnvVars(""))
	assert.Error(t, err)
	assert.ErrorContains(t, err, "unable to locate the analyzer manager package. Advanced security scans cannot be performed without this package")
}

func TestGetExtendedScanResults_ServerNotValid(t *testing.T) {
	securityParallelRunnerForTest := utils.CreateSecurityParallelRunner(cliutils.Threads)
	targetResults := results.NewCommandResults("", true).NewScanResults(results.ScanTarget{Target: "target", Technology: techutils.Pip})

	scanner := &jas.JasScanner{}
	jasScanner, err := jas.CreateJasScanner(scanner, &jas.FakeServerDetails, jas.GetAnalyzerManagerXscEnvVars("", targetResults.GetTechnologies()...))
	assert.NoError(t, err)

	targetResults.NewScaScanResults(&jas.FakeBasicXrayResults[0])
	err = AddJasScannersTasks(securityParallelRunnerForTest, jfrogappsconfig.Module{}, targetResults, &[]string{"issueId_1_direct_dependency", "issueId_2_direct_dependency"}, nil, false, jasScanner, applicability.ApplicabilityScannerType, secrets.SecretsScannerType, utils.GetAllSupportedScans())
	assert.NoError(t, err)
}

func TestGetExtendedScanResults_AnalyzerManagerReturnsError(t *testing.T) {
	assert.NoError(t, jas.DownloadAnalyzerManagerIfNeeded(0))

	jfrogAppsConfigForTest, _ := jas.CreateJFrogAppsConfig(nil)
	scanner := &jas.JasScanner{}
	scanner, _ = jas.CreateJasScanner(scanner, &jas.FakeServerDetails, jas.GetAnalyzerManagerXscEnvVars(""))
	_, err := applicability.RunApplicabilityScan(jas.FakeBasicXrayResults, []string{"issueId_2_direct_dependency", "issueId_1_direct_dependency"},
		scanner, false, applicability.ApplicabilityScannerType, jfrogAppsConfigForTest.Modules[0], 0)

	// Expect error:
	assert.ErrorContains(t, err, "failed to run Applicability scan")
}
