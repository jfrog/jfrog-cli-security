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
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
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
	scanner, err := jas.NewJasScanner(&jas.FakeServerDetails)
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

	jasScanner, err := jas.NewJasScanner(&jas.FakeServerDetails, jas.WithEnvVars(false, jas.NotDiffScanEnvValue, jas.GetAnalyzerManagerXscEnvVars("", "", "", []string{}, targetResults.GetTechnologies()...)))
	assert.NoError(t, err)
	jasScanner.AnalyzerManager.AnalyzerManagerFullPath, err = jas.GetAnalyzerManagerExecutable()
	assert.NoError(t, err)

	targetResults.ScaScanResults(0, jas.FakeBasicXrayResults[0])
	directComponents := []string{"issueId_1_direct_dependency", "issueId_2_direct_dependency"}
	testParams := JasRunnerParams{
		Runner:             securityParallelRunnerForTest,
		Scanner:            jasScanner,
		ScanResults:        targetResults,
		ScansToPerform:     utils.GetAllSupportedScans(),
		ApplicableScanType: applicability.ApplicabilityScannerType,
		SecretsScanType:    secrets.SecretsScannerType,
		CvesProvider: func() (directCves []string, indirectCves []string) {
			return results.ExtractCvesFromScanResponse(targetResults.GetScaScansXrayResults(), directComponents)
		},
	}
	assert.NoError(t, AddJasScannersTasks(testParams))
}

func TestJasRunner_AnalyzerManagerReturnsError(t *testing.T) {
	assert.NoError(t, jas.DownloadAnalyzerManagerIfNeeded(0))

	jfrogAppsConfigForTest, _ := jas.CreateJFrogAppsConfig(nil)
	scanner, _ := jas.NewJasScanner(&jas.FakeServerDetails)
	directCves, indirectCves := results.ExtractCvesFromScanResponse(jas.FakeBasicXrayResults, []string{"issueId_2_direct_dependency", "issueId_1_direct_dependency"})
	_, err := applicability.RunApplicabilityScan(
		applicability.ContextualAnalysisScanParams{
			DirectDependenciesCves:   directCves,
			IndirectDependenciesCves: indirectCves,
			ScanType:                 applicability.ApplicabilityScannerType,
			Module:                   jfrogAppsConfigForTest.Modules[0],
		},
		scanner,
	)
	// Expect error:
	assert.ErrorContains(t, jas.ParseAnalyzerManagerError(jasutils.Applicability, err), "failed to run Applicability scan")
}
