package audit

import (
	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	scanservices "github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"strings"
	"testing"
)

// Note: Currently, if a config profile is provided, the scan will use the profile's settings, IGNORING jfrog-apps-config if exists.
func TestAuditWithConfigProfile(t *testing.T) {
	testcases := []struct {
		name                  string
		configProfile         services.ConfigProfile
		expectedSastIssues    int
		expectedSecretsIssues int
	}{
		{
			name: "Enable only secrets scanner",
			configProfile: services.ConfigProfile{
				ProfileName: "only-secrets",
				Modules: []services.Module{{
					ModuleId:     1,
					ModuleName:   "only-secrets-module",
					PathFromRoot: ".",
					ScanConfig: services.ScanConfig{
						SastScannerConfig: services.SastScannerConfig{
							EnableSastScan: false,
						},
						SecretsScannerConfig: services.SecretsScannerConfig{
							EnableSecretsScan: true,
						},
					},
				}},
				IsDefault: false,
			},
			expectedSastIssues:    0,
			expectedSecretsIssues: 7,
		},
		{
			name: "Enable only sast scanner",
			configProfile: services.ConfigProfile{
				ProfileName: "only-sast",
				Modules: []services.Module{{
					ModuleId:     1,
					ModuleName:   "only-sast-module",
					PathFromRoot: ".",
					ScanConfig: services.ScanConfig{
						SastScannerConfig: services.SastScannerConfig{
							EnableSastScan: true,
						},
						SecretsScannerConfig: services.SecretsScannerConfig{
							EnableSecretsScan: false,
						},
					},
				}},
				IsDefault: false,
			},
			expectedSastIssues:    1,
			expectedSecretsIssues: 0,
		},
		{
			name: "Enable secrets and sast",
			configProfile: services.ConfigProfile{
				ProfileName: "secrets&sast",
				Modules: []services.Module{{
					ModuleId:     1,
					ModuleName:   "secrets&sast-module",
					PathFromRoot: ".",
					ScanConfig: services.ScanConfig{
						SastScannerConfig: services.SastScannerConfig{
							EnableSastScan: true,
						},
						SecretsScannerConfig: services.SecretsScannerConfig{
							EnableSecretsScan: true,
						},
					},
				}},
				IsDefault: false,
			},
			expectedSastIssues:    1,
			expectedSecretsIssues: 7,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			mockServer, serverDetails := utils.XrayServer(t, utils.EntitlementsMinVersion)
			defer mockServer.Close()

			tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
			defer createTempDirCallback()
			testDirPath := filepath.Join("..", "..", "tests", "testdata", "projects", "jas", "jas")
			assert.NoError(t, biutils.CopyDir(testDirPath, tempDirPath, true, nil))

			auditBasicParams := (&utils.AuditBasicParams{}).
				SetServerDetails(serverDetails).
				SetOutputFormat(format.Table).
				SetUseJas(true)

			configProfile := testcase.configProfile
			auditParams := NewAuditParams().
				SetWorkingDirs([]string{tempDirPath}).
				SetGraphBasicParams(auditBasicParams).
				SetConfigProfile(&configProfile).
				SetCommonGraphScanParams(&scangraph.CommonGraphScanParams{
					RepoPath:               "",
					ScanType:               scanservices.Dependency,
					IncludeVulnerabilities: true,
					XscVersion:             services.ConfigProfileMinXscVersion,
					MultiScanId:            "random-msi",
				})
			auditParams.SetIsRecursiveScan(true)

			auditResults, err := RunAudit(auditParams)
			assert.NoError(t, err)

			// Currently, the only supported scanners are Secrets and Sast, therefore if a config profile is utilized - all other scanners are disabled.
			if testcase.expectedSastIssues > 0 {
				assert.NotNil(t, auditResults.ExtendedScanResults.SastScanResults)
				assert.Equal(t, testcase.expectedSastIssues, len(auditResults.ExtendedScanResults.SastScanResults[0].Results))
			} else {
				assert.Nil(t, auditResults.ExtendedScanResults.SastScanResults)
			}

			if testcase.expectedSecretsIssues > 0 {
				assert.NotNil(t, auditResults.ExtendedScanResults.SecretsScanResults)
				assert.Equal(t, testcase.expectedSecretsIssues, len(auditResults.ExtendedScanResults.SecretsScanResults[0].Results))
			} else {
				assert.Nil(t, auditResults.ExtendedScanResults.SecretsScanResults)
			}

			assert.Nil(t, auditResults.ScaResults)
			assert.Nil(t, auditResults.ExtendedScanResults.ApplicabilityScanResults)
			assert.Nil(t, auditResults.ExtendedScanResults.IacScanResults)
		})
	}
}

// This test tests audit flow when providing --output-dir flag
func TestAuditWithScansOutputDir(t *testing.T) {
	mockServer, serverDetails := utils.XrayServer(t, utils.EntitlementsMinVersion)
	defer mockServer.Close()

	outputDirPath, removeOutputDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer removeOutputDirCallback()

	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	testDirPath := filepath.Join("..", "..", "tests", "testdata", "projects", "jas", "jas")
	assert.NoError(t, biutils.CopyDir(testDirPath, tempDirPath, true, nil))

	auditBasicParams := (&utils.AuditBasicParams{}).
		SetServerDetails(serverDetails).
		SetOutputFormat(format.Table).
		SetUseJas(true)

	auditParams := NewAuditParams().
		SetWorkingDirs([]string{tempDirPath}).
		SetGraphBasicParams(auditBasicParams).
		SetCommonGraphScanParams(&scangraph.CommonGraphScanParams{
			ScanType:               scanservices.Dependency,
			IncludeVulnerabilities: true,
			MultiScanId:            utils.TestScaScanId,
		}).
		SetScansResultsOutputDir(outputDirPath)
	auditParams.SetIsRecursiveScan(true)

	_, err := RunAudit(auditParams)
	assert.NoError(t, err)

	filesList, err := fileutils.ListFiles(outputDirPath, false)
	assert.NoError(t, err)
	assert.Len(t, filesList, 5)

	var fileNamesWithoutSuffix []string
	for _, fileName := range filesList {
		// Removing <hash>.json suffix to so we can check by suffix all expected files exist
		splitName := strings.Split(fileName, "_")
		fileNamesWithoutSuffix = append(fileNamesWithoutSuffix, splitName[0])
	}

	assert.Contains(t, fileNamesWithoutSuffix, filepath.Join(outputDirPath, "sca"))
	assert.Contains(t, fileNamesWithoutSuffix, filepath.Join(outputDirPath, "iac"))
	assert.Contains(t, fileNamesWithoutSuffix, filepath.Join(outputDirPath, "sast"))
	assert.Contains(t, fileNamesWithoutSuffix, filepath.Join(outputDirPath, "secrets"))
	assert.Contains(t, fileNamesWithoutSuffix, filepath.Join(outputDirPath, "applicability"))
}
