package audit

import (
	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"
	"github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
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

			auditBasicParams := (&utils.AuditBasicParams{}).
				SetServerDetails(serverDetails).
				SetOutputFormat(format.Table).
				SetUseJas(true)

			configProfile := testcase.configProfile
			auditParams := NewAuditParams().
				SetGraphBasicParams(auditBasicParams).
				SetConfigProfile(&configProfile).
				SetCommonGraphScanParams(&scangraph.CommonGraphScanParams{
					RepoPath:               "",
					ProjectKey:             "",
					Watches:                nil,
					ScanType:               "dependency",
					IncludeVulnerabilities: true,
					XscVersion:             services.ConfigProfileMinXscVersion,
					MultiScanId:            "random-msi",
				})
			auditParams.SetIsRecursiveScan(true)

			tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
			defer createTempDirCallback()
			testDirPath := filepath.Join("..", "..", "tests", "testdata", "projects", "jas", "jas")
			assert.NoError(t, biutils.CopyDir(testDirPath, tempDirPath, true, nil))

			baseWd, err := os.Getwd()
			assert.NoError(t, err)
			chdirCallback := clientTests.ChangeDirWithCallback(t, baseWd, tempDirPath)
			defer chdirCallback()

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
