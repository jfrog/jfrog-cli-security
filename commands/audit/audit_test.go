package audit

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	scanservices "github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/stretchr/testify/assert"
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
			expectedSecretsIssues: 16,
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
			expectedSecretsIssues: 16,
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

	searchForStrWithSubString(t, filesList, "sca_results")
	searchForStrWithSubString(t, filesList, "iac_results")
	searchForStrWithSubString(t, filesList, "sast_results")
	searchForStrWithSubString(t, filesList, "secrets_results")
	searchForStrWithSubString(t, filesList, "applicability_results")
}

func searchForStrWithSubString(t *testing.T, filesList []string, subString string) {
	for _, file := range filesList {
		if strings.Contains(file, subString) {
			return
		}
	}
	assert.Fail(t, "File %s not found in the list", subString)
}

func TestAuditWithPartialResults(t *testing.T) {
	testcases := []struct {
		name                string
		allowPartialResults bool
		useJas              bool
		testDirPath         string
	}{
		{
			name:                "Failure in SCA during dependency tree construction",
			allowPartialResults: false,
			useJas:              false,
			testDirPath:         filepath.Join("..", "..", "tests", "testdata", "projects", "package-managers", "npm", "npm-un-installable"),
		},
		{
			name:                "Failure in SCA during scan itself",
			allowPartialResults: false,
			useJas:              false,
			testDirPath:         filepath.Join("..", "..", "tests", "testdata", "projects", "package-managers", "npm", "npm-project"),
		},
		{
			name:                "Skip failure in SCA during dependency tree construction",
			allowPartialResults: true,
			useJas:              false,
			testDirPath:         filepath.Join("..", "..", "tests", "testdata", "projects", "package-managers", "npm", "npm-un-installable"),
		},
		{
			name:                "Skip failure in SCA during scan itself",
			allowPartialResults: true,
			useJas:              false,
			testDirPath:         filepath.Join("..", "..", "tests", "testdata", "projects", "package-managers", "npm", "npm-project"),
		},
		// TODO when applying allow-partial-results to JAS make sure to add a test case that checks failures in JAS scans + add  some JAS api call to the mock server
	}

	serverMock, serverDetails := utils.CreateXrayRestsMockServer(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI == "/xray/api/v1/system/version" {
			_, err := w.Write([]byte(fmt.Sprintf(`{"xray_version": "%s", "xray_revision": "xxx"}`, scangraph.GraphScanMinXrayVersion)))
			if !assert.NoError(t, err) {
				return
			}
		}
		if strings.HasPrefix(r.RequestURI, "/xray/api/v1/scan/graph") && r.Method == http.MethodPost {
			// We set SCA scan graph API to fail
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	defer serverMock.Close()

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
			defer createTempDirCallback()

			assert.NoError(t, biutils.CopyDir(testcase.testDirPath, tempDirPath, false, nil))

			auditBasicParams := (&utils.AuditBasicParams{}).
				SetServerDetails(serverDetails).
				SetOutputFormat(format.Table).
				SetUseJas(testcase.useJas).
				SetAllowPartialResults(testcase.allowPartialResults)

			auditParams := NewAuditParams().
				SetWorkingDirs([]string{tempDirPath}).
				SetGraphBasicParams(auditBasicParams).
				SetCommonGraphScanParams(&scangraph.CommonGraphScanParams{
					ScanType:               scanservices.Dependency,
					IncludeVulnerabilities: true,
					MultiScanId:            utils.TestScaScanId,
				})
			auditParams.SetIsRecursiveScan(true)

			scanResults, err := RunAudit(auditParams)
			if testcase.allowPartialResults {
				assert.NoError(t, scanResults.ScansErr)
				assert.NoError(t, err)
			} else {
				assert.Error(t, scanResults.ScansErr)
				assert.NoError(t, err)
			}
		})
	}
}

func TestCreateErrorIfPartialResultsDisabled(t *testing.T) {
	testcases := []struct {
		name                string
		allowPartialResults bool
		auditParallelRunner bool
	}{
		{
			name:                "Allow partial results - no error expected",
			allowPartialResults: true,
			auditParallelRunner: true,
		},
		{
			name:                "Partial results disabled with SecurityParallelRunner",
			allowPartialResults: false,
			auditParallelRunner: true,
		},
		{
			name:                "Partial results disabled without SecurityParallelRunner",
			allowPartialResults: false,
			auditParallelRunner: false,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			auditBasicParams := (&utils.AuditBasicParams{}).SetAllowPartialResults(testcase.allowPartialResults)
			auditParams := NewAuditParams().SetGraphBasicParams(auditBasicParams)

			var auditParallelRunner *utils.SecurityParallelRunner
			if testcase.auditParallelRunner {
				auditParallelRunner = utils.CreateSecurityParallelRunner(1)
			}

			err := createErrorIfPartialResultsDisabled(auditParams, auditParallelRunner, "", errors.New("error"))
			if testcase.allowPartialResults {
				assert.NoError(t, err)
			} else {
				if testcase.auditParallelRunner {
					assert.False(t, isErrorsQueueEmpty(auditParallelRunner))
				} else {
					assert.Error(t, err)
				}
			}
		})
	}
}

func isErrorsQueueEmpty(spr *utils.SecurityParallelRunner) bool {
	select {
	case <-spr.ErrorsQueue:
		// Channel is not empty
		return false
	default:
		// Channel is empty
		return true
	}
}
