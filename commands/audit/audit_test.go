package audit

import (
	"fmt"
	commonCommands "github.com/jfrog/jfrog-cli-core/v2/common/commands"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	configTests "github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/validations"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"

	biutils "github.com/jfrog/build-info-go/utils"

	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	scanservices "github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/jfrog/jfrog-client-go/xsc/services"
)

func TestDetectScansToPreform(t *testing.T) {

	dir, cleanUp := createTestDir(t)

	tests := []struct {
		name     string
		wd       string
		params   func() *AuditParams
		expected []*results.TargetResults
	}{
		{
			name: "Test specific technologies",
			wd:   dir,
			params: func() *AuditParams {
				param := NewAuditParams().SetWorkingDirs([]string{dir})
				param.SetTechnologies([]string{"maven", "npm", "go"}).SetIsRecursiveScan(true)
				return param
			},
			expected: []*results.TargetResults{
				{
					// We requested specific technologies, Nuget is not in the list but we want to run JAS on it
					ScanTarget: results.ScanTarget{
						Target: filepath.Join(dir, "Nuget"),
					},
					JasResults: &results.JasScansResults{},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Go,
						Target:     filepath.Join(dir, "dir", "go"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "dir", "go", "go.mod")},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Maven,
						Target:     filepath.Join(dir, "dir", "maven"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{
							filepath.Join(dir, "dir", "maven", "maven-sub", "pom.xml"),
							filepath.Join(dir, "dir", "maven", "maven-sub2", "pom.xml"),
							filepath.Join(dir, "dir", "maven", "pom.xml"),
						},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Npm,
						Target:     filepath.Join(dir, "dir", "npm"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "dir", "npm", "package.json")},
					},
				},
				{
					// We requested specific technologies, yarn is not in the list but we want to run JAS on it
					ScanTarget: results.ScanTarget{
						Target: filepath.Join(dir, "yarn"),
					},
					JasResults: &results.JasScansResults{},
				},
			},
		},
		{
			name: "Test all",
			wd:   dir,
			params: func() *AuditParams {
				param := NewAuditParams().SetWorkingDirs([]string{dir})
				param.SetIsRecursiveScan(true)
				return param
			},
			expected: []*results.TargetResults{
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Nuget,
						Target:     filepath.Join(dir, "Nuget"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "Nuget", "Nuget-sub", "project.csproj"), filepath.Join(dir, "Nuget", "project.sln")},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Go,
						Target:     filepath.Join(dir, "dir", "go"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "dir", "go", "go.mod")},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Maven,
						Target:     filepath.Join(dir, "dir", "maven"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{
							filepath.Join(dir, "dir", "maven", "maven-sub", "pom.xml"),
							filepath.Join(dir, "dir", "maven", "maven-sub2", "pom.xml"),
							filepath.Join(dir, "dir", "maven", "pom.xml"),
						},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Npm,
						Target:     filepath.Join(dir, "dir", "npm"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "dir", "npm", "package.json")},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Yarn,
						Target:     filepath.Join(dir, "yarn"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "yarn", "package.json")},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Pip,
						Target:     filepath.Join(dir, "yarn", "Pip"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "yarn", "Pip", "requirements.txt")},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Pipenv,
						Target:     filepath.Join(dir, "yarn", "Pipenv"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "yarn", "Pipenv", "Pipfile")},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := results.NewCommandResults(utils.SourceCode).SetEntitledForJas(true).SetSecretValidation(true)
			detectScanTargets(results, test.params())
			if assert.Len(t, results.Targets, len(test.expected)) {
				sort.Slice(results.Targets, func(i, j int) bool {
					return results.Targets[i].ScanTarget.Target < results.Targets[j].ScanTarget.Target
				})
				sort.Slice(test.expected, func(i, j int) bool {
					return test.expected[i].ScanTarget.Target < test.expected[j].ScanTarget.Target
				})
				for i := range results.Targets {
					if results.Targets[i].ScaResults != nil {
						sort.Strings(results.Targets[i].ScaResults.Descriptors)
					}
					if test.expected[i].ScaResults != nil {
						sort.Strings(test.expected[i].ScaResults.Descriptors)
					}
				}
			}
			assert.ElementsMatch(t, test.expected, results.Targets)
		})
	}

	cleanUp()
}

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
			mockServer, serverDetails := validations.XrayServer(t, utils.EntitlementsMinVersion)
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

			auditParams.SetWorkingDirs([]string{tempDirPath}).SetIsRecursiveScan(true)
			auditResults := RunAudit(auditParams)
			assert.NoError(t, auditResults.GetErrors())

			// Currently, the only supported scanners are Secrets and Sast, therefore if a config profile is utilized - all other scanners are disabled.
			summary, err := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{IncludeVulnerabilities: true, HasViolationContext: true}).ConvertToSummary(auditResults)
			assert.NoError(t, err)
			// Validate Sast and Secrets have the expected number of issues and that Iac and Sca did not run
			validations.ValidateCommandSummaryOutput(t, validations.ValidationParams{Actual: summary, ExactResultsMatch: true, Sast: testcase.expectedSastIssues, Secrets: testcase.expectedSecretsIssues, Vulnerabilities: testcase.expectedSastIssues + testcase.expectedSecretsIssues})
		})
	}
}

// This test tests audit flow when providing --output-dir flag
func TestAuditWithScansOutputDir(t *testing.T) {
	mockServer, serverDetails := validations.XrayServer(t, utils.EntitlementsMinVersion)
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
			MultiScanId:            validations.TestScaScanId,
		}).
		SetScansResultsOutputDir(outputDirPath)
	auditParams.SetIsRecursiveScan(true)

	auditResults := RunAudit(auditParams)
	assert.NoError(t, auditResults.GetErrors())

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
		pipRequirementsFile string
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
			name:                "Failure in JAS scans",
			allowPartialResults: false,
			useJas:              true,
			pipRequirementsFile: "requirements.txt",
			testDirPath:         filepath.Join("..", "..", "tests", "testdata", "projects", "jas", "jas", "npm-project"),
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
		{
			name:                "Skip failure in JAS scans",
			allowPartialResults: true,
			useJas:              true,
			pipRequirementsFile: "requirements.txt",
			testDirPath:         filepath.Join("..", "..", "tests", "testdata", "projects", "jas", "jas", "npm-project"),
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			serverMock, serverDetails := validations.CreateXrayRestsMockServer(func(w http.ResponseWriter, r *http.Request) {
				if r.RequestURI == "/xray/api/v1/system/version" {
					_, err := w.Write([]byte(fmt.Sprintf(`{"xray_version": "%s", "xray_revision": "xxx"}`, utils.EntitlementsMinVersion)))
					if !assert.NoError(t, err) {
						return
					}
				}
				// All endpoints required to test failures in SCA scan
				if !testcase.useJas {
					if strings.Contains(r.RequestURI, "/xray/api/v1/scan/graph") && r.Method == http.MethodPost {
						// We set SCA scan graph API to fail
						w.WriteHeader(http.StatusBadRequest)
					}
				}

				// All endpoints required to test failures in JAS
				if testcase.useJas {
					if strings.Contains(r.RequestURI, "/xsc-gen-exe-analyzer-manager-local/v1") {
						w.WriteHeader(http.StatusBadRequest)
					}
					if strings.Contains(r.RequestURI, "api/v1/entitlements/feature/contextual_analysis") && r.Method == http.MethodGet {
						_, err := w.Write([]byte(`{"entitled":true,"feature_id":"contextual_analysis"}`))
						if !assert.NoError(t, err) {
							return
						}
					}
				}

			})
			defer serverMock.Close()

			tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
			defer createTempDirCallback()

			if testcase.useJas {
				// In order to simulate failure in Jas process we fail the AM download by using the mock server for the download and failing the endpoint call there
				clientTests.SetEnvAndAssert(t, coreutils.HomeDir, filepath.Join(tempDirPath, configTests.Out, "jfroghome"))
				err := commonCommands.NewConfigCommand(commonCommands.AddOrEdit, "testServer").SetDetails(serverDetails).SetInteractive(false).SetEncPassword(false).Run()
				assert.NoError(t, err)
				defer securityTestUtils.CleanTestsHomeEnv()

				callbackEnv := clientTests.SetEnvWithCallbackAndAssert(t, coreutils.ReleasesRemoteEnv, "testServer/testRemoteRepo")
				defer callbackEnv()
			}

			assert.NoError(t, biutils.CopyDir(testcase.testDirPath, tempDirPath, false, nil))

			auditBasicParams := (&utils.AuditBasicParams{}).
				SetServerDetails(serverDetails).
				SetOutputFormat(format.Table).
				SetUseJas(testcase.useJas).
				SetAllowPartialResults(testcase.allowPartialResults).
				SetPipRequirementsFile(testcase.pipRequirementsFile)

			auditParams := NewAuditParams().
				SetWorkingDirs([]string{tempDirPath}).
				SetGraphBasicParams(auditBasicParams).
				SetCommonGraphScanParams(&scangraph.CommonGraphScanParams{
					ScanType:               scanservices.Dependency,
					IncludeVulnerabilities: true,
					MultiScanId:            validations.TestScaScanId,
				})
			auditParams.SetIsRecursiveScan(true)

			auditResults := RunAudit(auditParams)
			if testcase.allowPartialResults {
				assert.NoError(t, auditResults.GetErrors())
			} else {
				assert.Error(t, auditResults.GetErrors())
			}
		})
	}
}
