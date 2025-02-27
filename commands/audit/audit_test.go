package audit

import (
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	commonCommands "github.com/jfrog/jfrog-cli-core/v2/common/commands"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	configTests "github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"

	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/validations"

	biutils "github.com/jfrog/build-info-go/utils"

	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	xrayServices "github.com/jfrog/jfrog-client-go/xray/services"
	xrayApi "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/jfrog/jfrog-client-go/xsc/services"
)

func TestDetectScansToPerform(t *testing.T) {

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
					JasResults: &results.JasScansResults{JasVulnerabilities: results.JasScanResults{}, JasViolations: results.JasScanResults{}},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Go,
						Target:     filepath.Join(dir, "dir", "go"),
					},
					JasResults: &results.JasScansResults{JasVulnerabilities: results.JasScanResults{}, JasViolations: results.JasScanResults{}},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "dir", "go", "go.mod")},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Maven,
						Target:     filepath.Join(dir, "dir", "maven"),
					},
					JasResults: &results.JasScansResults{JasVulnerabilities: results.JasScanResults{}, JasViolations: results.JasScanResults{}},
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
					JasResults: &results.JasScansResults{JasVulnerabilities: results.JasScanResults{}, JasViolations: results.JasScanResults{}},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "dir", "npm", "package.json")},
					},
				},
				{
					// We requested specific technologies, yarn is not in the list but we want to run JAS on it
					ScanTarget: results.ScanTarget{
						Target: filepath.Join(dir, "yarn"),
					},
					JasResults: &results.JasScansResults{JasVulnerabilities: results.JasScanResults{}, JasViolations: results.JasScanResults{}},
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
					JasResults: &results.JasScansResults{JasVulnerabilities: results.JasScanResults{}, JasViolations: results.JasScanResults{}},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "Nuget", "Nuget-sub", "project.csproj"), filepath.Join(dir, "Nuget", "project.sln")},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Go,
						Target:     filepath.Join(dir, "dir", "go"),
					},
					JasResults: &results.JasScansResults{JasVulnerabilities: results.JasScanResults{}, JasViolations: results.JasScanResults{}},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "dir", "go", "go.mod")},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Maven,
						Target:     filepath.Join(dir, "dir", "maven"),
					},
					JasResults: &results.JasScansResults{JasVulnerabilities: results.JasScanResults{}, JasViolations: results.JasScanResults{}},
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
					JasResults: &results.JasScansResults{JasVulnerabilities: results.JasScanResults{}, JasViolations: results.JasScanResults{}},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "dir", "npm", "package.json")},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Yarn,
						Target:     filepath.Join(dir, "yarn"),
					},
					JasResults: &results.JasScansResults{JasVulnerabilities: results.JasScanResults{}, JasViolations: results.JasScanResults{}},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "yarn", "package.json")},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Pip,
						Target:     filepath.Join(dir, "yarn", "Pip"),
					},
					JasResults: &results.JasScansResults{JasVulnerabilities: results.JasScanResults{}, JasViolations: results.JasScanResults{}},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "yarn", "Pip", "requirements.txt")},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Pipenv,
						Target:     filepath.Join(dir, "yarn", "Pipenv"),
					},
					JasResults: &results.JasScansResults{JasVulnerabilities: results.JasScanResults{}, JasViolations: results.JasScanResults{}},
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
		name                    string
		testDirPath             string
		configProfile           services.ConfigProfile
		expectedScaIssues       int
		expectedCaApplicable    int
		expectedCaUndetermined  int
		expectedCaNotCovered    int
		expectedCaNotApplicable int
		expectedSastIssues      int
		expectedSecretsIssues   int
		expectedIacIssues       int
	}{
		{
			name:        "Enable Sca scanner",
			testDirPath: filepath.Join("..", "..", "tests", "testdata", "projects", "jas", "jas"),
			configProfile: services.ConfigProfile{
				ProfileName: "Sca only",
				Modules: []services.Module{{
					ModuleId:     1,
					ModuleName:   "only-sca-module",
					PathFromRoot: ".",
					ScanConfig: services.ScanConfig{
						ScaScannerConfig: services.ScaScannerConfig{
							EnableScaScan: true,
						},
						ContextualAnalysisScannerConfig: services.CaScannerConfig{
							EnableCaScan: false,
						},
						SastScannerConfig: services.SastScannerConfig{
							EnableSastScan: false,
						},
						SecretsScannerConfig: services.SecretsScannerConfig{
							EnableSecretsScan: false,
						},
						IacScannerConfig: services.IacScannerConfig{
							EnableIacScan: false,
						},
					},
				}},
				IsDefault: false,
			},
			expectedScaIssues: 15,
		},
		{
			name:        "Sca scanner enabled with exclusions",
			testDirPath: filepath.Join("..", "..", "tests", "testdata", "projects", "jas", "jas"),
			configProfile: services.ConfigProfile{
				ProfileName: "Sca-exclude-dirs",
				Modules: []services.Module{{
					ModuleId:     1,
					ModuleName:   "Sca-exclude-dirs-module",
					PathFromRoot: ".",
					ScanConfig: services.ScanConfig{
						ScaScannerConfig: services.ScaScannerConfig{
							EnableScaScan:   true,
							ExcludePatterns: []string{"*.*"},
						},
						ContextualAnalysisScannerConfig: services.CaScannerConfig{
							EnableCaScan: false,
						},
						SastScannerConfig: services.SastScannerConfig{
							EnableSastScan: false,
						},
						SecretsScannerConfig: services.SecretsScannerConfig{
							EnableSecretsScan: false,
						},
						IacScannerConfig: services.IacScannerConfig{
							EnableIacScan: false,
						},
					},
				}},
				IsDefault: false,
			},
			expectedScaIssues: 0,
		},
		{
			name:        "Enable Sca and Applicability scanners",
			testDirPath: filepath.Join("..", "..", "tests", "testdata", "projects", "jas", "jas"),
			configProfile: services.ConfigProfile{
				ProfileName: "Sca&Applicability",
				Modules: []services.Module{{
					ModuleId:     1,
					ModuleName:   "sca-and-applicability",
					PathFromRoot: ".",
					ScanConfig: services.ScanConfig{
						ScaScannerConfig: services.ScaScannerConfig{
							EnableScaScan: true,
						},
						ContextualAnalysisScannerConfig: services.CaScannerConfig{
							EnableCaScan: true,
						},
						SastScannerConfig: services.SastScannerConfig{
							EnableSastScan: false,
						},
						SecretsScannerConfig: services.SecretsScannerConfig{
							EnableSecretsScan: false,
						},
						IacScannerConfig: services.IacScannerConfig{
							EnableIacScan: false,
						},
					},
				}},
				IsDefault: false,
			},
			expectedCaApplicable:    3,
			expectedCaUndetermined:  6,
			expectedCaNotCovered:    4,
			expectedCaNotApplicable: 2,
		},
		// TODO Add testcase for Sca and Applicability with exclusions after resolving the Glob patterns issues
		{
			name:        "Enable only secrets scanner",
			testDirPath: filepath.Join("..", "..", "tests", "testdata", "projects", "jas", "jas"),
			configProfile: services.ConfigProfile{
				ProfileName: "only-secrets",
				Modules: []services.Module{{
					ModuleId:     1,
					ModuleName:   "only-secrets-module",
					PathFromRoot: ".",
					ScanConfig: services.ScanConfig{
						ScaScannerConfig: services.ScaScannerConfig{
							EnableScaScan: false,
						},
						ContextualAnalysisScannerConfig: services.CaScannerConfig{
							EnableCaScan: false,
						},
						SastScannerConfig: services.SastScannerConfig{
							EnableSastScan: false,
						},
						SecretsScannerConfig: services.SecretsScannerConfig{
							EnableSecretsScan: true,
						},
						IacScannerConfig: services.IacScannerConfig{
							EnableIacScan: false,
						},
					},
				}},
				IsDefault: false,
			},
			expectedSecretsIssues: 16,
		},
		{
			name:        "Secrets scanner is enabled with exclusions",
			testDirPath: filepath.Join("..", "..", "tests", "testdata", "projects", "jas", "jas"),
			configProfile: services.ConfigProfile{
				ProfileName: "secrets-with-exclusions",
				Modules: []services.Module{{
					ModuleId:     1,
					ModuleName:   "secrets-with-exclusions-module",
					PathFromRoot: ".",
					ScanConfig: services.ScanConfig{
						ScaScannerConfig: services.ScaScannerConfig{
							EnableScaScan: false,
						},
						ContextualAnalysisScannerConfig: services.CaScannerConfig{
							EnableCaScan: false,
						},
						SastScannerConfig: services.SastScannerConfig{
							EnableSastScan: false,
						},
						SecretsScannerConfig: services.SecretsScannerConfig{
							EnableSecretsScan: true,
							ExcludePatterns:   []string{"*api_secrets*"},
						},
						IacScannerConfig: services.IacScannerConfig{
							EnableIacScan: false,
						},
					},
				}},
				IsDefault: false,
			},
			expectedSecretsIssues: 7,
		},
		{
			name:        "Enable only Sast scanner",
			testDirPath: filepath.Join("..", "..", "tests", "testdata", "projects", "jas", "jas"),
			configProfile: services.ConfigProfile{
				ProfileName: "only-sast",
				Modules: []services.Module{{
					ModuleId:     1,
					ModuleName:   "only-sast-module",
					PathFromRoot: ".",
					ScanConfig: services.ScanConfig{
						ScaScannerConfig: services.ScaScannerConfig{
							EnableScaScan: false,
						},
						ContextualAnalysisScannerConfig: services.CaScannerConfig{
							EnableCaScan: false,
						},
						SastScannerConfig: services.SastScannerConfig{
							EnableSastScan: true,
						},
						SecretsScannerConfig: services.SecretsScannerConfig{
							EnableSecretsScan: false,
						},
						IacScannerConfig: services.IacScannerConfig{
							EnableIacScan: false,
						},
					},
				}},
				IsDefault: false,
			},
			expectedSastIssues: 3,
		},
		{
			name:        "Sast scanner is enabled with exclusions",
			testDirPath: filepath.Join("..", "..", "tests", "testdata", "projects", "jas", "jas"),
			configProfile: services.ConfigProfile{
				ProfileName: "sast-with-exclusions",
				Modules: []services.Module{{
					ModuleId:     1,
					ModuleName:   "sast-with-exclusions-module",
					PathFromRoot: ".",
					ScanConfig: services.ScanConfig{
						ScaScannerConfig: services.ScaScannerConfig{
							EnableScaScan: false,
						},
						ContextualAnalysisScannerConfig: services.CaScannerConfig{
							EnableCaScan: false,
						},
						SastScannerConfig: services.SastScannerConfig{
							EnableSastScan:  true,
							ExcludePatterns: []string{"*flask_webgoat*"},
						},
						SecretsScannerConfig: services.SecretsScannerConfig{
							EnableSecretsScan: false,
						},
						IacScannerConfig: services.IacScannerConfig{
							EnableIacScan: false,
						},
					},
				}},
				IsDefault: false,
			},
			expectedSastIssues: 0,
		},
		{
			name:        "Enable only IaC scanner",
			testDirPath: filepath.Join("..", "..", "tests", "testdata", "projects", "jas", "jas"),
			configProfile: services.ConfigProfile{
				ProfileName: "only-sast",
				Modules: []services.Module{{
					ModuleId:     1,
					ModuleName:   "only-iac-module",
					PathFromRoot: ".",
					ScanConfig: services.ScanConfig{
						ScaScannerConfig: services.ScaScannerConfig{
							EnableScaScan: false,
						},
						ContextualAnalysisScannerConfig: services.CaScannerConfig{
							EnableCaScan: false,
						},
						SastScannerConfig: services.SastScannerConfig{
							EnableSastScan: false,
						},
						SecretsScannerConfig: services.SecretsScannerConfig{
							EnableSecretsScan: false,
						},
						IacScannerConfig: services.IacScannerConfig{
							EnableIacScan: true,
						},
					},
				}},
				IsDefault: false,
			},
			expectedIacIssues: 9,
		},
		{
			name:        "Iac is enabled with exclusions",
			testDirPath: filepath.Join("..", "..", "tests", "testdata", "projects", "jas", "jas"),
			configProfile: services.ConfigProfile{
				ProfileName: "iac-with-exclusions",
				Modules: []services.Module{{
					ModuleId:     1,
					ModuleName:   "iac-with-exclusions-module",
					PathFromRoot: ".",
					ScanConfig: services.ScanConfig{
						ScaScannerConfig: services.ScaScannerConfig{
							EnableScaScan: false,
						},
						ContextualAnalysisScannerConfig: services.CaScannerConfig{
							EnableCaScan: false,
						},
						SastScannerConfig: services.SastScannerConfig{
							EnableSastScan: false,
						},
						SecretsScannerConfig: services.SecretsScannerConfig{
							EnableSecretsScan: false,
						},
						IacScannerConfig: services.IacScannerConfig{
							EnableIacScan:   true,
							ExcludePatterns: []string{"*iac/gcp*"},
						},
					},
				}},
				IsDefault: false,
			},
			expectedIacIssues: 0,
		},
		{
			name:        "Enable All Scanners",
			testDirPath: filepath.Join("..", "..", "tests", "testdata", "projects", "jas", "jas"),
			configProfile: services.ConfigProfile{
				ProfileName: "all-jas-scanners",
				Modules: []services.Module{{
					ModuleId:     1,
					ModuleName:   "all-jas-module",
					PathFromRoot: ".",
					ScanConfig: services.ScanConfig{
						ScaScannerConfig: services.ScaScannerConfig{
							EnableScaScan: true,
						},
						ContextualAnalysisScannerConfig: services.CaScannerConfig{
							EnableCaScan: true,
						},
						SastScannerConfig: services.SastScannerConfig{
							EnableSastScan: true,
						},
						SecretsScannerConfig: services.SecretsScannerConfig{
							EnableSecretsScan: true,
						},
						IacScannerConfig: services.IacScannerConfig{
							EnableIacScan: true,
						},
					},
				}},
				IsDefault: false,
			},
			expectedSastIssues:      3,
			expectedSecretsIssues:   16,
			expectedIacIssues:       9,
			expectedCaApplicable:    3,
			expectedCaUndetermined:  6,
			expectedCaNotCovered:    4,
			expectedCaNotApplicable: 2,
		},
		{
			name:        "All scanners enabled but some with exclude patterns",
			testDirPath: filepath.Join("..", "..", "tests", "testdata", "projects", "jas", "jas"),
			configProfile: services.ConfigProfile{
				ProfileName: "some-scanners-with-exclusions",
				Modules: []services.Module{{
					ModuleId:     1,
					ModuleName:   "some-scanners-with-exclusions-module",
					PathFromRoot: ".",
					ScanConfig: services.ScanConfig{
						ScaScannerConfig: services.ScaScannerConfig{
							EnableScaScan: true,
						},
						ContextualAnalysisScannerConfig: services.CaScannerConfig{
							EnableCaScan: true,
						},
						SastScannerConfig: services.SastScannerConfig{
							EnableSastScan:  true,
							ExcludePatterns: []string{"*flask_webgoat*"},
						},
						SecretsScannerConfig: services.SecretsScannerConfig{
							EnableSecretsScan: true,
							ExcludePatterns:   []string{"*api_secrets*"},
						},
						IacScannerConfig: services.IacScannerConfig{
							EnableIacScan: true,
						},
					},
				}},
				IsDefault: false,
			},
			expectedSastIssues:      0,
			expectedSecretsIssues:   7,
			expectedIacIssues:       9,
			expectedCaApplicable:    3,
			expectedCaUndetermined:  6,
			expectedCaNotCovered:    4,
			expectedCaNotApplicable: 2,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			mockServer, serverDetails := validations.XrayServer(t, validations.MockServerParams{XrayVersion: utils.EntitlementsMinVersion, XscVersion: services.ConfigProfileMinXscVersion})
			defer mockServer.Close()

			tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
			defer createTempDirCallback()
			assert.NoError(t, biutils.CopyDir(testcase.testDirPath, tempDirPath, true, nil))

			configProfile := testcase.configProfile
			auditBasicParams := (&utils.AuditBasicParams{}).
				SetServerDetails(serverDetails).
				SetXrayVersion(utils.EntitlementsMinVersion).
				SetXscVersion(services.ConfigProfileMinXscVersion).
				SetOutputFormat(format.Table).
				SetUseJas(true).
				SetConfigProfile(&configProfile)

			auditParams := NewAuditParams().
				SetWorkingDirs([]string{tempDirPath}).
				SetMultiScanId(validations.TestMsi).
				SetGraphBasicParams(auditBasicParams).
				SetResultsContext(results.ResultContext{IncludeVulnerabilities: true})

			auditParams.SetWorkingDirs([]string{tempDirPath}).SetIsRecursiveScan(true)
			auditResults := RunAudit(auditParams)
			assert.NoError(t, auditResults.GetErrors())

			summary, err := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{IncludeVulnerabilities: true}).ConvertToSummary(auditResults)
			assert.NoError(t, err)

			var scaResultsCount int
			// When checking Applicability results with ExactResultsMatch = true, the sum of all statuses should equal total Sca results amount. Else, we check the provided Sca issues amount
			if testcase.expectedCaApplicable > 0 || testcase.expectedCaNotApplicable > 0 || testcase.expectedCaNotCovered > 0 || testcase.expectedCaUndetermined > 0 {
				scaResultsCount = testcase.expectedCaApplicable + testcase.expectedCaNotApplicable + testcase.expectedCaNotCovered + testcase.expectedCaUndetermined
			} else {
				scaResultsCount = testcase.expectedScaIssues
			}
			validations.ValidateCommandSummaryOutput(t, validations.ValidationParams{
				Actual:            summary,
				ExactResultsMatch: true,
				Total:             &validations.TotalCount{Vulnerabilities: testcase.expectedSastIssues + testcase.expectedSecretsIssues + testcase.expectedIacIssues + scaResultsCount},
				Vulnerabilities: &validations.VulnerabilityCount{
					ValidateScan:                &validations.ScanCount{Sca: scaResultsCount, Sast: testcase.expectedSastIssues, Secrets: testcase.expectedSecretsIssues, Iac: testcase.expectedIacIssues},
					ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Applicable: testcase.expectedCaApplicable, NotApplicable: testcase.expectedCaNotApplicable, NotCovered: testcase.expectedCaNotCovered, Undetermined: testcase.expectedCaUndetermined},
				},
			})
		})
	}
}

// This test tests audit flow when providing --output-dir flag
func TestAuditWithScansOutputDir(t *testing.T) {
	mockServer, serverDetails := validations.XrayServer(t, validations.MockServerParams{XrayVersion: utils.EntitlementsMinVersion})
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
		SetXrayVersion(utils.EntitlementsMinVersion).
		SetUseJas(true)

	auditParams := NewAuditParams().
		SetWorkingDirs([]string{tempDirPath}).
		SetMultiScanId(validations.TestScaScanId).
		SetGraphBasicParams(auditBasicParams).
		SetResultsContext(results.ResultContext{IncludeVulnerabilities: true}).
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
				SetXrayVersion("3.108.0").
				SetUseJas(testcase.useJas).
				SetAllowPartialResults(testcase.allowPartialResults).
				SetPipRequirementsFile(testcase.pipRequirementsFile)

			auditParams := NewAuditParams().
				SetWorkingDirs([]string{tempDirPath}).
				SetMultiScanId(validations.TestScaScanId).
				SetGraphBasicParams(auditBasicParams).
				SetResultsContext(results.ResultContext{IncludeVulnerabilities: true})
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

func TestCreateResultsContext(t *testing.T) {
	mockWatches := []string{"watch-1", "watch-2"}
	mockProjectKey := "project"
	mockArtifactoryRepoPath := "repo/path"

	tests := []struct {
		name                    string
		xrayVersion             string
		expectedPlatformWatches xrayApi.ResourcesWatchesBody
	}{
		{
			name:                    "Git Repo Url Supported",
			xrayVersion:             xrayServices.MinXrayVersionGitRepoKey,
			expectedPlatformWatches: xrayApi.ResourcesWatchesBody{GitRepositoryWatches: mockWatches},
		},
		{
			name:        "Git Repo Url Not Supported (Backward Compatibility)",
			xrayVersion: "1.0.0",
		},
	}
	for _, test := range tests {
		testCaseExpectedGitRepoHttpsCloneUrl := ""
		expectedIncludeVulnerabilitiesIfOnlyGitRepoUrlProvided := false
		if len(test.expectedPlatformWatches.GitRepositoryWatches) > 0 {
			// We should include the value of gitRepoUrl only if a watch is assigned to this git_repository
			testCaseExpectedGitRepoHttpsCloneUrl = validations.TestMockGitInfo.GitRepoHttpsCloneUrl
		} else {
			// If only the git repo url is provided but not supported or there are no defined watches, the expected includeVulnerabilities flag should be set to true even if not provided
			expectedIncludeVulnerabilitiesIfOnlyGitRepoUrlProvided = true
		}
		testCases := []struct {
			name string

			artifactoryRepoPath    string
			httpCloneUrl           string
			watches                []string
			jfrogProjectKey        string
			includeVulnerabilities bool
			includeLicenses        bool
			includeSbom            bool

			expectedArtifactoryRepoPath    string
			expectedHttpCloneUrl           string
			expectedWatches                []string
			expectedJfrogProjectKey        string
			expectedIncludeVulnerabilities bool
			expectedIncludeLicenses        bool
			expectedIncludeSbom            bool
		}{
			{
				name:            "Only Vulnerabilities",
				includeLicenses: true,
				includeSbom:     true,
				// Since no violation context is provided, the includeVulnerabilities flag should be set to true even if not provided
				expectedIncludeVulnerabilities: true,
				expectedIncludeLicenses:        true,
				expectedIncludeSbom:            true,
			},
			{
				name:            "Watches",
				watches:         mockWatches,
				expectedWatches: mockWatches,
			},
			{
				name:                        "Artifactory Repo Path",
				artifactoryRepoPath:         mockArtifactoryRepoPath,
				expectedArtifactoryRepoPath: mockArtifactoryRepoPath,
			},
			{
				name:                    "Project key",
				jfrogProjectKey:         mockProjectKey,
				expectedJfrogProjectKey: mockProjectKey,
				includeLicenses:         true,
				expectedIncludeLicenses: true,
			},
			{
				name:                           "Git Clone Url",
				httpCloneUrl:                   validations.TestMockGitInfo.GitRepoHttpsCloneUrl,
				expectedHttpCloneUrl:           testCaseExpectedGitRepoHttpsCloneUrl,
				expectedIncludeVulnerabilities: expectedIncludeVulnerabilitiesIfOnlyGitRepoUrlProvided,
			},
			{
				name:                   "All",
				httpCloneUrl:           validations.TestMockGitInfo.GitRepoHttpsCloneUrl,
				watches:                mockWatches,
				jfrogProjectKey:        mockProjectKey,
				includeVulnerabilities: true,
				includeLicenses:        true,
				includeSbom:            true,

				expectedHttpCloneUrl:           testCaseExpectedGitRepoHttpsCloneUrl,
				expectedWatches:                mockWatches,
				expectedJfrogProjectKey:        mockProjectKey,
				expectedIncludeVulnerabilities: true,
				expectedIncludeLicenses:        true,
				expectedIncludeSbom:            true,
			},
		}
		for _, testCase := range testCases {
			t.Run(fmt.Sprintf("%s - %s", test.name, testCase.name), func(t *testing.T) {
				mockServer, serverDetails := validations.XrayServer(t, validations.MockServerParams{XrayVersion: test.xrayVersion, ReturnMockPlatformWatches: test.expectedPlatformWatches})
				defer mockServer.Close()
				context := CreateAuditResultsContext(serverDetails, test.xrayVersion, testCase.watches, testCase.artifactoryRepoPath, testCase.jfrogProjectKey, testCase.httpCloneUrl, testCase.includeVulnerabilities, testCase.includeLicenses, testCase.includeSbom)
				assert.Equal(t, testCase.expectedArtifactoryRepoPath, context.RepoPath)
				assert.Equal(t, testCase.expectedHttpCloneUrl, context.GitRepoHttpsCloneUrl)
				assert.Equal(t, testCase.expectedWatches, context.Watches)
				assert.Equal(t, testCase.expectedJfrogProjectKey, context.ProjectKey)
				assert.Equal(t, testCase.expectedIncludeVulnerabilities, context.IncludeVulnerabilities)
				assert.Equal(t, testCase.expectedIncludeLicenses, context.IncludeLicenses)
				assert.Equal(t, testCase.expectedIncludeSbom, context.IncludeSbom)
			})
		}
	}
}
