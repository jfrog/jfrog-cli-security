package audit

import (
	"path/filepath"
	"sort"
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
					ScanTarget: results.ScanTarget{
						Technology: techutils.Maven,
						Target:     filepath.Join(dir, "dir", "maven"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{
							filepath.Join(dir, "dir", "maven", "pom.xml"),
							filepath.Join(dir, "dir", "maven", "maven-sub", "pom.xml"),
							filepath.Join(dir, "dir", "maven", "maven-sub2", "pom.xml"),
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
						Technology: techutils.Go,
						Target:     filepath.Join(dir, "dir", "go"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "dir", "go", "go.mod")},
					},
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
						Technology: techutils.Maven,
						Target:     filepath.Join(dir, "dir", "maven"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{
							filepath.Join(dir, "dir", "maven", "pom.xml"),
							filepath.Join(dir, "dir", "maven", "maven-sub", "pom.xml"),
							filepath.Join(dir, "dir", "maven", "maven-sub2", "pom.xml"),
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
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Nuget,
						Target:     filepath.Join(dir, "Nuget"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "Nuget", "project.sln"), filepath.Join(dir, "Nuget", "Nuget-sub", "project.csproj")},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := results.NewCommandResults(utils.SourceCode, "", true)
			detectScanTargets(results, test.params())
			if assert.Len(t, results.Targets, len(test.expected)) {
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
			auditResults, err := RunAudit(auditParams)
			assert.NoError(t, err)

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
