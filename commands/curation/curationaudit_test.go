package curation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/gofrog/datastructures"
	coreCommonTests "github.com/jfrog/jfrog-cli-core/v2/common/tests"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	testUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	clienttestutils "github.com/jfrog/jfrog-client-go/utils/tests"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var TestDataDir = filepath.Join("..", "..", "tests", "testdata")

func TestExtractPoliciesFromMsg(t *testing.T) {
	var err error
	extractPoliciesRegex := regexp.MustCompile(extractPoliciesRegexTemplate)
	assert.NoError(t, err)
	tests := getTestCasesForExtractPoliciesFromMsg()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ta := treeAnalyzer{extractPoliciesRegex: extractPoliciesRegex}
			got := ta.extractPoliciesFromMsg(tt.errResp)
			assert.Equal(t, tt.expect, got)
		})
	}
}

func getTestCasesForExtractPoliciesFromMsg() []struct {
	name    string
	errResp *ErrorsResp
	expect  []Policy
} {
	tests := []struct {
		name    string
		errResp *ErrorsResp
		expect  []Policy
	}{
		{
			name: "one policy",
			errResp: &ErrorsResp{
				Errors: []ErrorResp{
					{
						Status:  403,
						Message: "Package test:1.0.0 download was blocked by JFrog Packages Curation service due to the following policies violated {policy1, condition1}.",
					},
				},
			},
			expect: []Policy{
				{
					Policy:    "policy1",
					Condition: "condition1",
				},
			},
		},
		{
			name: "one policy",
			errResp: &ErrorsResp{
				Errors: []ErrorResp{
					{
						Status:  403,
						Message: "Package test:1.0.0 download was blocked by JFrog Packages Curation service due to the following policies violated {policy1, condition1, Package is 3339 days old, Upgrade to version 0.2.4 (latest)}.",
					},
				},
			},
			expect: []Policy{
				{
					Policy:         "policy1",
					Condition:      "condition1",
					Explanation:    "Package is 3339 days old",
					Recommendation: "Upgrade to version 0.2.4 (latest)",
				},
			},
		},
		{
			name: "two policies",
			errResp: &ErrorsResp{
				Errors: []ErrorResp{
					{
						Status: 403,
						Message: "Package test:1.0.0 download was blocked by JFrog Packages Curation service due to" +
							" the following policies violated {policy1, condition1}, {policy2, condition2}.",
					},
				},
			},
			expect: []Policy{
				{
					Policy:    "policy1",
					Condition: "condition1",
				},
				{
					Policy:    "policy2",
					Condition: "condition2",
				},
			},
		},
		{
			name: "no policies",
			errResp: &ErrorsResp{
				Errors: []ErrorResp{
					{
						Status:  403,
						Message: "not the expected message format.",
					},
				},
			},
			expect: nil,
		},
	}
	return tests
}

func TestGetNameScopeAndVersion(t *testing.T) {
	tests := []struct {
		name            string
		componentId     string
		artiUrl         string
		repo            string
		tech            string
		wantDownloadUrl string
		wantName        string
		wantVersion     string
		wantScope       string
	}{
		{
			name:            "npm component",
			componentId:     "npm://test:1.0.0",
			artiUrl:         "http://localhost:8000/artifactory",
			repo:            "npm",
			tech:            techutils.Npm.String(),
			wantDownloadUrl: "http://localhost:8000/artifactory/api/npm/npm/test/-/test-1.0.0.tgz",
			wantName:        "test",
			wantVersion:     "1.0.0",
		},
		{
			name:            "npm component with scope",
			componentId:     "npm://dev/test:1.0.0",
			artiUrl:         "http://localhost:8000/artifactory",
			repo:            "npm",
			tech:            techutils.Npm.String(),
			wantDownloadUrl: "http://localhost:8000/artifactory/api/npm/npm/dev/test/-/test-1.0.0.tgz",
			wantName:        "test",
			wantVersion:     "1.0.0",
			wantScope:       "dev",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDownloadUrl, gotName, gotScope, gotVersion := getNpmNameScopeAndVersion(tt.componentId, tt.artiUrl, tt.repo, tt.repo)
			assert.Equal(t, tt.wantDownloadUrl, gotDownloadUrl[0], "getNameScopeAndVersion() gotDownloadUrl = %v, want %v", gotDownloadUrl[0], tt.wantDownloadUrl)
			assert.Equal(t, tt.wantName, gotName, "getNpmNameScopeAndVersion() gotName = %v, want %v", gotName, tt.wantName)
			assert.Equal(t, tt.wantScope, gotScope, "getNpmNameScopeAndVersion() gotScope = %v, want %v", gotScope, tt.wantScope)
			assert.Equal(t, tt.wantVersion, gotVersion, "getNpmNameScopeAndVersion() gotVersion = %v, want %v", gotVersion, tt.wantVersion)
		})
	}
}

func TestTreeAnalyzerFillGraphRelations(t *testing.T) {
	tests := getTestCasesForFillGraphRelations()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nc := &treeAnalyzer{
				url:  "http://localhost:8046/artifactory",
				repo: "npm-repo",
				tech: "npm",
			}
			var packageStatus []*PackageStatus
			preProcessedMap := fillSyncedMap(tt.givenMap)
			nc.fillGraphRelations(tt.givenGraph, preProcessedMap, &packageStatus, "", "", datastructures.MakeSet[string](), true)
			sort.Slice(packageStatus, func(i, j int) bool {
				if packageStatus[i].BlockedPackageUrl == packageStatus[j].BlockedPackageUrl {
					return packageStatus[i].ParentName < packageStatus[j].ParentName
				}
				return packageStatus[i].BlockedPackageUrl < packageStatus[j].BlockedPackageUrl
			})
			sort.Slice(tt.expectedPackagesStatus, func(i, j int) bool {
				if tt.expectedPackagesStatus[i].BlockedPackageUrl == tt.expectedPackagesStatus[j].BlockedPackageUrl {
					return tt.expectedPackagesStatus[i].ParentName < tt.expectedPackagesStatus[j].ParentName
				}
				return tt.expectedPackagesStatus[i].BlockedPackageUrl < tt.expectedPackagesStatus[j].BlockedPackageUrl
			})
			assert.Equal(t, tt.expectedPackagesStatus, packageStatus)
		})
	}
}

func getTestCasesForFillGraphRelations() []struct {
	name                   string
	givenGraph             *xrayUtils.GraphNode
	givenMap               []*PackageStatus
	expectedPackagesStatus []*PackageStatus
} {
	tests := []struct {
		name                   string
		givenGraph             *xrayUtils.GraphNode
		givenMap               []*PackageStatus
		expectedPackagesStatus []*PackageStatus
	}{
		{
			name: "block indirect",
			givenGraph: &xrayUtils.GraphNode{
				Id: "npm://root-test",
				Nodes: []*xrayUtils.GraphNode{
					{
						Id: "npm://test-parent:1.0.0",
						Nodes: []*xrayUtils.GraphNode{
							{Id: "npm://test-child:2.0.0"},
						},
					},
				},
			},
			givenMap: []*PackageStatus{
				{
					Action:            "blocked",
					BlockedPackageUrl: "http://localhost:8046/artifactory/api/npm/npm-repo/test-child/-/test-child-2.0.0.tgz",
					PackageName:       "test-child",
					PackageVersion:    "2.0.0",
					BlockingReason:    "Policy violations",
					PkgType:           "npm",
					Policy: []Policy{
						{
							Policy:    "policy1",
							Condition: "condition1",
						},
					},
				},
			},
			expectedPackagesStatus: []*PackageStatus{
				{
					Action:            "blocked",
					BlockedPackageUrl: "http://localhost:8046/artifactory/api/npm/npm-repo/test-child/-/test-child-2.0.0.tgz",
					PackageName:       "test-child",
					PackageVersion:    "2.0.0",
					BlockingReason:    "Policy violations",
					PkgType:           "npm",
					Policy: []Policy{
						{
							Policy:    "policy1",
							Condition: "condition1",
						},
					},
					ParentName:    "test-parent",
					ParentVersion: "1.0.0",
					DepRelation:   "indirect",
				},
			},
		},
		{
			name: "no duplications",
			givenGraph: &xrayUtils.GraphNode{
				Id: "npm://root-test",
				Nodes: []*xrayUtils.GraphNode{
					{
						Id: "npm://test-parent:1.0.0",
						Nodes: []*xrayUtils.GraphNode{
							{
								Id: "npm://test-child:2.0.0",
								Nodes: []*xrayUtils.GraphNode{
									{
										Id: "npm://@dev/test-child:4.0.0",
									},
								},
							},
							{
								Id: "npm://test-child:3.0.0",
								Nodes: []*xrayUtils.GraphNode{
									{
										Id: "npm://@dev/test-child:4.0.0",
									},
								},
							},
							{
								Id: "npm://@dev/test-child:5.0.0",
								Nodes: []*xrayUtils.GraphNode{
									{
										Id: "npm://test-child:4.0.0",
									},
								},
							},
						},
					},
					{
						Id: "npm://@dev/test-parent:1.0.0",
						Nodes: []*xrayUtils.GraphNode{
							{
								Id: "npm://test-child:4.0.0",
							},
						},
					},
				},
			},
			givenMap: []*PackageStatus{
				{
					Action:            "blocked",
					BlockedPackageUrl: "http://localhost:8046/artifactory/api/npm/npm-repo/@dev/test-child/-/test-child-4.0.0.tgz",
					PackageName:       "@dev/test-child",
					PackageVersion:    "4.0.0",
					BlockingReason:    "Policy violations",
					PkgType:           "npm",
					Policy: []Policy{
						{
							Policy:    "policy1",
							Condition: "condition1",
						},
					},
				},
				{
					Action:            "blocked",
					BlockedPackageUrl: "http://localhost:8046/artifactory/api/npm/npm-repo/test-child/-/test-child-4.0.0.tgz",
					PackageName:       "test-child",
					PackageVersion:    "4.0.0",
					BlockingReason:    "Policy violations",
					PkgType:           "npm",
					Policy: []Policy{
						{
							Policy:    "policy1",
							Condition: "condition1",
						},
					},
				},
			},
			expectedPackagesStatus: []*PackageStatus{
				{
					Action:            "blocked",
					BlockedPackageUrl: "http://localhost:8046/artifactory/api/npm/npm-repo/test-child/-/test-child-4.0.0.tgz",
					PackageName:       "test-child",
					PackageVersion:    "4.0.0",
					BlockingReason:    "Policy violations",
					PkgType:           "npm",
					Policy: []Policy{
						{
							Policy:    "policy1",
							Condition: "condition1",
						},
					},
					ParentName:    "test-parent",
					ParentVersion: "1.0.0",
					DepRelation:   "indirect",
				},
				{
					Action:            "blocked",
					BlockedPackageUrl: "http://localhost:8046/artifactory/api/npm/npm-repo/test-child/-/test-child-4.0.0.tgz",
					PackageName:       "test-child",
					PackageVersion:    "4.0.0",
					BlockingReason:    "Policy violations",
					PkgType:           "npm",
					Policy: []Policy{
						{
							Policy:    "policy1",
							Condition: "condition1",
						},
					},
					ParentName:    "@dev/test-parent",
					ParentVersion: "1.0.0",
					DepRelation:   "indirect",
				},
				{
					Action:            "blocked",
					BlockedPackageUrl: "http://localhost:8046/artifactory/api/npm/npm-repo/@dev/test-child/-/test-child-4.0.0.tgz",
					PackageName:       "@dev/test-child",
					PackageVersion:    "4.0.0",
					BlockingReason:    "Policy violations",
					PkgType:           "npm",
					Policy: []Policy{
						{
							Policy:    "policy1",
							Condition: "condition1",
						},
					},
					ParentName:    "test-parent",
					ParentVersion: "1.0.0",
					DepRelation:   "indirect",
				},
			},
		},
	}
	return tests
}

func fillSyncedMap(pkgStatus []*PackageStatus) *sync.Map {
	syncMap := sync.Map{}
	for _, value := range pkgStatus {
		syncMap.Store(value.BlockedPackageUrl, value)
	}
	return &syncMap
}

func TestDoCurationAudit(t *testing.T) {
	tests := getTestCasesForDoCurationAudit()
	basePathToTests, err := filepath.Abs(TestDataDir)
	assert.NoError(t, err)

	cleanUpFlags := setCurationFlagsForTest(t)
	defer cleanUpFlags()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create Mock server
			mockServer, config := curationServer(t, tt.expectedBuildRequest, tt.expectedRequest, tt.requestToFail, tt.requestToError, tt.serveResources)
			defer mockServer.Close()
			// Create test env
			cleanUp := createCurationTestEnv(t, basePathToTests, tt, config)
			defer cleanUp()
			// Create audit command, and run it
			results, err := createCurationCmdAndRun(tt)
			// Validate the results
			if tt.requestToError == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				startUrl := strings.Index(tt.expectedError, "/")
				assert.GreaterOrEqual(t, startUrl, 0)
				errMsgExpected := tt.expectedError[:startUrl] + config.ArtifactoryUrl +
					tt.expectedError[strings.Index(tt.expectedError, "/")+1:]
				assert.EqualError(t, err, errMsgExpected)
			}
			validateCurationResults(t, tt, results, config)
		})
	}
}

func createCurationTestEnv(t *testing.T, basePathToTests string, testCase testCase, config *config.ServerDetails) func() {
	_, cleanUpHome := createTempHomeDirWithConfig(t, basePathToTests, testCase, config)
	testDirPath, cleanUpTestPathDir := testUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(basePathToTests, testCase.pathToProject))
	var cleanUpChdir func()
	if testCase.pathToTest != "" {
		// Set the test path as the current working directory
		cleanUpChdir = testUtils.ChangeWDWithCallback(t, filepath.Join(testDirPath, testCase.pathToTest))
	}
	// Run pre test exec
	runPreTestExec(t, testDirPath, testCase)
	return func() {
		if cleanUpChdir != nil {
			cleanUpChdir()
		}
		cleanUpTestPathDir()
		cleanUpHome()
	}
}

func createTempHomeDirWithConfig(t *testing.T, basePathToTests string, testCase testCase, config *config.ServerDetails) (string, func()) {
	tempHomeDirPath, err := fileutils.CreateTempDir()
	assert.NoError(t, err)
	// create .jfrog dir in temp home dir
	jfrogDir := filepath.Join(tempHomeDirPath, ".jfrog")
	assert.NoError(t, os.MkdirAll(jfrogDir, 0777))
	// copy .jfrog config content from test project to temp home dir
	assert.NoError(t, biutils.CopyDir(filepath.Join(basePathToTests, testCase.getPathToTests(), ".jfrog"), jfrogDir, true, nil))
	// Set the home dir
	callbackHomeDir := clienttestutils.SetEnvWithCallbackAndAssert(t, coreutils.HomeDir, tempHomeDirPath)
	// Create the server details config file
	WriteServerDetailsConfigFileBytes(t, config.ArtifactoryUrl, tempHomeDirPath, testCase.createServerWithoutCreds)
	return tempHomeDirPath, func() {
		callbackHomeDir()
		err := fileutils.RemoveTempDir(tempHomeDirPath)
		if err != nil {
			// in some package manager the cache folder can be deleted only by root, in this case, test continue without failing
			assert.ErrorIs(t, err, os.ErrPermission)
		}
	}
}

func setCurationFlagsForTest(t *testing.T) func() {
	callbackCurationFlag := clienttestutils.SetEnvWithCallbackAndAssert(t, utils.CurationSupportFlag, "true")
	// Golang option to disable the use of the checksum database
	callbackNoSum := clienttestutils.SetEnvWithCallbackAndAssert(t, "GOSUMDB", "off")
	return func() {
		callbackCurationFlag()
		callbackNoSum()
	}
}

func runPreTestExec(t *testing.T, basePathToTests string, testCase testCase) {
	if testCase.preTestExec == "" {
		return
	}
	callbackPreTest := testUtils.ChangeWDWithCallback(t, filepath.Join(basePathToTests, testCase.pathToPreTest))
	output, err := exec.Command(testCase.preTestExec, testCase.funcToGetGoals(t)...).CombinedOutput()
	assert.NoErrorf(t, err, string(output))
	callbackPreTest()
}

func createCurationCmdAndRun(tt testCase) (cmdResults map[string]*CurationReport, err error) {
	curationCmd := NewCurationAuditCommand()
	curationCmd.SetIsCurationCmd(true)
	curationCmd.parallelRequests = 3
	curationCmd.SetIgnoreConfigFile(tt.shouldIgnoreConfigFile)
	cmdResults = map[string]*CurationReport{}
	err = curationCmd.doCurateAudit(cmdResults)
	return
}

func validateCurationResults(t *testing.T, testCase testCase, results map[string]*CurationReport, config *config.ServerDetails) {
	// Add the mock server to the expected blocked message url
	for key := range testCase.expectedResp {
		for index := range testCase.expectedResp[key].packagesStatus {
			testCase.expectedResp[key].packagesStatus[index].BlockedPackageUrl = fmt.Sprintf("%s%s",
				strings.TrimSuffix(config.GetArtifactoryUrl(), "/"),
				testCase.expectedResp[key].packagesStatus[index].BlockedPackageUrl)
		}
	}
	// the number of packages is not deterministic for pip, as it depends on the version of the package manager.
	if testCase.tech == techutils.Pip {
		for key := range results {
			result := results[key]
			result.totalNumberOfPackages = 0
		}
	}
	assert.Equal(t, testCase.expectedResp, results)
	for _, requestDone := range testCase.expectedRequest {
		assert.True(t, requestDone)
	}
	for _, requestDone := range testCase.expectedBuildRequest {
		assert.True(t, requestDone)
	}
}

type testCase struct {
	name                     string
	pathToProject            string
	pathToTest               string
	pathToPreTest            string
	preTestExec              string
	serveResources           map[string]string
	funcToGetGoals           func(t *testing.T) []string
	shouldIgnoreConfigFile   bool
	expectedBuildRequest     map[string]bool
	expectedRequest          map[string]bool
	requestToFail            map[string]bool
	expectedResp             map[string]*CurationReport
	requestToError           map[string]bool
	expectedError            string
	tech                     techutils.Technology
	createServerWithoutCreds bool
}

func (tc testCase) getPathToTests() string {
	if len(tc.pathToTest) > 0 {
		return filepath.Join(tc.pathToProject, tc.pathToTest)
	}
	return tc.pathToProject
}

func getTestCasesForDoCurationAudit() []testCase {
	tests := []testCase{
		{
			name:                     "go tree - one blocked package",
			tech:                     techutils.Go,
			pathToProject:            filepath.Join("projects", "package-managers", "go", "curation-project"),
			createServerWithoutCreds: true,
			serveResources: map[string]string{
				"v1.5.2.mod":                              filepath.Join("resources", "quote-v1.5.2.mod"),
				"v1.5.2.zip":                              filepath.Join("resources", "quote-v1.5.2.zip"),
				"v1.5.2.info":                             filepath.Join("resources", "quote-v1.5.2.info"),
				"v1.3.0.mod":                              filepath.Join("resources", "sampler-v1.3.0.mod"),
				"v1.3.0.zip":                              filepath.Join("resources", "sampler-v1.3.0.zip"),
				"v1.3.0.info":                             filepath.Join("resources", "sampler-v1.3.0.info"),
				"v0.0.0-20170915032832-14c0d48ead0c.mod":  filepath.Join("resources", "text-v0.0.0-20170915032832-14c0d48ead0c.mod"),
				"v0.0.0-20170915032832-14c0d48ead0c.zip":  filepath.Join("resources", "text-v0.0.0-20170915032832-14c0d48ead0c.zip"),
				"v0.0.0-20170915032832-14c0d48ead0c.info": filepath.Join("resources", "text-v0.0.0-20170915032832-14c0d48ead0c.info"),
			},
			requestToFail: map[string]bool{
				"/api/go/go-virtual/rsc.io/sampler/@v/v1.3.0.zip": false,
			},
			expectedResp: map[string]*CurationReport{
				"github.com/you/hello": {packagesStatus: []*PackageStatus{
					{
						Action:            "blocked",
						ParentName:        "rsc.io/quote",
						ParentVersion:     "v1.5.2",
						BlockedPackageUrl: "/api/go/go-virtual/rsc.io/sampler/@v/v1.3.0.zip",
						PackageName:       "rsc.io/sampler",
						PackageVersion:    "v1.3.0",
						BlockingReason:    "Policy violations",
						DepRelation:       "indirect",
						PkgType:           "go",
						Policy: []Policy{
							{
								Policy:    "pol1",
								Condition: "cond1",
							},
						},
					},
					{
						Action:            "blocked",
						ParentName:        "rsc.io/sampler",
						ParentVersion:     "v1.3.0",
						BlockedPackageUrl: "/api/go/go-virtual/rsc.io/sampler/@v/v1.3.0.zip",
						PackageName:       "rsc.io/sampler",
						PackageVersion:    "v1.3.0",
						BlockingReason:    "Policy violations",
						DepRelation:       "direct",
						PkgType:           "go",
						Policy: []Policy{
							{
								Policy:    "pol1",
								Condition: "cond1",
							},
						},
					},
				},
					totalNumberOfPackages: 3,
				},
			},
		},
		{
			name:          "python tree - one blocked package",
			tech:          techutils.Pip,
			pathToProject: filepath.Join("projects", "package-managers", "python", "pip", "pip-curation"),
			serveResources: map[string]string{
				"pip":                                   filepath.Join("resources", "pip-resp"),
				"pexpect":                               filepath.Join("resources", "pexpect-resp"),
				"ptyprocess":                            filepath.Join("resources", "ptyprocess-resp"),
				"pexpect-4.8.0-py2.py3-none-any.whl":    filepath.Join("resources", "pexpect-4.8.0-py2.py3-none-any.whl"),
				"ptyprocess-0.7.0-py2.py3-none-any.whl": filepath.Join("resources", "ptyprocess-0.7.0-py2.py3-none-any.whl"),
			},
			requestToFail: map[string]bool{
				"/api/pypi/pypi-remote/packages/packages/39/7b/88dbb785881c28a102619d46423cb853b46dbccc70d3ac362d99773a78ce/pexpect-4.8.0-py2.py3-none-any.whl": false,
			},
			expectedResp: map[string]*CurationReport{
				"pip-curation": {packagesStatus: []*PackageStatus{
					{
						Action:            "blocked",
						ParentVersion:     "4.8.0",
						ParentName:        "pexpect",
						BlockedPackageUrl: "/api/pypi/pypi-remote/packages/packages/39/7b/88dbb785881c28a102619d46423cb853b46dbccc70d3ac362d99773a78ce/pexpect-4.8.0-py2.py3-none-any.whl",
						PackageName:       "pexpect",
						PackageVersion:    "4.8.0",
						BlockingReason:    "Policy violations",
						PkgType:           "pip",
						DepRelation:       "direct",
						Policy: []Policy{
							{
								Policy:    "pol1",
								Condition: "cond1",
							},
						},
					},
				},
				},
			},
		},
		{
			name:          "maven tree - one blocked package",
			tech:          techutils.Maven,
			pathToProject: filepath.Join("projects", "package-managers", "maven", "maven-curation"),
			pathToTest:    "test",
			pathToPreTest: "pretest",
			preTestExec:   "mvn",
			funcToGetGoals: func(t *testing.T) []string {
				// We want to populate the cache with dependencies before running the tests, so that during the test only the blocked package needs to be resolved.
				// The cache directory is determined by the project directory, so we need to "simulate" the cache directory when running the pretest build.
				// During the test, the blocked package will be resolved from the same cache directory that was populated in the pretest build.
				cleanUpTestDirChange := testUtils.ChangeWDWithCallback(t, filepath.Join("..", "test"))
				curationCache, err := utils.GetCurationCacheFolderByTech(techutils.Maven)
				require.NoError(t, err)
				cleanUpTestDirChange()
				return []string{"com.jfrog:maven-dep-tree:tree", "-DdepsTreeOutputFile=output", "-Dmaven.repo.local=" + curationCache}
			},
			expectedBuildRequest: map[string]bool{
				"/api/curation/audit/maven-remote/org/webjars/npm/underscore/1.13.6/underscore-1.13.6.pom": false,
			},
			requestToFail: map[string]bool{
				"/maven-remote/org/webjars/npm/underscore/1.13.6/underscore-1.13.6.jar": false,
			},
			expectedResp: map[string]*CurationReport{
				"test:my-app:1.0.0": {packagesStatus: []*PackageStatus{
					{
						Action:            "blocked",
						ParentVersion:     "1.13.6",
						ParentName:        "org.webjars.npm:underscore",
						BlockedPackageUrl: "/maven-remote/org/webjars/npm/underscore/1.13.6/underscore-1.13.6.jar",
						PackageName:       "org.webjars.npm:underscore",
						PackageVersion:    "1.13.6",
						BlockingReason:    "Policy violations",
						PkgType:           "maven",
						DepRelation:       "direct",
						Policy: []Policy{
							{
								Policy:    "pol1",
								Condition: "cond1",
							},
						},
					},
				},
					totalNumberOfPackages: 2,
				},
			},
			requestToError: nil,
			expectedError:  "",
		},
		{
			name:                   "npm tree - two blocked package ",
			tech:                   techutils.Npm,
			pathToProject:          filepath.Join("projects", "package-managers", "npm", "npm-project"),
			shouldIgnoreConfigFile: true,
			expectedRequest: map[string]bool{
				"/api/npm/npms/lightweight/-/lightweight-0.1.0.tgz": false,
				"/api/npm/npms/underscore/-/underscore-1.13.6.tgz":  false,
			},
			requestToFail: map[string]bool{
				"/api/npm/npms/underscore/-/underscore-1.13.6.tgz": false,
			},
			expectedResp: map[string]*CurationReport{
				"npm_test:1.0.0": {packagesStatus: []*PackageStatus{
					{
						Action:            "blocked",
						ParentVersion:     "1.13.6",
						ParentName:        "underscore",
						BlockedPackageUrl: "/api/npm/npms/underscore/-/underscore-1.13.6.tgz",
						PackageName:       "underscore",
						PackageVersion:    "1.13.6",
						BlockingReason:    "Policy violations",
						PkgType:           "npm",
						DepRelation:       "direct",
						Policy: []Policy{
							{
								Policy:    "pol1",
								Condition: "cond1",
							},
						},
					},
				},
					totalNumberOfPackages: 2,
				},
			},
		},
		{
			name:                   "npm tree - two blocked one error",
			tech:                   techutils.Npm,
			pathToProject:          filepath.Join("projects", "package-managers", "npm", "npm-project"),
			shouldIgnoreConfigFile: true,
			expectedRequest: map[string]bool{
				"/api/npm/npms/lightweight/-/lightweight-0.1.0.tgz": false,
				"/api/npm/npms/underscore/-/underscore-1.13.6.tgz":  false,
			},
			requestToFail: map[string]bool{
				"/api/npm/npms/underscore/-/underscore-1.13.6.tgz": false,
			},
			requestToError: map[string]bool{
				"/api/npm/npms/lightweight/-/lightweight-0.1.0.tgz": false,
			},
			expectedResp: map[string]*CurationReport{
				"npm_test:1.0.0": {packagesStatus: []*PackageStatus{
					{
						Action:            "blocked",
						ParentVersion:     "1.13.6",
						ParentName:        "underscore",
						BlockedPackageUrl: "/api/npm/npms/underscore/-/underscore-1.13.6.tgz",
						PackageName:       "underscore",
						PackageVersion:    "1.13.6",
						BlockingReason:    "Policy violations",
						PkgType:           "npm",
						DepRelation:       "direct",
						Policy: []Policy{
							{
								Policy:    "pol1",
								Condition: "cond1",
							},
						},
					},
				},
					totalNumberOfPackages: 2,
				},
			},
			expectedError: fmt.Sprintf("failed sending HEAD request to %s for package '%s'. Status-code: %v. "+
				"Cause: executor timeout after 2 attempts with 0 milliseconds wait intervals",
				"/api/npm/npms/lightweight/-/lightweight-0.1.0.tgz", "lightweight:0.1.0", http.StatusInternalServerError),
		},
		{
			name:          "dotnet tree",
			tech:          techutils.Dotnet,
			pathToProject: filepath.Join("projects", "package-managers", "dotnet", "dotnet-curation"),
			serveResources: map[string]string{
				"curated-nuget": filepath.Join("resources", "feed.json"),
				"index.json":    filepath.Join("resources", "index.json"),
				"13.0.3":        filepath.Join("resources", "newtonsoft.json.13.0.3.nupkg"),
			},
			requestToFail: map[string]bool{
				"/api/nuget/v3/curated-nuget/registration-semver2/Download/newtonsoft.json/13.0.3": false,
			},
			expectedResp: map[string]*CurationReport{
				"dotnet-curation": {packagesStatus: []*PackageStatus{
					{
						Action:            "blocked",
						ParentName:        "Newtonsoft.Json",
						ParentVersion:     "13.0.3",
						BlockedPackageUrl: "/api/nuget/v3/curated-nuget/registration-semver2/Download/newtonsoft.json/13.0.3",
						PackageName:       "Newtonsoft.Json",
						PackageVersion:    "13.0.3",
						BlockingReason:    "Policy violations",
						DepRelation:       "direct",
						PkgType:           "nuget",
						Policy: []Policy{
							{
								Policy:    "pol1",
								Condition: "cond1",
							},
						},
					},
				},
					totalNumberOfPackages: 1,
				},
			},
		},
	}
	return tests
}

func curationServer(t *testing.T, expectedBuildRequest map[string]bool, expectedRequest map[string]bool, requestToFail map[string]bool, requestToError map[string]bool, resourceToServe map[string]string) (*httptest.Server, *config.ServerDetails) {
	mapLockReadWrite := sync.Mutex{}
	serverMock, config, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			mapLockReadWrite.Lock()
			if _, exist := expectedRequest[r.RequestURI]; exist {
				expectedRequest[r.RequestURI] = true
			}
			mapLockReadWrite.Unlock()
			if _, exist := requestToFail[r.RequestURI]; exist {
				w.WriteHeader(http.StatusForbidden)
			}
			if _, exist := requestToError[r.RequestURI]; exist {
				w.WriteHeader(http.StatusInternalServerError)
			}
		}
		if r.Method == http.MethodGet {
			if resourceToServe != nil {
				if pathToRes, ok := resourceToServe[path.Base(r.RequestURI)]; ok && strings.Contains(r.RequestURI, "api/curation/audit") {
					f, err := fileutils.ReadFile(pathToRes)
					require.NoError(t, err)
					f = bytes.ReplaceAll(f, []byte("127.0.0.1:80"), []byte(r.Host))
					w.Header().Add("content-type", "text/html")
					_, err = w.Write(f)
					require.NoError(t, err)
					return
				}
			}
			if _, exist := expectedBuildRequest[r.RequestURI]; exist {
				expectedBuildRequest[r.RequestURI] = true
			}

			if _, exist := requestToFail[r.RequestURI]; exist {
				w.WriteHeader(http.StatusForbidden)
				_, err := w.Write([]byte("{\n    \"errors\": [\n        {\n            \"status\": 403,\n            " +
					"\"message\": \"Package download was blocked by JFrog Packages " +
					"Curation service due to the following policies violated {pol1, cond1}\"\n        }\n    ]\n}"))
				assert.NoError(t, err)
			}
		}
	})
	config.XrayUrl = config.Url + "xray/"
	return serverMock, config
}

func WriteServerDetailsConfigFileBytes(t *testing.T, url string, configPath string, withoutCreds bool) string {
	var username, password string
	if !withoutCreds {
		username = "admin"
		password = "password"
	}
	serverDetails := config.ConfigV5{
		Servers: []*config.ServerDetails{
			{
				ServerId:       "test",
				User:           username,
				Password:       password,
				Url:            url,
				ArtifactoryUrl: url,
			},
		},
		Version: "v" + strconv.Itoa(coreutils.GetCliConfigVersion()),
	}

	detailsByte, err := json.Marshal(serverDetails)
	assert.NoError(t, err)
	confFilePath := filepath.Join(configPath, "jfrog-cli.conf.v"+strconv.Itoa(coreutils.GetCliConfigVersion()))
	assert.NoError(t, os.WriteFile(confFilePath, detailsByte, 0644))
	return confFilePath
}

func Test_getGoNameScopeAndVersion(t *testing.T) {
	tests := []struct {
		name         string
		compId       string
		rtUrl        string
		downloadUrls []string
		repo         string
		compName     string
		version      string
	}{
		{
			name:         "valid go component id",
			compId:       "go://github.com/kennygrant/sanitize:v1.2.4",
			rtUrl:        "http://test/artifactory",
			repo:         "test",
			downloadUrls: []string{"http://test/artifactory/api/go/test/github.com/kennygrant/sanitize/@v/v1.2.4.zip"},
			compName:     "github.com/kennygrant/sanitize",
			version:      "v1.2.4",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDownloadUrls, gotName, _, gotVersion := getGoNameScopeAndVersion(tt.compId, tt.rtUrl, tt.repo)
			assert.Equal(t, tt.downloadUrls, gotDownloadUrls)
			assert.Equal(t, tt.compName, gotName)
			assert.Equal(t, tt.version, gotVersion)
		})
	}
}

func Test_getNugetNameScopeAndVersion(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		artiUrl     string
		repo        string
		wantUrls    []string
		wantName    string
		wantVersion string
	}{
		{
			name:        "Basic case",
			id:          "nuget://Newtonsoft.Json:13.0.1.1",
			artiUrl:     "http://test/artifactory",
			repo:        "test",
			wantUrls:    []string{"http://test/artifactory/api/nuget/v3/test/registration-semver2/Download/newtonsoft.json/13.0.1.1"},
			wantName:    "Newtonsoft.Json",
			wantVersion: "13.0.1.1",
		},
		{
			name:    "Case with alternative versions",
			id:      "nuget://Example.Package:1.0.0",
			artiUrl: "http://test/artifactory",
			repo:    "test",
			wantUrls: []string{
				"http://test/artifactory/api/nuget/v3/test/registration-semver2/Download/example.package/1.0.0",
				"http://test/artifactory/api/nuget/v3/test/registration-semver2/Download/example.package/1.0.0.0",
				"http://test/artifactory/api/nuget/v3/test/registration-semver2/Download/example.package/1.0",
				"http://test/artifactory/api/nuget/v3/test/registration-semver2/Download/example.package/1",
			},
			wantName:    "Example.Package",
			wantVersion: "1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUrls, gotName, gotVersion := getNugetNameScopeAndVersion(tt.id, tt.artiUrl, tt.repo)
			assert.Equal(t, tt.wantUrls, gotUrls)
			assert.Equal(t, tt.wantName, gotName)
			assert.Equal(t, tt.wantVersion, gotVersion)
		})
	}
}

func Test_convertResultsToSummary(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]*CurationReport
		expected formats.ResultsSummary
	}{
		{
			name: "results for one result",
			input: map[string]*CurationReport{
				"project1": {
					packagesStatus: []*PackageStatus{
						{
							PackageName:    "test1",
							PackageVersion: "1.0.0",
							ParentVersion:  "1.0.0",
							ParentName:     "parent-test1",

							Action: "blocked",
							Policy: []Policy{
								{
									Policy:    "policy1",
									Condition: "cond1",
								},
							},
						},
					},
					totalNumberOfPackages: 5,
				},
			},
			expected: formats.ResultsSummary{
				Scans: []formats.ScanSummary{
					{
						Target: "project1",
						CuratedPackages: &formats.CuratedPackages{
							PackageCount: 5,
							Blocked: []formats.BlockedPackages{{
								Policy:    "policy1",
								Condition: "cond1",
								Packages:  map[string]int{"test1:1.0.0": 1},
							}},
						},
					},
				},
			},
		},
		{
			name: "results for three result - aggregate one, same component in two policies",
			input: map[string]*CurationReport{
				"project1": {
					packagesStatus: []*PackageStatus{
						{
							PackageName:    "test1",
							PackageVersion: "1.0.0",
							ParentVersion:  "1.0.0",
							ParentName:     "parent-test1",

							Action: "blocked",
							Policy: []Policy{
								{
									Policy:    "policy1",
									Condition: "cond1",
								},
								{
									Policy:    "policy2",
									Condition: "cond2",
								},
							},
						},
						{
							PackageName:    "test2",
							PackageVersion: "2.0.0",
							ParentVersion:  "2.0.0",
							ParentName:     "parent-test2",

							Action: "blocked",
							Policy: []Policy{
								{
									Policy:    "policy2",
									Condition: "cond2",
								},
							},
						},
						{
							PackageName:    "test3",
							PackageVersion: "3.0.0",
							ParentVersion:  "3.0.0",
							ParentName:     "parent-test3",

							Action: "blocked",
							Policy: []Policy{
								{
									Policy:    "policy2",
									Condition: "cond2",
								},
							},
						},
					},
					totalNumberOfPackages: 6,
				},
			},
			expected: formats.ResultsSummary{
				Scans: []formats.ScanSummary{
					{
						Target: "project1",
						CuratedPackages: &formats.CuratedPackages{
							PackageCount: 6,
							Blocked: []formats.BlockedPackages{
								{
									Policy:    "policy1",
									Condition: "cond1",
									Packages:  map[string]int{"test1:1.0.0": 1},
								},
								{
									Policy:    "policy2",
									Condition: "cond2",
									Packages:  map[string]int{"test1:1.0.0": 1, "test2:2.0.0": 1, "test3:3.0.0": 1},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := convertResultsToSummary(tt.input)
			// Sort Blocked base on count (low first) to make the test deterministic
			for _, scan := range summary.Scans {
				sort.Slice(scan.CuratedPackages.Blocked, func(i, j int) bool {
					return len(scan.CuratedPackages.Blocked[i].Packages) < len(scan.CuratedPackages.Blocked[j].Packages)
				})
			}
			assert.Equal(t, tt.expected, summary)
		})
	}
}
