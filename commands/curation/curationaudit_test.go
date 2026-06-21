package curation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/java"
	"github.com/jfrog/jfrog-cli-security/utils/formats"

	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/common/project"
	coreCommonTests "github.com/jfrog/jfrog-cli-core/v2/common/tests"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	clienttestutils "github.com/jfrog/jfrog-client-go/utils/tests"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/python"
	testUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
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
		{
			name: "on-demand in progress",
			errResp: &ErrorsResp{
				Errors: []ErrorResp{
					{
						Status:  403,
						Message: "Package test:1.0.0 download was blocked by JFrog Packages Curation service due to the package not being found in catalog, curation on-demand scan in progress.",
					},
				},
			},
			expect: []Policy{
				{
					Explanation: BlockingReasonOnDemand,
				},
			},
		},
		{
			name: "package not found in catalog",
			errResp: &ErrorsResp{
				Errors: []ErrorResp{
					{
						Status:  403,
						Message: "package test:1.0.0 download was blocked by jfrog packages curation service due to the package not being found in catalog",
					},
				},
			},
			expect: []Policy{
				{
					Explanation: BlockingReasonNotFound,
				},
			},
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

func TestIsYarnBerryWorkspaceMember(t *testing.T) {
	tests := []struct {
		name    string
		pkgName string
		version string
		want    bool
	}{
		{"workspace member — typical", "admin-ui-428bae", "0.0.0", true},
		{"workspace member — root style", "root-workspace-0b6124", "0.0.0", true},
		{"real package version 0.0.0", "my-pkg", "0.0.0", false},           // no hex suffix
		{"real package with hex-looking name", "a-1b2c3d", "1.2.3", false}, // wrong version
		{"Yarn V1 use.local", "my-pkg", "0.0.0-use.local", false},          // caught by earlier check
		{"suffix too short", "pkg-4abc", "0.0.0", false},                   // 4 chars, not 6
		{"suffix uppercase", "pkg-4ABC12", "0.0.0", false},                 // uppercase hex not matched
		{"suffix has non-hex", "pkg-4xyzab", "0.0.0", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isYarnBerryWorkspaceMember(tt.pkgName, tt.version))
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
	// For tests, we use localhost http server (nuget have issues without setting insecureTls)
	curationCmd.SetInsecureTls(true)
	curationCmd.SetIgnoreConfigFile(tt.shouldIgnoreConfigFile)
	curationCmd.SetInsecureTls(tt.allowInsecureTls)
	curationCmd.SetMvnIncludePluginDeps(tt.mvnIncludePluginDeps)
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
	// the number of packages is not deterministic for gem, as it depends on the version of the package manager.
	if testCase.tech == techutils.Gem {
		for key := range results {
			result := results[key]
			result.totalNumberOfPackages = 0
		}
	}
	// Cases that exercise Maven plugin-dep injection pull in a plugin's full transitive
	// closure (e.g. maven-jar-plugin -> maven-archiver -> plexus-utils ...), which varies
	// across plugin/Maven versions. Suppress the count assertion when requested.
	if testCase.skipPackageCount {
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
	allowInsecureTls         bool
	// mvnIncludePluginDeps wires the --mvn-include-plugin-deps CLI flag into the curation
	// audit command so the test exercises Maven build-plugin transitive dep collection.
	mvnIncludePluginDeps bool
	// skipPackageCount tells validateCurationResults to ignore totalNumberOfPackages.
	// Use for cases where the count depends on a Maven plugin's transitive closure
	// (e.g. maven-jar-plugin) and would otherwise be brittle across Maven/plugin versions.
	skipPackageCount bool
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
			name:          "gradle tree - one blocked package",
			tech:          techutils.Gradle,
			pathToProject: filepath.Join("projects", "package-managers", "gradle", "curation-project"),
			funcToGetGoals: func(t *testing.T) []string {
				// To ensure only the blocked package is resolved during testing, we pre-populate the cache with dependencies beforehand.
				// Since the cache location depends on the project directory, we need to mimic that setup during the pretest build.
				// This way, the test phase will use the same cache directory, already filled with required dependencies.
				restoreWD := testUtils.ChangeWDWithCallback(t, "tests/testdata/projects/package-managers")
				defer restoreWD()

				curationCache, err := utils.GetCurationCacheFolderByTech(techutils.Gradle.String())
				require.NoError(t, err)

				return []string{
					"gradle", "build",
					"--build-file", "build.gradle",
					"--gradle-user-home=" + curationCache,
					"--no-daemon",
				}
			},
			serveResources: map[string]string{
				"build.gradle": filepath.Join("tests", "testdata", "projects", "package-managers", "gradle", "curation-project", "build.gradle"),
			},
			requestToFail: map[string]bool{
				"/gradle-virtual/log4j/log4j/1.2.14/log4j-1.2.14.jar": true,
			},
			expectedResp: map[string]*CurationReport{
				"com.example:curation-project:1.0.0": {
					// Ensure packagesStatus is properly initialized, even if empty initially
					packagesStatus: []*PackageStatus{
						{
							Action:            "blocked",
							ParentName:        "log4j:log4j",
							ParentVersion:     "1.2.14",
							BlockedPackageUrl: "/gradle-virtual/log4j/log4j/1.2.14/log4j-1.2.14.jar",
							PackageName:       "log4j:log4j",
							PackageVersion:    "1.2.14",
							BlockingReason:    "Policy violations",
							DepRelation:       "direct",
							PkgType:           "gradle",
							WaiverAllowed:     false,
							Policy: []Policy{
								{
									Policy:         "pol1",
									Condition:      "cond1",
									Explanation:    "",
									Recommendation: "",
								},
							},
						},
					},
					totalNumberOfPackages: 5, // Adjust the number if necessary
				},
			},
			allowInsecureTls: true,
		},
		{
			name:          "python tree - one blocked package",
			tech:          techutils.Pip,
			pathToProject: filepath.Join("projects", "package-managers", "python", "pip", "pip-curation"),
			serveResources: map[string]string{
				"pip":                                   filepath.Join("resources", "pip-resp"),
				"pexpect":                               filepath.Join("resources", "pexpect-resp"),
				"ptyprocess":                            filepath.Join("resources", "ptyprocess-resp"),
				"typing-extensions":                     filepath.Join("resources", "typing-extensions-resp"),
				"pexpect-4.8.0-py2.py3-none-any.whl":    filepath.Join("resources", "pexpect-4.8.0-py2.py3-none-any.whl"),
				"ptyprocess-0.7.0-py2.py3-none-any.whl": filepath.Join("resources", "ptyprocess-0.7.0-py2.py3-none-any.whl"),
				"typing_extensions-4.15.0-py3-none-any.whl": filepath.Join("resources", "typing_extensions-4.15.0-py3-none-any.whl"),
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
			name:          "gem tree - one blocked package",
			tech:          techutils.Gem,
			pathToProject: filepath.Join("projects", "package-managers", "gem", "curation-project"),

			// This function now prepares a completely isolated environment before your code runs.
			funcToGetGoals: func(t *testing.T) []string {
				// Create a new, empty temporary directory for this test run only.
				tempGemHome, err := os.MkdirTemp("", "gem-home")
				require.NoError(t, err)

				// Return a shell command that sets the GEM_HOME.
				// Your application's subsequent 'bundle lock' will run in this clean environment.
				return []string{"export", "GEM_HOME=" + tempGemHome}
			},

			serveResources: map[string]string{
				"Gemfile": filepath.Join("tests", "testdata", "projects", "package-managers", "gem", "curation-project", "Gemfile"),
			},

			// Block a package that your logs confirm is being requested.
			requestToFail: map[string]bool{
				"/api/gems/ruby-remote/gems/activesupport-5.2.3.gem": true,
			},

			// Expect a report containing the exact blocked package.
			expectedResp: map[string]*CurationReport{
				"Ruby-Project": {
					packagesStatus: []*PackageStatus{
						{
							Action:            "blocked",
							ParentName:        "actionview",
							ParentVersion:     "5.2.3",
							BlockedPackageUrl: "/api/gems/ruby-remote/gems/activesupport-5.2.3.gem",
							PackageName:       "activesupport",
							PackageVersion:    "5.2.3",
							DepRelation:       "indirect",
							PkgType:           "ruby",
							BlockingReason:    "Policy violations",
							Policy: []Policy{
								{
									Policy:    "pol1",
									Condition: "cond1",
								},
							},
						},
						{
							Action:            "blocked",
							ParentName:        "activesupport",
							ParentVersion:     "5.2.3",
							BlockedPackageUrl: "/api/gems/ruby-remote/gems/activesupport-5.2.3.gem",
							PackageName:       "activesupport",
							PackageVersion:    "5.2.3",
							DepRelation:       "direct",
							PkgType:           "ruby",
							BlockingReason:    "Policy violations",
							Policy: []Policy{
								{
									Policy:    "pol1",
									Condition: "cond1",
								},
							},
						},
						{
							Action:            "blocked",
							ParentName:        "rails-dom-testing",
							ParentVersion:     "2.3.0",
							BlockedPackageUrl: "/api/gems/ruby-remote/gems/activesupport-5.2.3.gem",
							PackageName:       "activesupport",
							PackageVersion:    "5.2.3",
							DepRelation:       "indirect",
							PkgType:           "ruby",
							BlockingReason:    "Policy violations",
							Policy: []Policy{
								{
									Policy:    "pol1",
									Condition: "cond1",
								},
							},
						},
					},
					totalNumberOfPackages: 0, // Ignore package count for cross-platform compatibility
				},
			},
			allowInsecureTls: true,
		},
		{
			// Regression coverage for --mvn-include-plugin-deps. The customer scenario was a
			// build that downloaded a curated artifact only via a Maven build-plugin's transitive
			// closure; `jf ca` would report "0 blocked" because mvn dependency:tree never sees
			// plugin deps. The test pom pins maven-jar-plugin to 3.4.1, whose fixed transitive
			// closure includes org.ow2.asm:asm:9.8 (via plexus-archiver:4.9.2). The mock server
			// blocks that exact jar URL. With the flag on, the curation audit must resolve plugin
			// deps, inject asm into the tree, and surface it as blocked.
			name:          "maven tree - one blocked plugin dependency",
			tech:          techutils.Maven,
			pathToProject: filepath.Join("projects", "package-managers", "maven", "maven-curation-plugin-deps"),
			pathToTest:    "test",
			pathToPreTest: "pretest",
			preTestExec:   "mvn",
			funcToGetGoals: func(t *testing.T) []string {
				// Curation cache is keyed off the project directory — compute it from the
				// test/ dir (where the real test will run) so pretest writes into the same
				// folder that the test phase reads. Mirrors the maven-curation case above.
				cleanUpTestDirChange := testUtils.ChangeWDWithCallback(t, filepath.Join("..", "test"))
				curationCache, err := utils.GetCurationCacheFolderByTech(techutils.Maven.String())
				require.NoError(t, err)
				cleanUpTestDirChange()
				// One mvn invocation, multiple goals: maven-dep-tree:tree primes the project
				// dep cache; dependency:resolve-plugins and help:effective-pom pre-download
				// the plugins that resolvePluginDeps()/resolveInstallLifecyclePlugins() will
				// re-run during the test phase against the mock server.
				return []string{
					"com.jfrog:maven-dep-tree:" + java.GetMavenDepTreeVersion() + ":tree",
					"-DdepsTreeOutputFile=output",
					"-Dmaven.repo.local=" + curationCache,
					"dependency:resolve-plugins",
					"help:effective-pom",
				}
			},
			mvnIncludePluginDeps: true,
			// The full plugin closure depends on the runner's ambient Maven plugin versions;
			// only asm:9.8 (pinned via maven-jar-plugin:3.4.1) is deterministic, so we assert
			// just that blocked package and skip the non-deterministic total count.
			skipPackageCount: true,
			requestToFail: map[string]bool{
				"/maven-remote/org/ow2/asm/asm/9.8/asm-9.8.jar": false,
			},
			expectedResp: map[string]*CurationReport{
				"test:plugin-dep-app:1.0.0": {packagesStatus: []*PackageStatus{
					{
						Action:            "blocked",
						ParentVersion:     "9.8",
						ParentName:        "org.ow2.asm:asm",
						BlockedPackageUrl: "/maven-remote/org/ow2/asm/asm/9.8/asm-9.8.jar",
						PackageName:       "org.ow2.asm:asm",
						PackageVersion:    "9.8",
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
				}},
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
				curationCache, err := utils.GetCurationCacheFolderByTech(techutils.Maven.String())
				require.NoError(t, err)
				cleanUpTestDirChange()
				return []string{"com.jfrog:maven-dep-tree:" + java.GetMavenDepTreeVersion() + ":tree", "-DdepsTreeOutputFile=output", "-Dmaven.repo.local=" + curationCache}
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
			// One HEAD probe 500s, the other 403s. The 500 is logged as a warning
			// and the walk continues; expect a partial report containing only the
			// confirmed-blocked package (underscore@1.13.6) plus the error.
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
				"curated-nuget/index.json": filepath.Join("resources", "feed.json"),
				"index.json":               filepath.Join("resources", "index.json"),
				"13.0.3":                   filepath.Join("resources", "newtonsoft.json.13.0.3.nupkg"),
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
			allowInsecureTls: true,
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
				if pathToRes := getResourceToServe(resourceToServe, r.RequestURI); pathToRes != "" && strings.Contains(r.RequestURI, "api/curation/audit") {
					f, err := fileutils.ReadFile(pathToRes)
					require.NoError(t, err)
					f = bytes.ReplaceAll(f, []byte("127.0.0.1:80"), []byte(r.Host))
					w.Header().Add("content-type", "text/html")
					// #nosec G705 -- mock server serves controlled test-resource file content only, not user input
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

func getResourceToServe(resourcesToServe map[string]string, pathToRes string) string {
	for key, value := range resourcesToServe {
		if strings.HasSuffix(strings.TrimSuffix(pathToRes, "/"), key) {
			return value
		}
	}
	return ""
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

func Test_getGradleNameScopeAndVersion(t *testing.T) {
	tests := []struct {
		name             string
		id               string
		artiUrl          string
		repo             string
		node             string
		wantDownloadUrls []string
		wantName         string
		wantScope        string
		wantVersion      string
	}{
		{
			name:             "Realistic package from example - log4j",
			id:               "gav://log4j:log4j:1.2.14",
			artiUrl:          "http://test.jfrog.io/artifactory",
			repo:             "gradle-virtual",
			node:             "",
			wantDownloadUrls: []string{"http://test.jfrog.io/artifactory/gradle-virtual/log4j/log4j/1.2.14/log4j-1.2.14.jar"},
			wantName:         "log4j:log4j",
			wantScope:        "",
			wantVersion:      "1.2.14",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDownloadUrls, gotName, gotScope, gotVersion := getGradleNameScopeAndVersion(tt.id, tt.artiUrl, tt.repo, nil)
			assert.Equal(t, tt.wantDownloadUrls, gotDownloadUrls, "downloadUrls mismatch")
			assert.Equal(t, tt.wantName, gotName, "name mismatch")
			assert.Equal(t, tt.wantScope, gotScope, "scope mismatch")
			assert.Equal(t, tt.wantVersion, gotVersion, "version mismatch")
		})
	}
}

func Test_getGemNameScopeAndVersion(t *testing.T) {
	tests := []struct {
		name             string
		id               string
		artiUrl          string
		repo             string
		wantDownloadUrls []string
		wantName         string
		wantScope        string
		wantVersion      string
	}{
		{
			name:             "Realistic package from example - devise",
			id:               "rubygems://devise:4.7.1",
			artiUrl:          "http://test.jfrog.io/artifactory",
			repo:             "test-gems-remote",
			wantDownloadUrls: []string{"http://test.jfrog.io/artifactory/api/gems/test-gems-remote/gems/devise-4.7.1.gem"},
			wantName:         "devise",
			wantScope:        "",
			wantVersion:      "4.7.1",
		},
		{
			name:             "Project name extraction case",
			id:               "rubygems://some-gem:1.0.0",
			artiUrl:          "",
			repo:             "",
			wantDownloadUrls: nil,
			wantName:         "Ruby-Project",
			wantScope:        "",
			wantVersion:      "",
		},
		{
			name:             "Invalid format case",
			id:               "rubygems://invalid-format",
			artiUrl:          "http://test.jfrog.io/artifactory",
			repo:             "test-gems-remote",
			wantDownloadUrls: nil,
			wantName:         "",
			wantScope:        "",
			wantVersion:      "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDownloadUrls, gotName, gotScope, gotVersion := getGemNameScopeAndVersion(tt.id, tt.artiUrl, tt.repo)
			assert.Equal(t, tt.wantDownloadUrls, gotDownloadUrls, "downloadUrls mismatch")
			assert.Equal(t, tt.wantName, gotName, "name mismatch")
			assert.Equal(t, tt.wantScope, gotScope, "scope mismatch")
			assert.Equal(t, tt.wantVersion, gotVersion, "version mismatch")
		})
	}
}

func Test_getDockerNameAndVersion(t *testing.T) {
	tests := []struct {
		name             string
		id               string
		artiUrl          string
		repo             string
		wantDownloadUrls []string
		wantName         string
		wantVersion      string
	}{
		{
			name:             "Basic docker image with tag",
			id:               "docker://nginx:1.21.0",
			artiUrl:          "http://test.jfrog.io/artifactory",
			repo:             "docker-remote",
			wantDownloadUrls: []string{"http://test.jfrog.io/artifactory/api/docker/docker-remote/v2/nginx/manifests/1.21.0"},
			wantName:         "nginx",
			wantVersion:      "1.21.0",
		},
		{
			name:             "Docker image with registry prefix",
			id:               "docker://registry.example.com/nginx:1.21.0",
			artiUrl:          "http://test.jfrog.io/artifactory",
			repo:             "docker-remote",
			wantDownloadUrls: []string{"http://test.jfrog.io/artifactory/api/docker/docker-remote/v2/registry.example.com/nginx/manifests/1.21.0"},
			wantName:         "registry.example.com/nginx",
			wantVersion:      "1.21.0",
		},
		{
			name:             "Docker image with sha256 digest",
			id:               "docker://nginx:sha256:abc123def456",
			artiUrl:          "http://test.jfrog.io/artifactory",
			repo:             "docker-remote",
			wantDownloadUrls: []string{"http://test.jfrog.io/artifactory/api/docker/docker-remote/v2/nginx/manifests/sha256:abc123def456"},
			wantName:         "nginx",
			wantVersion:      "sha256:abc123def456",
		},
		{
			name:             "Docker image without version defaults to latest",
			id:               "docker://nginx",
			artiUrl:          "http://test.jfrog.io/artifactory",
			repo:             "docker-remote",
			wantDownloadUrls: []string{"http://test.jfrog.io/artifactory/api/docker/docker-remote/v2/nginx/manifests/latest"},
			wantName:         "nginx",
			wantVersion:      "latest",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDownloadUrls, gotName, gotVersion := getDockerNameAndVersion(tt.id, tt.artiUrl, tt.repo)
			assert.Equal(t, tt.wantDownloadUrls, gotDownloadUrls, "downloadUrls mismatch")
			assert.Equal(t, tt.wantName, gotName, "name mismatch")
			assert.Equal(t, tt.wantVersion, gotVersion, "version mismatch")
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
			name: "partial CVS fallback report — IsPartial propagates to summary",
			input: map[string]*CurationReport{
				"project1": {
					packagesStatus: []*PackageStatus{
						{
							PackageName:    "langchain-core",
							PackageVersion: "1.4.7",
							ParentVersion:  "1.4.7",
							ParentName:     "langchain-core",
							Action:         "blocked",
							Policy:         []Policy{{Policy: "p", Condition: "immature"}},
						},
					},
					totalNumberOfPackages: 1,
					isPartial:             true,
				},
			},
			expected: formats.ResultsSummary{
				Scans: []formats.ScanSummary{
					{
						Target: "project1",
						CuratedPackages: &formats.CuratedPackages{
							PackageCount: 1,
							IsPartial:    true,
							Blocked: []formats.BlockedPackages{{
								Policy:    "p",
								Condition: "immature",
								Packages:  map[string]int{"langchain-core:1.4.7": 1},
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

func Test_getSelectedPackages(t *testing.T) {
	blockedPackages := []*PackageStatus{
		{PackageName: "pkg1", PackageVersion: "1.0.0"},
		{PackageName: "pkg2", PackageVersion: "2.0.0"},
		{PackageName: "pkg3", PackageVersion: "3.0.0"},
		{PackageName: "pkg4", PackageVersion: "4.0.0"},
	}

	tests := []struct {
		name           string
		requestedRows  string
		expectedResult []*PackageStatus
		expectedOk     bool
	}{
		{
			name:           "Select all packages",
			requestedRows:  "all",
			expectedResult: blockedPackages,
			expectedOk:     true,
		},
		{
			name:           "Select single package",
			requestedRows:  "2",
			expectedResult: []*PackageStatus{blockedPackages[1]},
			expectedOk:     true,
		},
		{
			name:           "Select multiple packages",
			requestedRows:  "1,3",
			expectedResult: []*PackageStatus{blockedPackages[0], blockedPackages[2]},
			expectedOk:     true,
		},
		{
			name:           "Select range of packages",
			requestedRows:  "2-4",
			expectedResult: []*PackageStatus{blockedPackages[1], blockedPackages[2], blockedPackages[3]},
			expectedOk:     true,
		},
		{
			name:           "Select mixed indices and ranges",
			requestedRows:  "1,3-4",
			expectedResult: []*PackageStatus{blockedPackages[0], blockedPackages[2], blockedPackages[3]},
			expectedOk:     true,
		},
		{
			name:           "Select overlapping ranges",
			requestedRows:  "2-3,2,3,3-4",
			expectedResult: []*PackageStatus{blockedPackages[1], blockedPackages[2], blockedPackages[3]},
			expectedOk:     true,
		},
		{
			name:           "Empty input",
			requestedRows:  "",
			expectedResult: nil,
			expectedOk:     false,
		},
		{
			name:           "Invalid format",
			requestedRows:  "invalid",
			expectedResult: nil,
			expectedOk:     false,
		},
		{
			name:           "Out of range index",
			requestedRows:  "5",
			expectedResult: nil,
			expectedOk:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := getSelectedPackages(tt.requestedRows, blockedPackages)
			assert.Equal(t, tt.expectedResult, result)
			assert.Equal(t, tt.expectedOk, ok)
		})
	}
}

func TestSendWaiverRequests(t *testing.T) {
	tests := []struct {
		name           string
		pkgs           []*PackageStatus
		msg            string
		mockResponse   string
		expectedStatus []WaiverResponse
		expectError    bool
		testCase
	}{
		{
			name: "Single package approved",
			pkgs: []*PackageStatus{
				{
					BlockedPackageUrl: "http://localhost:8046/artifactory/api/go/go-virtual/rsc.io/sampler/@v/v1.3.0.zip",
					PackageName:       "rsc.io/sampler",
					PackageVersion:    "v1.3.0",
				},
			},
			msg:          "Requesting waiver for testing",
			mockResponse: `{"errors":[{"status":200,"message":"waiver-id|approved"}]}`,
			expectedStatus: []WaiverResponse{
				{
					PkgName:     "rsc.io/sampler",
					Status:      "approved",
					WaiverID:    "waiver-id",
					Explanation: WaiverRequestApproved,
				},
			},
			expectError: false,
		},
		{
			name: "Single package forbidden",
			pkgs: []*PackageStatus{
				{
					BlockedPackageUrl: "http://localhost:8046/artifactory/api/go/go-virtual/rsc.io/sampler/@v/v1.3.0.zip",
					PackageName:       "rsc.io/sampler",
					PackageVersion:    "v1.3.0",
				},
			},
			msg:          "Requesting waiver for testing",
			mockResponse: `{"errors":[{"status":403,"message":"waiver-id|forbidden"}]}`,
			expectedStatus: []WaiverResponse{
				{
					PkgName:     "rsc.io/sampler",
					Status:      "forbidden",
					WaiverID:    "waiver-id",
					Explanation: WaiverRequestForbidden,
				},
			},
			expectError: false,
		},
		{
			name: "Error while sending requests",
			pkgs: []*PackageStatus{
				{
					BlockedPackageUrl: "http://localhost:8046/artifactory/api/go/go-virtual/rsc.io/sampler/@v/v1.3.0.zip",
					PackageName:       "rsc.io/sampler",
					PackageVersion:    "v1.3.0",
				},
			},
			msg:            "Requesting waiver for testing",
			mockResponse:   `{"errors":[{"status":500,"message":"error"}]}`,
			expectedStatus: nil,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock server to simulate Artifactory responses
			testHandler := func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				_, err := w.Write([]byte(tt.mockResponse))
				assert.NoError(t, err)
			}
			mockServer, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, testHandler)
			defer mockServer.Close()

			// Create CurationAuditCommand instance
			ca := &CurationAuditCommand{}

			// Call the function
			for _, pkg := range tt.pkgs {
				pkg.BlockedPackageUrl = strings.ReplaceAll(pkg.BlockedPackageUrl, "http://localhost:8046/", serverDetails.GetArtifactoryUrl())
			}
			requestStatuses, err := ca.sendWaiverRequests(tt.pkgs, tt.msg, serverDetails)

			// Assertions
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedStatus, requestStatuses)
			}
		})
	}
}

// TestFetchNodesStatusConcurrentMapWrite reproduces crash
// reported when many packages are blocked by curation simultaneously.
func TestFetchNodesStatusConcurrentMapWrite(t *testing.T) {
	const numNodes = 50

	// Mock server: HEAD returns 403 for all packages, GET returns curation block JSON
	blockResponse := `{"errors":[{"status":403,"message":"Package download was blocked by JFrog Packages Curation service due to the following policies violated {testPolicy, testCondition, testExplanation, testRecommendation}"}]}`
	serverMock, _, rtManager := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(blockResponse))
			return
		}
	})
	defer serverMock.Close()

	rtAuth := rtManager.GetConfig().GetServiceDetails()
	httpClientDetails := rtAuth.CreateHttpClientDetails()

	root := &xrayUtils.GraphNode{Id: "npm://root:1.0.0"}
	for i := 0; i < numNodes; i++ {
		root.Nodes = append(root.Nodes, &xrayUtils.GraphNode{
			Id: fmt.Sprintf("npm://pkg-%d:%d.0.0", i, i),
		})
	}

	analyzer := treeAnalyzer{
		rtManager:            rtManager,
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
		rtAuth:               rtAuth,
		httpClientDetails:    httpClientDetails,
		url:                  rtAuth.GetUrl(),
		repo:                 "npm-remote",
		tech:                 techutils.Npm,
		parallelRequests:     10,
	}

	packagesStatusMap := sync.Map{}
	rootNodes := map[string]struct{}{root.Id: {}}

	// This will crash with "concurrent map writes" without the fix
	err := analyzer.fetchNodesStatus(root, &packagesStatusMap, rootNodes)
	assert.NoError(t, err)

	// Verify all blocked packages were recorded
	count := 0
	packagesStatusMap.Range(func(_, _ any) bool {
		count++
		return true
	})
	assert.Equal(t, numNodes, count, "expected all %d packages to be recorded as blocked", numNodes)
}

// =============================================================================
// Tests for Poetry support added to curationaudit.go.
// Covers the new dispatcher case (Pip, Poetry -> getPythonNameVersion) and the
// supportedTech registration.
// =============================================================================

func Test_getPythonNameVersion(t *testing.T) {
	const exampleUrl = "https://test.jfrog.io/artifactory/api/pypi/pypi-remote/packages/aa/bb/flask-2.0.0-py3-none-any.whl"

	tests := []struct {
		name             string
		id               string
		downloadUrlsMap  map[string]string
		wantDownloadUrls []string
		wantName         string
		wantVersion      string
	}{
		{
			name:             "pip id with matching download url",
			id:               "pypi://flask:2.0.0",
			downloadUrlsMap:  map[string]string{"pypi://flask:2.0.0": exampleUrl},
			wantDownloadUrls: []string{exampleUrl},
			wantName:         "flask",
			wantVersion:      "2.0.0",
		},
		{
			name:             "poetry id with matching download url (same pypi:// prefix)",
			id:               "pypi://click:8.0.1",
			downloadUrlsMap:  map[string]string{"pypi://click:8.0.1": exampleUrl},
			wantDownloadUrls: []string{exampleUrl},
			wantName:         "click",
			wantVersion:      "8.0.1",
		},
		{
			name:             "id present in map but no entry returns name+version only",
			id:               "pypi://requests:2.31.0",
			downloadUrlsMap:  map[string]string{"pypi://other:1.0.0": exampleUrl},
			wantDownloadUrls: nil,
			wantName:         "requests",
			wantVersion:      "2.31.0",
		},
		{
			name:             "nil downloadUrlsMap returns name+version only",
			id:               "pypi://requests:2.31.0",
			downloadUrlsMap:  nil,
			wantDownloadUrls: nil,
			wantName:         "requests",
			wantVersion:      "2.31.0",
		},
		{
			name:             "malformed id (no version separator) returns empty",
			id:               "pypi://malformed",
			downloadUrlsMap:  nil,
			wantDownloadUrls: nil,
			wantName:         "",
			wantVersion:      "",
		},
		{
			name:             "hyphenated name resolved via normalization fallback",
			id:               "pypi://Flask-Babel:1.0",
			downloadUrlsMap:  map[string]string{"pypi://flask_babel:1.0": exampleUrl},
			wantDownloadUrls: []string{exampleUrl},
			wantName:         "Flask-Babel",
			wantVersion:      "1.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDownloadUrls, gotName, gotVersion := getPythonNameVersion(tt.id, tt.downloadUrlsMap)
			assert.Equal(t, tt.wantDownloadUrls, gotDownloadUrls, "downloadUrls mismatch")
			assert.Equal(t, tt.wantName, gotName, "name mismatch")
			assert.Equal(t, tt.wantVersion, gotVersion, "version mismatch")
		})
	}
}

// TestGetBlockedPackageDetails_403UnparsableBodyReturnsBlocked verifies that
// getBlockedPackageDetails returns a blocked PackageStatus (no error) when a 403
// response body cannot be resolved to a known curation block reason:
// (1) the body is not valid JSON (e.g. an HTML error page), or
// (2) the body is valid JSON but the Errors array is empty.
// In both cases the 403 itself is treated as authoritative — the package is
// recorded as blocked with an unknown policy rather than being dropped silently.
func TestGetBlockedPackageDetails_403UnparsableBodyReturnsBlocked(t *testing.T) {
	tests := []struct {
		name     string
		respBody string
	}{
		{
			name:     "non-JSON body (HTML error page)",
			respBody: "<html><body><h1>403 Forbidden</h1></body></html>",
		},
		{
			name:     "JSON body with empty errors list",
			respBody: `{"errors":[]}`,
		},
	}

	const (
		pkgName    = "telnyx"
		pkgVersion = "4.87.1"
	)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverMock, _, rtManager := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(tt.respBody))
			})
			defer serverMock.Close()

			rtAuth := rtManager.GetConfig().GetServiceDetails()
			httpClientDetails := rtAuth.CreateHttpClientDetails()
			analyzer := treeAnalyzer{
				rtManager:            rtManager,
				rtAuth:               rtAuth,
				httpClientDetails:    httpClientDetails,
				extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
				url:                  rtAuth.GetUrl(),
				repo:                 "pypi-remote",
				tech:                 techutils.Poetry,
			}
			packageUrl := fmt.Sprintf("%sapi/pypi/pypi-remote/packages/%s-%s.tar.gz", rtAuth.GetUrl(), pkgName, pkgVersion)

			got, err := analyzer.getBlockedPackageDetails(packageUrl, pkgName, pkgVersion)

			require.NoError(t, err, "unparsable 403 body should not surface as an error")
			require.NotNil(t, got, "a blocked PackageStatus must be returned when the 403 block reason is unknown")
			assert.Equal(t, blocked, got.Action)
			assert.Equal(t, BlockingReasonUnknown, got.BlockingReason)
			assert.Equal(t, pkgName, got.PackageName)
			assert.Equal(t, pkgVersion, got.PackageVersion)
		})
	}
}

// TestFetchCvsBlockedStatusTransitive verifies the CVS fallback for a transitive range blocker:
// the range is resolved to the newest satisfying version and the policy is recovered from the 403 probe.
func TestFetchCvsBlockedStatusTransitive(t *testing.T) {
	const (
		repo            = "test-pip-repo"
		blockedPkg      = "langchain-core"
		blockedVer      = "1.4.7"
		parentPkg       = "deepagents"
		parentVer       = "0.6.1"
		rangeSpec       = ">=1.4.0"
		expectedPolicy  = "strict-immature-policy"
		expectedCond    = "Package version is immature (strict)"
		expectedExpl    = "Package version is 3 days old"
		expectedRec     = "Use an older version or wait until this version is no longer immature"
		whlRelativePath = "packages/ab/cd/langchain_core-1.4.7-py3-none-any.whl"
	)

	// Curation 403 body returned when the normal download URL is probed.
	blockMsg := fmt.Sprintf(
		"Package %s:%s download was blocked by JFrog Packages Curation service due to the following policies violated {%s, %s, %s, %s}.",
		blockedPkg, blockedVer, expectedPolicy, expectedCond, expectedExpl, expectedRec,
	)
	blockResponse := fmt.Sprintf(`{"errors":[{"status":403,"message":%q}]}`, blockMsg)

	// All-versions metadata JSON (the simple-index-unfiltered endpoint).
	allVersionsJSON := `{"releases":{"1.4.0":[],"1.4.1":[],"1.4.5":[],"1.4.7":[]}}`

	// Version-specific metadata JSON (returns the whl download URL).
	versionMetaJSON := fmt.Sprintf(`{"urls":[{"packagetype":"bdist_wheel","url":"../../%s"}]}`, whlRelativePath)

	serverMock, _, rtManager := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		// All-versions metadata: /api/pypi/<repo>/pypi/<name>/json
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/pypi/"+blockedPkg+"/json"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(allVersionsJSON))

		// Version-specific metadata: /api/pypi/<repo>/pypi/<name>/<ver>/json
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/pypi/"+blockedPkg+"/"+blockedVer+"/json"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(versionMetaJSON))

		// Normal download URL probe: HEAD first → 403 (detection step)
		case r.Method == http.MethodHead && strings.Contains(r.URL.Path, whlRelativePath):
			w.WriteHeader(http.StatusForbidden)

		// Normal download URL probe: GET with waiver → 403 with policy body
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, whlRelativePath):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(blockResponse))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer serverMock.Close()

	rtAuth := rtManager.GetConfig().GetServiceDetails()
	httpClientDetails := rtAuth.CreateHttpClientDetails()

	analyzer := treeAnalyzer{
		rtManager:            rtManager,
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
		rtAuth:               rtAuth,
		httpClientDetails:    httpClientDetails,
		url:                  rtAuth.GetUrl(),
		repo:                 repo,
		tech:                 techutils.Pip,
		parallelRequests:     1,
	}

	// Transitive PinnedRequirement: langchain-core with deepagents as parent.
	pins := []python.PinnedRequirement{
		{
			Name:          blockedPkg,
			VersionRange:  rangeSpec,
			ParentName:    parentPkg,
			ParentVersion: parentVer,
		},
	}

	statuses := analyzer.fetchCvsBlockedStatus(pins)
	require.Len(t, statuses, 1)

	s := statuses[0]

	// Blocked package attribution
	assert.Equal(t, blockedPkg, s.PackageName, "blocked package name")
	assert.Equal(t, blockedVer, s.PackageVersion, "blocked package version — newest satisfying range")

	// Parent (direct dep) attribution
	assert.Equal(t, parentPkg, s.ParentName, "direct dependency name")
	assert.Equal(t, parentVer, s.ParentVersion, "direct dependency version")

	// Policy details recovered from the 403 probe
	require.Len(t, s.Policy, 1)
	assert.Equal(t, expectedPolicy, s.Policy[0].Policy, "violated policy name")
	assert.Equal(t, expectedCond, s.Policy[0].Condition, "violated condition name")
	assert.Equal(t, expectedExpl, s.Policy[0].Explanation, "explanation")
	assert.Equal(t, expectedRec, s.Policy[0].Recommendation, "recommendation")
	assert.Equal(t, blocked, s.Action)
}

// TestFetchCvsBlockedStatusNotInMetadataNotRendered verifies that a version absent from the metadata API is not rendered as a blocked row.
func TestFetchCvsBlockedStatusNotInMetadataNotRendered(t *testing.T) {
	const (
		repo = "test-pip-repo"
		pkg  = "telnyx"
		ver  = "4.87.1000" // not in the metadata API
	)

	serverMock, _, rtManager := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/pypi/"+pkg+"/"+ver+"/json"):
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer serverMock.Close()

	rtAuth := rtManager.GetConfig().GetServiceDetails()
	analyzer := treeAnalyzer{
		rtManager:            rtManager,
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
		rtAuth:               rtAuth,
		httpClientDetails:    rtAuth.CreateHttpClientDetails(),
		url:                  rtAuth.GetUrl(),
		repo:                 repo,
		tech:                 techutils.Pip,
		parallelRequests:     1,
	}

	pins := []python.PinnedRequirement{
		{Name: pkg, Version: ver, ParentName: pkg, ParentVersion: ver},
	}

	statuses := analyzer.fetchCvsBlockedStatus(pins)
	assert.Empty(t, statuses, "a version absent from the metadata API must not be rendered as a blocked row")
}

// TestFetchCvsBlockedStatusSetsDepRelation verifies DepRelation is populated for both direct and transitive CVS-fallback rows.
func TestFetchCvsBlockedStatusSetsDepRelation(t *testing.T) {
	const (
		repo            = "test-pip-repo"
		blockedPkg      = "langchain-core"
		blockedVer      = "1.4.7"
		parentPkg       = "deepagents"
		parentVer       = "0.6.1"
		whlRelativePath = "packages/ab/cd/langchain_core-1.4.7-py3-none-any.whl"
	)

	serverMock, _, rtManager := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/pypi/"+blockedPkg+"/json"):
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"releases":{%q:[]}}`, blockedVer)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/pypi/"+blockedPkg+"/"+blockedVer+"/json"):
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"urls":[{"packagetype":"bdist_wheel","url":"../../%s"}]}`, whlRelativePath)
		case r.Method == http.MethodHead:
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":[{"status":403,"message":"Package langchain-core:1.4.7 download was blocked by Curation service due to policy 'strict-policy'","policy":"strict-policy","condition":"immature","explanation":"too new","recommendation":"use older"}]}`))
		}
	})
	defer serverMock.Close()

	rtAuth := rtManager.GetConfig().GetServiceDetails()
	analyzer := treeAnalyzer{
		rtManager:            rtManager,
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
		rtAuth:               rtAuth,
		httpClientDetails:    rtAuth.CreateHttpClientDetails(),
		url:                  rtAuth.GetUrl(),
		repo:                 repo,
		tech:                 techutils.Pip,
	}

	// Transitive pin: parent differs from package → indirect.
	pins := []python.PinnedRequirement{
		{Name: blockedPkg, VersionRange: ">=1.4.0", ParentName: parentPkg, ParentVersion: parentVer},
	}
	statuses := analyzer.fetchCvsBlockedStatus(pins)
	require.Len(t, statuses, 1)
	assert.Equal(t, indirectRelation, statuses[0].DepRelation, "transitive CVS-fallback row must be indirect")

	// Direct pin: parent equals package → direct.
	pins = []python.PinnedRequirement{
		{Name: blockedPkg, Version: blockedVer, ParentName: blockedPkg, ParentVersion: blockedVer},
	}
	statuses = analyzer.fetchCvsBlockedStatus(pins)
	require.Len(t, statuses, 1)
	assert.Equal(t, directRelation, statuses[0].DepRelation, "direct CVS-fallback row must be direct")

	// ResolutionImpossible: name-only, self-attributed → must be indirect.
	pins = []python.PinnedRequirement{
		{Name: blockedPkg, ParentName: blockedPkg}, // no Version, no VersionRange
	}
	statuses = analyzer.fetchCvsBlockedStatus(pins)
	require.Len(t, statuses, 1)
	assert.Equal(t, indirectRelation, statuses[0].DepRelation,
		"ResolutionImpossible CVS-fallback row must be indirect (parent unknown)")
}

// TestFetchCvsBlockedStatusHeadErrorNoFalsePositive verifies that a HEAD transport error does not
// produce a spurious blocked row.
func TestFetchCvsBlockedStatusHeadErrorNoFalsePositive(t *testing.T) {
	const (
		repo            = "test-pip-repo"
		pkg             = "foo"
		ver             = "1.0"
		whlRelativePath = "packages/ab/cd/foo-1.0-py3-none-any.whl"
	)

	serverMock, _, rtManager := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead:
			w.WriteHeader(http.StatusInternalServerError)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/pypi/"+pkg+"/"+ver+"/json"):
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"urls":[{"packagetype":"bdist_wheel","url":"../../%s"}]}`, whlRelativePath)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer serverMock.Close()

	rtAuth := rtManager.GetConfig().GetServiceDetails()
	analyzer := treeAnalyzer{
		rtManager:            rtManager,
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
		rtAuth:               rtAuth,
		httpClientDetails:    rtAuth.CreateHttpClientDetails(),
		url:                  rtAuth.GetUrl(),
		repo:                 repo,
		tech:                 techutils.Pip,
	}

	pins := []python.PinnedRequirement{{Name: pkg, Version: ver, ParentName: pkg, ParentVersion: ver}}
	statuses := analyzer.fetchCvsBlockedStatus(pins)
	assert.Empty(t, statuses, "HEAD transport error must not produce a false-positive blocked row")
}

// TestFetchCvsBlockedStatusHeadOKNoFalsePositive verifies that a HEAD 200 (stale CVS cache scenario)
// does not produce a spurious blocked row. When pip's CVS-filtered simple-index hid a version but
// the artifact is now accessible (policy changed, waiver granted), HEAD returns 200 and the package
// must be skipped entirely.
func TestFetchCvsBlockedStatusHeadOKNoFalsePositive(t *testing.T) {
	const (
		repo            = "test-pip-repo"
		pkg             = "foo"
		ver             = "1.0"
		whlRelativePath = "packages/ab/cd/foo-1.0-py3-none-any.whl"
	)

	serverMock, _, rtManager := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead:
			// Stale CVS cache cleared; package is now accessible.
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/pypi/"+pkg+"/"+ver+"/json"):
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"urls":[{"packagetype":"bdist_wheel","url":"../../%s"}]}`, whlRelativePath)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer serverMock.Close()

	rtAuth := rtManager.GetConfig().GetServiceDetails()
	analyzer := treeAnalyzer{
		rtManager:            rtManager,
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
		rtAuth:               rtAuth,
		httpClientDetails:    rtAuth.CreateHttpClientDetails(),
		url:                  rtAuth.GetUrl(),
		repo:                 repo,
		tech:                 techutils.Pip,
	}

	pins := []python.PinnedRequirement{{Name: pkg, Version: ver, ParentName: pkg, ParentVersion: ver}}
	statuses := analyzer.fetchCvsBlockedStatus(pins)
	assert.Empty(t, statuses, "HEAD 200 (stale CVS cache) must not produce a false-positive blocked row")
}

// TestRunCvsFallbackGetWdFailurePreservesResults verifies that a failed os.Getwd() does not cause
// runCvsFallback to discard the already-recovered packagesStatus. The results map must be populated
// under the "unknown-project" fallback key instead of silently returning cvsErr.
func TestRunCvsFallbackGetWdFailurePreservesResults(t *testing.T) {
	const (
		repo            = "test-pip-repo"
		blockedPkg      = "langchain-core"
		blockedVer      = "1.4.7"
		whlRelativePath = "packages/ab/cd/langchain_core-1.4.7-py3-none-any.whl"
	)
	blockJSON := `{"errors":[{"status":403,"message":"Package langchain-core:1.4.7 download was blocked by Curation service due to policy 'p'","policy":"p","condition":"immature","explanation":"too new","recommendation":"use older"}]}`
	serverMock, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/pypi/"+blockedPkg+"/"+blockedVer+"/json"):
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"urls":[{"packagetype":"bdist_wheel","url":"../../%s"}]}`, whlRelativePath)
		case r.Method == http.MethodHead:
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(blockJSON))
		}
	})
	defer serverMock.Close()

	repoConfig := (&project.RepositoryConfig{}).
		SetTargetRepo(repo).
		SetServerDetails(serverDetails)
	ca := &CurationAuditCommand{
		PackageManagerConfig: repoConfig,
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
	}

	// Simulate os.Getwd() failure via the injectable function variable.
	orig := osGetwd
	osGetwd = func() (string, error) { return "", errors.New("simulated: no such file or directory") }
	t.Cleanup(func() { osGetwd = orig })

	cvsErr := &python.CvsBlockedError{
		Packages: []python.PinnedRequirement{
			{Name: blockedPkg, Version: blockedVer, ParentName: blockedPkg, ParentVersion: blockedVer},
		},
	}
	results := map[string]*CurationReport{}
	err := ca.runCvsFallback(cvsErr, techutils.Pip, results)

	assert.NoError(t, err, "os.Getwd failure must not surface as an error")
	assert.Len(t, results, 1, "recovered packagesStatus must be stored even when Getwd fails")
	assert.Contains(t, results, "unknown-project", "results key must be the fallback key when Getwd fails")
}

// TestEffectiveParentVersion covers all branches of the effectiveParentVersion helper.
func TestEffectiveParentVersion(t *testing.T) {
	cases := []struct {
		name string
		pin  python.PinnedRequirement
		want string
	}{
		{"exact direct", python.PinnedRequirement{Name: "foo", Version: "1.0", ParentName: "foo", ParentVersion: "1.0"}, "1.0"},
		{"direct range — shows range spec", python.PinnedRequirement{Name: "foo", VersionRange: ">=1.4", ParentName: "foo"}, ">=1.4"},
		{"transitive range — parent ver unknown", python.PinnedRequirement{Name: "foo", VersionRange: ">=1.4", ParentName: "bar"}, ""},
		{"transitive with known parent ver", python.PinnedRequirement{Name: "foo", VersionRange: ">=1.4", ParentName: "bar", ParentVersion: "2.3"}, "2.3"},
		{"ResolutionImpossible — all empty", python.PinnedRequirement{Name: "foo", ParentName: "foo"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, effectiveParentVersion(tc.pin))
		})
	}
}

func TestValidateRunNativeForTech(t *testing.T) {
	// Sanity: npm and pnpm are the allow-listed techs. Both flag states pass.
	assert.NoError(t, validateRunNativeForTech(techutils.Npm, true))
	assert.NoError(t, validateRunNativeForTech(techutils.Npm, false))
	assert.NoError(t, validateRunNativeForTech(techutils.Pnpm, true))
	assert.NoError(t, validateRunNativeForTech(techutils.Pnpm, false))

	// The failing-test scenario from the bug report: yarn + --run-native
	// must exit non-zero with a yarn-named error that points the user at
	// the supported config flow.
	t.Run("yarn rejects --run-native with actionable message", func(t *testing.T) {
		err := validateRunNativeForTech(techutils.Yarn, true)
		if assert.Error(t, err) {
			msg := err.Error()
			// Tech-neutral phrasing — the message must not hard-code
			// "only supported for npm", because the allow-list is the
			// source of truth and may grow over time.
			assert.Contains(t, msg, "--run-native is not supported for 'yarn' projects")
			assert.Contains(t, msg, "jf yarn-config", "the error must point the user at the supported config flow")
		}
		// Without the flag, yarn must pass validation cleanly — the
		// guard is strictly conditional on --run-native being on.
		assert.NoError(t, validateRunNativeForTech(techutils.Yarn, false))
	})

	// Every other supported tech follows the same contract. Catch silent
	// acceptance for any tech that's in the doc-table-of-supported but
	// hasn't implemented a native flow — same UX as yarn.
	otherTechs := []techutils.Technology{
		techutils.Gradle,
		techutils.Maven,
		techutils.Gem,
		techutils.Pip,
		techutils.Go,
		techutils.Nuget,
		techutils.Dotnet,
		techutils.Conan,
		techutils.Cocoapods,
		techutils.Swift,
		techutils.Docker,
	}
	for _, tech := range otherTechs {
		t.Run(tech.String()+" rejects --run-native", func(t *testing.T) {
			err := validateRunNativeForTech(tech, true)
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), tech.String(),
					"error message must name the offending tech so users running mixed-tech audits know which sub-audit complained")
			}
			assert.NoError(t, validateRunNativeForTech(tech, false))
		})
	}
}

// TestResolveResolverTechForCuration locks in the npm.yaml ↔ yarn.yaml
// fallback for the resolver-config lookup in auditTree. The exact
// reason this fallback has to live here, separate from the existing
// SetRepo fallback, is that auditTree calls
// SetResolutionRepoInParamsIfExists *before* it reaches SetRepo — and
// that earlier call is what populates params.DependenciesRepository,
// which in turn decides whether configureYarnResolutionServerAndRunInstall
// performs the .yarnrc.yml backup/replace/restore round-trip. Without
// the round-trip, a 'yarn install' against curation that hits a 403
// can leave the workspace install state inconsistent and the
// downstream 'yarn info' enumeration fails with a workspace-assertion
// error. So the contract under test is twofold:
//
//  1. For tech=Yarn with only npm.yaml present, return Npm so the
//     resolver lookup reads npm.yaml (npm and yarn share the same
//     Artifactory npm API, so the same repo serves both ecosystems).
//  2. For any other input (yarn.yaml present, both present, neither
//     present, or tech≠Yarn) return the input tech unchanged.
//
// The Npm-detected case is intentionally not exercised here because
// resolveNpmYarnTech already upgrades that case to Yarn at the
// detection layer (see TestResolveNpmYarnTech-style coverage in
// resolveNpmYarnTech consumers); by the time auditTree sees tech=Npm
// a matching npm.yaml is guaranteed to exist.
//
// Each subtest builds a hermetic .jfrog/projects/ directory, chdirs
// into it, and isolates JFROG_CLI_HOME_DIR so a real config on the
// developer's machine can't leak in.
func TestResolveResolverTechForCuration(t *testing.T) {
	type setup struct {
		writeYarnYaml bool
		writeNpmYaml  bool
	}
	testCases := []struct {
		name string
		tech techutils.Technology
		setup
		want techutils.Technology
	}{
		{
			name:  "yarn with yarn.yaml present — no fallback, lookup must use yarn.yaml directly",
			tech:  techutils.Yarn,
			setup: setup{writeYarnYaml: true},
			want:  techutils.Yarn,
		},
		{
			name:  "yarn with only npm.yaml — falls back to npm so the resolver lookup reads npm.yaml",
			tech:  techutils.Yarn,
			setup: setup{writeNpmYaml: true},
			want:  techutils.Npm,
		},
		{
			name:  "yarn with both configs — yarn.yaml wins; fallback only triggers when primary is missing",
			tech:  techutils.Yarn,
			setup: setup{writeYarnYaml: true, writeNpmYaml: true},
			want:  techutils.Yarn,
		},
		{
			name: "yarn with neither config — no fallback target; return Yarn so the downstream lookup no-ops cleanly",
			tech: techutils.Yarn,
			want: techutils.Yarn,
		},
		{
			name:  "npm input — never rewritten by this helper (resolveNpmYarnTech owns the inverse direction at the detection layer)",
			tech:  techutils.Npm,
			setup: setup{writeYarnYaml: true},
			want:  techutils.Npm,
		},
		{
			name:  "non-npm/yarn tech is passed through untouched even when npm.yaml exists",
			tech:  techutils.Maven,
			setup: setup{writeNpmYaml: true},
			want:  techutils.Maven,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tempProjectDir := t.TempDir()
			projectsDir := filepath.Join(tempProjectDir, ".jfrog", "projects")
			require.NoError(t, os.MkdirAll(projectsDir, 0o755))
			if tc.writeYarnYaml {
				require.NoError(t, os.WriteFile(filepath.Join(projectsDir, "yarn.yaml"), []byte("resolver:\n  serverId: test\n  repo: irrelevant-yarn-repo\n"), 0o644))
			}
			if tc.writeNpmYaml {
				require.NoError(t, os.WriteFile(filepath.Join(projectsDir, "npm.yaml"), []byte("resolver:\n  serverId: test\n  repo: irrelevant-npm-repo\n"), 0o644))
			}
			// Isolate JFROG_CLI_HOME_DIR so a real ~/.jfrog/projects/*.yaml
			// on the developer's machine can't leak into the fallback
			// (GetProjectConfFilePath falls back to JFROG_CLI_HOME_DIR
			// when nothing matches walking up from CWD).
			restoreHome := clienttestutils.SetEnvWithCallbackAndAssert(t, coreutils.HomeDir, t.TempDir())
			defer restoreHome()
			restoreCwd := changeDirForTest(t, tempProjectDir)
			defer restoreCwd()

			got := resolveResolverTechForCuration(tc.tech)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestResolveNpmYarnTech(t *testing.T) {
	type setup struct {
		writeYarnYaml bool
		writeNpmYaml  bool
	}
	testCases := []struct {
		name  string
		tech  string
		setup setup
		want  string
	}{
		{
			name:  "npm with yarn.yaml only — promoted to yarn",
			tech:  techutils.Npm.String(),
			setup: setup{writeYarnYaml: true},
			want:  techutils.Yarn.String(),
		},
		{
			name:  "npm with both yaml files — npm.yaml wins, no promotion",
			tech:  techutils.Npm.String(),
			setup: setup{writeYarnYaml: true, writeNpmYaml: true},
			want:  techutils.Npm.String(),
		},
		{
			name:  "npm with npm.yaml only — stays npm",
			tech:  techutils.Npm.String(),
			setup: setup{writeNpmYaml: true},
			want:  techutils.Npm.String(),
		},
		{
			name:  "npm with neither yaml — stays npm",
			tech:  techutils.Npm.String(),
			setup: setup{},
			want:  techutils.Npm.String(),
		},
		{
			name:  "yarn input is never rewritten by this helper",
			tech:  techutils.Yarn.String(),
			setup: setup{writeYarnYaml: true},
			want:  techutils.Yarn.String(),
		},
		{
			name:  "non-npm/yarn tech passes through untouched",
			tech:  techutils.Maven.String(),
			setup: setup{writeYarnYaml: true},
			want:  techutils.Maven.String(),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tempProjectDir := t.TempDir()
			projectsDir := filepath.Join(tempProjectDir, ".jfrog", "projects")
			require.NoError(t, os.MkdirAll(projectsDir, 0o755))
			if tc.setup.writeYarnYaml {
				require.NoError(t, os.WriteFile(filepath.Join(projectsDir, "yarn.yaml"), []byte("resolver:\n  serverId: test\n  repo: irrelevant-yarn-repo\n"), 0o644))
			}
			if tc.setup.writeNpmYaml {
				require.NoError(t, os.WriteFile(filepath.Join(projectsDir, "npm.yaml"), []byte("resolver:\n  serverId: test\n  repo: irrelevant-npm-repo\n"), 0o644))
			}
			restoreHome := clienttestutils.SetEnvWithCallbackAndAssert(t, coreutils.HomeDir, t.TempDir())
			defer restoreHome()
			restoreCwd := changeDirForTest(t, tempProjectDir)
			defer restoreCwd()

			got := resolveNpmYarnTech(tc.tech)
			assert.Equal(t, tc.want, got)
		})
	}
}

func changeDirForTest(t *testing.T, dir string) func() {
	t.Helper()
	origCwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	return func() {
		// Restore CWD even if the test fails partway, so the next
		// subtest's GetProjectConfFilePath walk starts from a known dir.
		require.NoError(t, os.Chdir(origCwd))
	}
}

func TestPromotePnpmWorkspaceMember(t *testing.T) {
	npm := "npm"
	pnpm := "pnpm"
	other := "maven"

	tests := []struct {
		name             string
		techs            []string
		ancestorFile     string // file to create in the ancestor dir ("" = none)
		expectedHasPnpm  bool
		expectedHasNpm   bool
		expectNpmRemoved bool // npm was present in input and should be replaced by pnpm
	}{
		{
			// pnpm already present: function returns early, npm is NOT replaced.
			name:            "already has pnpm — no change",
			techs:           []string{pnpm, npm},
			expectedHasPnpm: true,
			expectedHasNpm:  true,
		},
		{
			name:            "no npm — no change",
			techs:           []string{other},
			expectedHasPnpm: false,
			expectedHasNpm:  false,
		},
		{
			name:            "npm only, no ancestor indicator — no promotion",
			techs:           []string{npm},
			ancestorFile:    "",
			expectedHasPnpm: false,
			expectedHasNpm:  true,
		},
		{
			name:             "npm only, ancestor has pnpm-workspace.yaml — promote",
			techs:            []string{npm},
			ancestorFile:     "pnpm-workspace.yaml",
			expectedHasPnpm:  true,
			expectedHasNpm:   false,
			expectNpmRemoved: true,
		},
		{
			name:             "npm only, ancestor has pnpm-lock.yaml — promote",
			techs:            []string{npm},
			ancestorFile:     "pnpm-lock.yaml",
			expectedHasPnpm:  true,
			expectedHasNpm:   false,
			expectNpmRemoved: true,
		},
		{
			name:             "npm + other, ancestor has pnpm-workspace.yaml — npm promoted, other kept",
			techs:            []string{npm, other},
			ancestorFile:     "pnpm-workspace.yaml",
			expectedHasPnpm:  true,
			expectedHasNpm:   false,
			expectNpmRemoved: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Build a two-level temp dir: root/sub — we run from sub so the walk finds root.
			root := t.TempDir()
			sub := filepath.Join(root, "sub")
			require.NoError(t, os.MkdirAll(sub, 0o755))

			if tc.ancestorFile != "" {
				require.NoError(t, os.WriteFile(filepath.Join(root, tc.ancestorFile), []byte{}, 0o644))
			}

			t.Chdir(sub)

			result := promotePnpmWorkspaceMember(tc.techs)

			hasPnpm, hasNpm := false, false
			for _, tech := range result {
				switch tech {
				case pnpm:
					hasPnpm = true
				case npm:
					hasNpm = true
				}
			}
			assert.Equal(t, tc.expectedHasPnpm, hasPnpm, "pnpm presence mismatch")
			assert.Equal(t, tc.expectedHasNpm, hasNpm, "npm presence mismatch")
			if tc.expectNpmRemoved {
				assert.False(t, hasNpm, "npm should have been replaced by pnpm")
				assert.True(t, hasPnpm, "pnpm should be present after promotion")
			}
		})
	}
}
