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
	"sync/atomic"
	"testing"

	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/java"
	"github.com/jfrog/jfrog-cli-security/utils/formats"

	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/gofrog/datastructures"
	rtUtils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/common/project"
	coreCommonTests "github.com/jfrog/jfrog-cli-core/v2/common/tests"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
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
				// Pre-populate the curation cache with all plugin artifact downloads so that
				// during the actual test run against the mock server only the blocked artifact
				// triggers an HTTP request. The -DincludePluginDeps=true flag causes
				// maven-dep-tree to resolve plugin transitive deps in the same invocation.
				return []string{
					"com.jfrog:maven-dep-tree:" + java.GetMavenDepTreeVersion() + ":tree",
					"-DdepsTreeOutputFile=output",
					"-Dmaven.repo.local=" + curationCache,
					"-DincludePluginDeps=true",
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
func Test_getHuggingFaceNameAndVersion(t *testing.T) {
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
			name:             "model with explicit sha revision",
			id:               "huggingfaceml://mcpotato/42-eicar-street:8fb61c4d511e9aaff0ea55396a124aa292830efc",
			artiUrl:          "https://test.jfrogdev.org/artifactory",
			repo:             "my-hugging-face-repo",
			wantDownloadUrls: []string{"https://test.jfrogdev.org/artifactory/api/huggingfaceml/my-hugging-face-repo/api/models/mcpotato/42-eicar-street/revision/8fb61c4d511e9aaff0ea55396a124aa292830efc"},
			wantName:         "mcpotato/42-eicar-street",
			wantVersion:      "8fb61c4d511e9aaff0ea55396a124aa292830efc",
		},
		{
			name:             "model with branch revision",
			id:               "huggingfaceml://bert-base-uncased:main",
			artiUrl:          "https://test.jfrogdev.org/artifactory",
			repo:             "my-hugging-face-repo",
			wantDownloadUrls: []string{"https://test.jfrogdev.org/artifactory/api/huggingfaceml/my-hugging-face-repo/api/models/bert-base-uncased/revision/main"},
			wantName:         "bert-base-uncased",
			wantVersion:      "main",
		},
		{
			name:             "model id with no revision defaults to main",
			id:               "huggingfaceml://org/model",
			artiUrl:          "https://test.jfrogdev.org/artifactory",
			repo:             "my-hugging-face-repo",
			wantDownloadUrls: []string{"https://test.jfrogdev.org/artifactory/api/huggingfaceml/my-hugging-face-repo/api/models/org/model/revision/main"},
			wantName:         "org/model",
			wantVersion:      "main",
		},
		{
			name:             "empty artiUrl and repo produce no download URL",
			id:               "huggingfaceml://org/model:main",
			artiUrl:          "",
			repo:             "",
			wantDownloadUrls: nil,
			wantName:         "org/model",
			wantVersion:      "main",
		},
		{
			name:             "empty id returns empty results",
			id:               "",
			artiUrl:          "https://test.jfrogdev.org/artifactory",
			repo:             "my-hugging-face-repo",
			wantDownloadUrls: nil,
			wantName:         "",
			wantVersion:      "",
		},
		{
			name:             "trailing slash stripped from artiUrl",
			id:               "huggingfaceml://org/model:v1.0",
			artiUrl:          "https://test.jfrogdev.org/artifactory/",
			repo:             "my-hugging-face-repo",
			wantDownloadUrls: []string{"https://test.jfrogdev.org/artifactory/api/huggingfaceml/my-hugging-face-repo/api/models/org/model/revision/v1.0"},
			wantName:         "org/model",
			wantVersion:      "v1.0",
		},
		{
			name:             "trailing colon defaults to main (not empty string)",
			id:               "huggingfaceml://org/model:",
			artiUrl:          "https://test.jfrogdev.org/artifactory",
			repo:             "my-hugging-face-repo",
			wantDownloadUrls: []string{"https://test.jfrogdev.org/artifactory/api/huggingfaceml/my-hugging-face-repo/api/models/org/model/revision/main"},
			wantName:         "org/model",
			wantVersion:      "main",
		},
		{
			name:             "leading colon only (no repo id) returns empty",
			id:               "huggingfaceml://:main",
			artiUrl:          "https://test.jfrogdev.org/artifactory",
			repo:             "my-hugging-face-repo",
			wantDownloadUrls: nil,
			wantName:         "",
			wantVersion:      "",
		},
		{
			// refs/pr/3 is a valid Hugging Face revision (a PR ref) and contains '/'.
			// It must be split off as the revision (not glued onto name) and
			// path-escaped in the URL so it lands as a single path segment.
			name:             "PR ref revision containing slashes is split and path-escaped",
			id:               "huggingfaceml://org/model:refs/pr/3",
			artiUrl:          "https://test.jfrogdev.org/artifactory",
			repo:             "my-hugging-face-repo",
			wantDownloadUrls: []string{"https://test.jfrogdev.org/artifactory/api/huggingfaceml/my-hugging-face-repo/api/models/org/model/revision/refs%2Fpr%2F3"},
			wantName:         "org/model",
			wantVersion:      "refs/pr/3",
		},
		{
			// repo_id (name) must be URL-escaped per segment just like revision already is —
			// otherwise '?', '#', or a space in a model ref produces a malformed/injected URL.
			name:             "repo_id with special characters is escaped per segment",
			id:               "huggingfaceml://org/weird model?id#frag:main",
			artiUrl:          "https://test.jfrogdev.org/artifactory",
			repo:             "my-hugging-face-repo",
			wantDownloadUrls: []string{"https://test.jfrogdev.org/artifactory/api/huggingfaceml/my-hugging-face-repo/api/models/org/weird%20model%3Fid%23frag/revision/main"},
			wantName:         "org/weird model?id#frag",
			wantVersion:      "main",
		},
		{
			// url.PathEscape leaves '.'/'..' unescaped (unreserved per RFC 3986), so a
			// repo_id segment of exactly ".." would still traverse the request path after
			// escaping. Such a segment must be rejected outright rather than escaped.
			name:             "repo_id with path-traversal segment produces no download URL",
			id:               "huggingfaceml://../../api/system/ping:main",
			artiUrl:          "https://test.jfrogdev.org/artifactory",
			repo:             "my-hugging-face-repo",
			wantDownloadUrls: nil,
			wantName:         "../../api/system/ping",
			wantVersion:      "main",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDownloadUrls, gotName, gotVersion := getHuggingFaceNameAndVersion(tt.id, tt.artiUrl, tt.repo)
			assert.Equal(t, tt.wantDownloadUrls, gotDownloadUrls, "downloadUrls mismatch")
			assert.Equal(t, tt.wantName, gotName, "name mismatch")
			assert.Equal(t, tt.wantVersion, gotVersion, "version mismatch")
		})
	}
}

func Test_validateCurationAuditFlags_DockerAndHuggingFaceConflict(t *testing.T) {
	ca := NewCurationAuditCommand().
		SetDockerImageName("my.registry/image:tag").
		SetHuggingFaceModel("org/model:main")
	err := validateCurationAuditFlags(ca)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--docker-image and --hugging-face-model cannot be used together")
}

func Test_validateCurationAuditFlags_DockerOnly(t *testing.T) {
	ca := NewCurationAuditCommand().SetDockerImageName("my.registry/image:tag")
	assert.NoError(t, validateCurationAuditFlags(ca))
}

func Test_hasPythonFiles_ExcludesDist(t *testing.T) {
	dir := t.TempDir()
	distDir := filepath.Join(dir, "dist")
	require.NoError(t, os.MkdirAll(distDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(distDir, "only_here.py"), []byte("x = 1\n"), 0644))
	assert.False(t, hasPythonFiles(dir))
}

func Test_hasPythonFiles_FindsProjectSource(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.py"), []byte("x = 1\n"), 0644))
	assert.True(t, hasPythonFiles(dir))
}

func Test_isHuggingFaceReport(t *testing.T) {
	hfPkg := &PackageStatus{PkgType: techutils.HuggingFaceML.String()}
	tests := []struct {
		name   string
		report *CurationReport
		want   bool
	}{
		{
			name:   "empty report",
			report: &CurationReport{},
			want:   false,
		},
		{
			name:   "warnings only without HF marker",
			report: &CurationReport{warnings: []string{"unresolved"}},
			want:   false,
		},
		{
			name:   "HF warnings-only placeholder",
			report: &CurationReport{warnings: []string{"unresolved"}, huggingFaceReport: true},
			want:   true,
		},
		{
			name:   "all HF packages",
			report: &CurationReport{packagesStatus: []*PackageStatus{hfPkg}},
			want:   true,
		},
		{
			name:   "mixed package types",
			report: &CurationReport{packagesStatus: []*PackageStatus{hfPkg, {PkgType: techutils.Pip.String()}}},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isHuggingFaceReport(tt.report))
		})
	}
}

func Test_isWarningsOnlyReport(t *testing.T) {
	assert.False(t, isWarningsOnlyReport(&CurationReport{}))
	assert.True(t, isWarningsOnlyReport(&CurationReport{warnings: []string{"warn"}}))
	assert.False(t, isWarningsOnlyReport(&CurationReport{
		packagesStatus: []*PackageStatus{{PkgType: techutils.HuggingFaceML.String()}},
	}))
	// packagesStatus only ever holds blocked packages (see fetchNodeStatus), so an
	// all-clean audit of a real package also has an empty packagesStatus — same
	// shape as the true "nothing was audited" placeholder. totalNumberOfPackages
	// must be the signal that disambiguates them, not packagesStatus emptiness.
	assert.False(t, isWarningsOnlyReport(&CurationReport{
		totalNumberOfPackages: 1,
		warnings:              []string{"dynamic revision"},
	}))
}

func Test_countPackageNodes(t *testing.T) {
	rootNodes := func(ids ...string) map[string]struct{} {
		m := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			m[id] = struct{}{}
		}
		return m
	}
	nodes := func(ids ...string) []*xrayUtils.GraphNode {
		var n []*xrayUtils.GraphNode
		for _, id := range ids {
			n = append(n, &xrayUtils.GraphNode{Id: id})
		}
		return n
	}

	// Single root (e.g. npm/pip): FlatTree.Nodes includes the root's own self-entry
	// alongside its dependencies — that self-entry must be excluded from the count.
	assert.Equal(t, 2, countPackageNodes(
		rootNodes("root"), nodes("root", "dep-a", "dep-b")))

	// Multiple roots (e.g. multiple --working-dirs): every root self-entry present
	// in the flat graph must be excluded, not just the first.
	assert.Equal(t, 2, countPackageNodes(
		rootNodes("root-a", "root-b"), nodes("root-a", "dep-a", "root-b", "dep-b")))

	// Hugging Face: BuildDependencyTree never adds a root self-entry, so nothing
	// should be subtracted — a single-dependency project must not undercount to 0.
	assert.Equal(t, 1, countPackageNodes(
		rootNodes("huggingface-project"), nodes("huggingfaceml://org/model:main")))

	assert.Equal(t, 0, countPackageNodes(rootNodes("root"), nil))
}

func Test_convertResultsToSummary_SkipsWarningsOnly(t *testing.T) {
	results := map[string]*CurationReport{
		"pip-project":         {packagesStatus: []*PackageStatus{{PackageName: "requests"}}, totalNumberOfPackages: 1},
		hfUnresolvedReportKey: {warnings: []string{"unresolved HF ref"}, huggingFaceReport: true},
	}
	summary := convertResultsToSummary(results)
	require.Len(t, summary.Scans, 1)
	assert.Equal(t, "pip-project", summary.Scans[0].Target)
}

// Test_convertResultsToSummary_RecordsAllUnresolvedHFReport: an all-unresolved hfPartial
// report must still be recorded, not dropped like the true "not attempted" placeholder.
func Test_convertResultsToSummary_RecordsAllUnresolvedHFReport(t *testing.T) {
	results := map[string]*CurationReport{
		"hf-project": {totalNumberOfPackages: 0, hfPartial: true, warnings: []string{"2 model reference(s)... HTTP 404"}},
	}
	summary := convertResultsToSummary(results)
	require.Len(t, summary.Scans, 1)
	assert.Equal(t, "hf-project", summary.Scans[0].Target)
	assert.Equal(t, 0, summary.Scans[0].CuratedPackages.PackageCount)
	assert.True(t, summary.Scans[0].CuratedPackages.IsPartial)
	assert.Equal(t, "hf_unresolved", summary.Scans[0].CuratedPackages.PartialReason)
}

// PackageCount must reflect remediation-needed rows, not the raw row count including "not evaluated" ones.
func Test_convertResultsToSummary_NpmLogPartialPackageCountExcludesNotEvaluated(t *testing.T) {
	results := map[string]*CurationReport{
		"npm-project": {
			packagesStatus: []*PackageStatus{
				{PackageName: "blocked-a", Action: blocked},
				{PackageName: "blocked-b", Action: blocked},
				{PackageName: "git-dep", Action: notEvaluated},
			},
			totalNumberOfPackages: 3,
			isPartial:             true,
			npmLogPartial:         true,
		},
	}
	summary := convertResultsToSummary(results)
	require.Len(t, summary.Scans, 1)
	assert.Equal(t, 2, summary.Scans[0].CuratedPackages.PackageCount,
		"PackageCount must count only rows needing remediation, not the not-evaluated row")
}

// An advisory-only npm-log-fallback report must still be recorded in the summary, like hfPartial already is.
func Test_convertResultsToSummary_RecordsAdvisoryOnlyNpmLogPartialReport(t *testing.T) {
	results := map[string]*CurationReport{
		"npm-project": {
			totalNumberOfPackages: 0,
			isPartial:             true,
			npmLogPartial:         true,
			warnings:              []string{"lodash@99.99.99 could not be resolved"},
		},
	}
	summary := convertResultsToSummary(results)
	require.Len(t, summary.Scans, 1)
	assert.Equal(t, "npm-project", summary.Scans[0].Target)
	assert.True(t, summary.Scans[0].CuratedPackages.IsPartial)
	assert.Equal(t, "npm_log_fallback", summary.Scans[0].CuratedPackages.PartialReason)
}

func Test_doCurateAudit_ExplicitHuggingFaceRequiresHFEndpoint(t *testing.T) {
	cleanUpFlags := setCurationFlagsForTest(t)
	defer cleanUpFlags()

	// Use a mock server so server resolution succeeds; the HF_ENDPOINT error then
	// fires naturally from getHuggingFaceRepositoryConfig → repoFromHFEndpoint.
	mockServer, serverConfig := hfMockServer(t, map[string]bool{}, map[string]bool{}, "hf-repo")
	defer mockServer.Close()

	tempHomeDir, cleanUpHome := createHFTestHome(t, serverConfig)
	defer cleanUpHome()
	callbackHomeDir := clienttestutils.SetEnvWithCallbackAndAssert(t, coreutils.HomeDir, tempHomeDir)
	defer callbackHomeDir()

	t.Setenv("HF_ENDPOINT", "")
	ca := NewCurationAuditCommand()
	ca.SetServerDetails(serverConfig)
	ca.SetIsCurationCmd(true)
	ca.SetInsecureTls(true)
	ca.SetHuggingFaceModel("org/model:main")
	results := map[string]*CurationReport{}
	err := ca.doCurateAudit(results)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HF_ENDPOINT")
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
							PackageCount:  1,
							IsPartial:     true,
							PartialReason: "cvs_fallback",
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

// TestFetchNodeStatus_HFExplicit404ReturnsError verifies an unresolvable explicit
// --hugging-face-model (HTTP 404) is a hard error, not a silently-skipped node.
func TestFetchNodeStatus_HFExplicit404ReturnsError(t *testing.T) {
	serverMock, _, rtManager := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer serverMock.Close()

	rtAuth := rtManager.GetConfig().GetServiceDetails()
	root := &xrayUtils.GraphNode{Id: "huggingfaceml://root"}
	root.Nodes = append(root.Nodes, &xrayUtils.GraphNode{Id: "huggingfaceml://org/nonexistent-model:main"})

	analyzer := treeAnalyzer{
		rtManager:            rtManager,
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
		rtAuth:               rtAuth,
		httpClientDetails:    rtAuth.CreateHttpClientDetails(),
		url:                  rtAuth.GetUrl(),
		repo:                 "hf-repo",
		tech:                 techutils.HuggingFaceML,
		hfExplicitModel:      true,
	}

	packagesStatusMap := sync.Map{}
	rootNodes := map[string]struct{}{root.Id: {}}
	err := analyzer.fetchNodesStatus(root, &packagesStatusMap, rootNodes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "org/nonexistent-model")
	assert.Contains(t, err.Error(), "404")
	assert.Empty(t, analyzer.hfUnresolvedNodes, "explicit mode must error, not silently record as unresolved")
}

// TestFetchNodeStatus_HFAutoDiscovery404RecordsUnresolvedNotError verifies an
// unresolvable auto-discovered reference (HTTP 404) is recorded as a warning,
// not a hard error.
func TestFetchNodeStatus_HFAutoDiscovery404RecordsUnresolvedNotError(t *testing.T) {
	serverMock, _, rtManager := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer serverMock.Close()

	rtAuth := rtManager.GetConfig().GetServiceDetails()
	root := &xrayUtils.GraphNode{Id: "huggingfaceml://root"}
	root.Nodes = append(root.Nodes, &xrayUtils.GraphNode{Id: "huggingfaceml://org/nonexistent-model:main"})

	analyzer := treeAnalyzer{
		rtManager:            rtManager,
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
		rtAuth:               rtAuth,
		httpClientDetails:    rtAuth.CreateHttpClientDetails(),
		url:                  rtAuth.GetUrl(),
		repo:                 "hf-repo",
		tech:                 techutils.HuggingFaceML,
		hfExplicitModel:      false,
	}

	packagesStatusMap := sync.Map{}
	rootNodes := map[string]struct{}{root.Id: {}}
	err := analyzer.fetchNodesStatus(root, &packagesStatusMap, rootNodes)
	require.NoError(t, err)
	require.Len(t, analyzer.hfUnresolvedNodes, 1)
	assert.Equal(t, "org/nonexistent-model:main", analyzer.hfUnresolvedNodes[0])
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
			serverMock, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(tt.respBody))
			})
			defer serverMock.Close()

			// Poetry (like Pip/Pipenv) routes through sendBoundedRequest, which requires a
			// zero-retry client — mirrors the production boundedRedirectManager construction.
			rtManager, err := rtUtils.CreateServiceManager(serverDetails, 0, 0, false)
			require.NoError(t, err)
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

	serverMock, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
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

	// Pip (like Poetry/Pipenv) routes through sendBoundedRequest, which requires a
	// zero-retry client — mirrors the production boundedRedirectManager construction.
	rtManager, err := rtUtils.CreateServiceManager(serverDetails, 0, 0, false)
	require.NoError(t, err)
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

// TestFetchCvsBlockedStatusPoetry verifies that the CVS fallback works for a
// poetry-pinned package: wrapPoetryCurationErr produces a *CvsBlockedError
// and fetchCvsBlockedStatus recovers the policy from the 403 probe, with the
// package type set to "poetry".
func TestFetchCvsBlockedStatusPoetry(t *testing.T) {
	const (
		repo            = "test-poetry-repo"
		blockedPkg      = "telnyx"
		blockedVer      = "4.87.1"
		expectedPolicy  = "immature-30"
		expectedCond    = "Package version is immature (strict)"
		expectedExpl    = "Package version is 5 days old"
		expectedRec     = "Use an older version or wait until this version is no longer immature"
		whlRelativePath = "packages/te/ln/telnyx-4.87.1-py3-none-any.whl"
	)

	blockMsg := fmt.Sprintf(
		"Package %s:%s download was blocked by JFrog Packages Curation service due to the following policies violated {%s, %s, %s, %s}.",
		blockedPkg, blockedVer, expectedPolicy, expectedCond, expectedExpl, expectedRec,
	)
	blockResponse := fmt.Sprintf(`{"errors":[{"status":403,"message":%q}]}`, blockMsg)
	versionMetaJSON := fmt.Sprintf(`{"urls":[{"packagetype":"bdist_wheel","url":"../../%s"}]}`, whlRelativePath)

	serverMock, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/pypi/"+blockedPkg+"/"+blockedVer+"/json"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(versionMetaJSON))
		case r.Method == http.MethodHead && strings.Contains(r.URL.Path, whlRelativePath):
			w.WriteHeader(http.StatusForbidden)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, whlRelativePath):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(blockResponse))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer serverMock.Close()

	// Poetry (like Pip/Pipenv) routes through sendBoundedRequest, which requires a
	// zero-retry client — mirrors the production boundedRedirectManager construction.
	rtManager, err := rtUtils.CreateServiceManager(serverDetails, 0, 0, false)
	require.NoError(t, err)
	rtAuth := rtManager.GetConfig().GetServiceDetails()
	httpClientDetails := rtAuth.CreateHttpClientDetails()

	analyzer := treeAnalyzer{
		rtManager:            rtManager,
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
		rtAuth:               rtAuth,
		httpClientDetails:    httpClientDetails,
		url:                  rtAuth.GetUrl(),
		repo:                 repo,
		tech:                 techutils.Poetry,
		parallelRequests:     1,
	}

	// Exact-pin PinnedRequirement produced by wrapPoetryCurationErr for a poetry project.
	pins := []python.PinnedRequirement{
		{Name: blockedPkg, Version: blockedVer, ParentName: blockedPkg, ParentVersion: blockedVer},
	}

	statuses := analyzer.fetchCvsBlockedStatus(pins)
	require.Len(t, statuses, 1)

	s := statuses[0]
	assert.Equal(t, blockedPkg, s.PackageName)
	assert.Equal(t, blockedVer, s.PackageVersion)
	assert.Equal(t, string(techutils.Poetry), s.PkgType, "package type must be poetry")
	require.Len(t, s.Policy, 1)
	assert.Equal(t, expectedPolicy, s.Policy[0].Policy)
	assert.Equal(t, expectedCond, s.Policy[0].Condition)
	assert.Equal(t, expectedExpl, s.Policy[0].Explanation)
	assert.Equal(t, expectedRec, s.Policy[0].Recommendation)
	assert.Equal(t, blocked, s.Action)
}

// TestFetchCvsBlockedStatusPoetryTransitive verifies the CVS fallback for a transitive
// blocker under poetry.
func TestFetchCvsBlockedStatusPoetryTransitive(t *testing.T) {
	const (
		repo            = "test-poetry-repo"
		blockedPkg      = "langchain-core"
		blockedVer      = "1.4.7"
		parentPkg       = "deepagents"
		parentVer       = "0.6.12"
		rangeSpec       = ">=1.4.0"
		expectedPolicy  = "immature-strict"
		expectedCond    = "Package version is immature (strict)"
		expectedExpl    = "Package version is 3 days old"
		expectedRec     = "Use an older version or wait until this version is no longer immature"
		whlRelativePath = "packages/ab/cd/langchain_core-1.4.7-py3-none-any.whl"
	)

	blockMsg := fmt.Sprintf(
		"Package %s:%s download was blocked by JFrog Packages Curation service due to the following policies violated {%s, %s, %s, %s}.",
		blockedPkg, blockedVer, expectedPolicy, expectedCond, expectedExpl, expectedRec,
	)
	blockResponse := fmt.Sprintf(`{"errors":[{"status":403,"message":%q}]}`, blockMsg)
	allVersionsJSON := `{"releases":{"1.4.0":[],"1.4.1":[],"1.4.5":[],"1.4.7":[]}}`
	versionMetaJSON := fmt.Sprintf(`{"urls":[{"packagetype":"bdist_wheel","url":"../../%s"}]}`, whlRelativePath)

	serverMock, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/pypi/"+blockedPkg+"/json"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(allVersionsJSON))
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/pypi/"+blockedPkg+"/"+blockedVer+"/json"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(versionMetaJSON))
		case r.Method == http.MethodHead && strings.Contains(r.URL.Path, whlRelativePath):
			w.WriteHeader(http.StatusForbidden)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, whlRelativePath):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(blockResponse))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer serverMock.Close()

	// Poetry (like Pip/Pipenv) routes through sendBoundedRequest, which requires a
	// zero-retry client — mirrors the production boundedRedirectManager construction.
	rtManager, err := rtUtils.CreateServiceManager(serverDetails, 0, 0, false)
	require.NoError(t, err)
	rtAuth := rtManager.GetConfig().GetServiceDetails()
	httpClientDetails := rtAuth.CreateHttpClientDetails()

	analyzer := treeAnalyzer{
		rtManager:            rtManager,
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
		rtAuth:               rtAuth,
		httpClientDetails:    httpClientDetails,
		url:                  rtAuth.GetUrl(),
		repo:                 repo,
		tech:                 techutils.Poetry,
		parallelRequests:     1,
	}

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

	// Parent (direct dep) attribution — must differ from the blocked package.
	assert.Equal(t, parentPkg, s.ParentName, "direct dependency name")
	assert.Equal(t, parentVer, s.ParentVersion, "direct dependency version")
	assert.NotEqual(t, s.PackageName, s.ParentName, "transitive blocker must show a different direct-dependency name")

	assert.Equal(t, string(techutils.Poetry), s.PkgType, "package type must be poetry")
	require.Len(t, s.Policy, 1)
	assert.Equal(t, expectedPolicy, s.Policy[0].Policy)
	assert.Equal(t, expectedCond, s.Policy[0].Condition)
	assert.Equal(t, expectedExpl, s.Policy[0].Explanation)
	assert.Equal(t, expectedRec, s.Policy[0].Recommendation)
	assert.Equal(t, blocked, s.Action)
}

// TestFetchCvsBlockedStatusNotInMetadataNotRendered verifies that a version absent from the metadata API is not rendered as a blocked row.
func TestFetchCvsBlockedStatusNotInMetadataNotRendered(t *testing.T) {
	const (
		repo = "test-pip-repo"
		pkg  = "telnyx"
		ver  = "4.87.1000" // not in the metadata API
	)

	serverMock, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/pypi/"+pkg+"/"+ver+"/json"):
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer serverMock.Close()

	// Pip (like Poetry/Pipenv) routes through sendBoundedRequest, which requires a
	// zero-retry client — mirrors the production boundedRedirectManager construction.
	rtManager, err := rtUtils.CreateServiceManager(serverDetails, 0, 0, false)
	require.NoError(t, err)
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

	serverMock, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
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

	// Pip (like Poetry/Pipenv) routes through sendBoundedRequest, which requires a
	// zero-retry client — mirrors the production boundedRedirectManager construction.
	rtManager, err := rtUtils.CreateServiceManager(serverDetails, 0, 0, false)
	require.NoError(t, err)
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

	serverMock, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
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

	// Pip (like Poetry/Pipenv) routes through sendBoundedRequest, which requires a
	// zero-retry client — mirrors the production boundedRedirectManager construction.
	rtManager, err := rtUtils.CreateServiceManager(serverDetails, 0, 0, false)
	require.NoError(t, err)
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

	serverMock, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
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

	// Pip (like Poetry/Pipenv) routes through sendBoundedRequest, which requires a
	// zero-retry client — mirrors the production boundedRedirectManager construction.
	rtManager, err := rtUtils.CreateServiceManager(serverDetails, 0, 0, false)
	require.NoError(t, err)
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

// TestRunCvsFallback_KeepsSeparateTableFromExistingReport verifies pip's CVS-fallback report
// gets its own distinct key (a second table) instead of overwriting or fusing into an existing
// report already recorded under the same directory-basename key (e.g. by HF auto-discovery).
func TestRunCvsFallback_KeepsSeparateTableFromExistingReport(t *testing.T) {
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

	orig := osGetwd
	osGetwd = func() (string, error) { return "/home/user/ml-project", nil }
	t.Cleanup(func() { osGetwd = orig })
	const key = "ml-project"

	// Pre-existing report under the same key, as HF auto-discovery would leave it.
	results := map[string]*CurationReport{
		key: {
			packagesStatus:    []*PackageStatus{{PackageName: "org/malicious-model", PackageVersion: "main", PkgType: "huggingfaceml"}},
			warnings:          []string{"Hugging Face: 1 model reference(s) could not be resolved"},
			huggingFaceReport: true,
			hfPartial:         true,
		},
	}

	cvsErr := &python.CvsBlockedError{
		Packages: []python.PinnedRequirement{
			{Name: blockedPkg, Version: blockedVer, ParentName: blockedPkg, ParentVersion: blockedVer},
		},
	}
	err := ca.runCvsFallback(cvsErr, techutils.Pip, results)
	require.NoError(t, err)

	require.Len(t, results, 2, "pip's fallback must land in a new table, leaving the existing HF report untouched")

	hfReport := results[key]
	require.NotNil(t, hfReport)
	assert.True(t, hfReport.huggingFaceReport)
	assert.True(t, hfReport.hfPartial)
	assert.Len(t, hfReport.packagesStatus, 1, "the pre-existing HF report must be unmodified")
	assert.Len(t, hfReport.warnings, 1)

	pipKey := uniqueReportKey(map[string]*CurationReport{key: hfReport}, key, techutils.Pip)
	pipReport := results[pipKey]
	require.NotNil(t, pipReport, "pip's report must be recorded under a disambiguated key, not merged into %q", key)
	assert.Len(t, pipReport.packagesStatus, 1)
	assert.True(t, pipReport.isPartial)
	assert.False(t, pipReport.huggingFaceReport, "pip's own report must not carry the HF marker")
}

// Feeds the mixed-crash.log fixture through the full runNpmLogFallback end to end.
func TestRunNpmLogFallback(t *testing.T) {
	const repo = "my-pnpm-remote"
	acceptsBlockMsg := "Package accepts:2.0.0 download was blocked by jfrog packages curation service due to the following policies violated " +
		"{cve-high, CVE with CVSS score of 9 or above, Package version contains a vulnerability, Upgrade to a fixed version}."
	acceptsBlockJSON := fmt.Sprintf(`{"errors":[{"status":403,"message":%q}]}`, acceptsBlockMsg)

	serverMock, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/accepts-2.0.0.tgz"):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(acceptsBlockJSON))
		case strings.Contains(r.URL.Path, "/lodash-99.99.99.tgz"):
			// Genuine ETARGET: plain 404, no curation signal.
			w.WriteHeader(http.StatusNotFound)
		case strings.Contains(r.URL.Path, "/express-5.2.1.tgz"), strings.Contains(r.URL.Path, "/typescript-5.3.3.tgz"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "/depd-"), strings.Contains(r.URL.Path, "/is-thirteen-"), strings.Contains(r.URL.Path, "/some-range-pkg-"):
			t.Errorf("unexpected HEAD-check for a whole-package-blocked/non-registry/unresolvable-range entry: %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
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

	projectDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "package.json"),
		[]byte(`{"name":"mypnpmproject-v11","version":"1.0.0"}`), 0644))
	orig := osGetwd
	osGetwd = func() (string, error) { return projectDir, nil }
	t.Cleanup(func() { osGetwd = orig })

	results := map[string]*CurationReport{}
	originalErr := errors.New("error while running 'npm install': exit status 1")
	logsDir := filepath.Join(TestDataDir, "curation", "npmlogs", "mixed-crash", "_logs")

	err := ca.runNpmLogFallback(logsDir, techutils.Npm, results, originalErr, false, 0)
	require.NoError(t, err)
	require.Len(t, results, 1)

	var report *CurationReport
	for _, r := range results {
		report = r
	}
	require.NotNil(t, report)
	assert.True(t, report.isPartial)
	assert.True(t, report.npmLogPartial)
	assert.Equal(t, originalErr.Error(), report.npmLogOriginalErr,
		"the real underlying npm error must be preserved, not just a generic curation-blamed message")

	byName := map[string]*PackageStatus{}
	for _, ps := range report.packagesStatus {
		byName[ps.PackageName] = ps
	}

	// Whole-package-blocked, transitive via express: "All versions blocked" and the
	// transitive-aware recommendation naming both packages.
	depd := byName["depd"]
	require.NotNil(t, depd, "depd should be reported as a whole-package block")
	assert.Equal(t, allVersionsBlockedText, depd.PackageVersion)
	assert.Equal(t, "express", depd.ParentName, "depd's direct-dependency attribution must walk to express, not stop at an intermediate parent")
	require.Len(t, depd.Policy, 1)
	assert.Contains(t, depd.Policy[0].Recommendation, "transitive dependency of express")

	// Resolved and blocked via the normal HEAD-check path (getBlockedPackageDetails,
	// unmodified) — full policy detail recovered from the 403 body.
	accepts := byName["accepts"]
	require.NotNil(t, accepts, "accepts should be reported as blocked via the standard HEAD-check")
	assert.Equal(t, "2.0.0", accepts.PackageVersion)
	require.Len(t, accepts.Policy, 1)
	assert.Equal(t, "cve-high", accepts.Policy[0].Policy)

	// Clean packages never appear as rows.
	assert.NotContains(t, byName, "express")
	assert.NotContains(t, byName, "typescript")

	// Git-URL, genuine ETARGET, and unresolvable range: never probed, never a row — advisory
	// warnings only, so none can be mistaken for a real block in the table/JSON output.
	assert.NotContains(t, byName, "is-thirteen")
	assert.NotContains(t, byName, "lodash")
	assert.NotContains(t, byName, "some-range-pkg")
	require.Len(t, report.warnings, 3)
	warningsText := strings.Join(report.warnings, "\n")
	assert.Contains(t, warningsText, "is-thirteen")
	assert.Contains(t, warningsText, "github:jonschlinkert/is-thirteen")
	assert.Contains(t, warningsText, "lodash@99.99.99")
	assert.Contains(t, warningsText, "not a curation policy block")
	assert.Contains(t, warningsText, "some-range-pkg")
	assert.Contains(t, warningsText, "^3.0.0")
}

// An ETARGET-confirmed-blocked package must not be stored under a key the graph lookup never finds.
func TestRunNpmLogFallback_ETARGETConfirmedBlockAppearsInReport(t *testing.T) {
	blockMsg := "Package pinned-blocked:9.9.9 download was blocked by jfrog packages curation service due to the following policies violated " +
		"{cve-high, CVE with CVSS score of 9 or above, Package version contains a vulnerability, Upgrade to a fixed version}."
	blockJSON := fmt.Sprintf(`{"errors":[{"status":403,"message":%q}]}`, blockMsg)

	serverMock, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/pinned-blocked-9.9.9.tgz") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(blockJSON))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer serverMock.Close()

	repoConfig := (&project.RepositoryConfig{}).SetTargetRepo("my-npm-remote").SetServerDetails(serverDetails)
	ca := &CurationAuditCommand{
		PackageManagerConfig: repoConfig,
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
	}

	logDir := t.TempDir()
	logsDir := filepath.Join(logDir, "_logs")
	require.NoError(t, os.MkdirAll(logsDir, 0755))
	logContent := "0 verbose cli node npm\n" +
		"46 silly placeDep ROOT pinned-blocked@ OK for: myproj@1.0.0 want: 9.9.9\n"
	require.NoError(t, os.WriteFile(filepath.Join(logsDir, "2026-01-01T00_00_00_000Z-debug-0.log"), []byte(logContent), 0644))

	projectDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{"name":"myproj","version":"1.0.0"}`), 0644))
	orig := osGetwd
	osGetwd = func() (string, error) { return projectDir, nil }
	t.Cleanup(func() { osGetwd = orig })

	results := map[string]*CurationReport{}
	originalErr := errors.New("error while running 'npm install': exit status 1")

	err := ca.runNpmLogFallback(logsDir, techutils.Npm, results, originalErr, false, 0)
	require.NoError(t, err)
	require.Len(t, results, 1)

	var report *CurationReport
	for _, r := range results {
		report = r
	}
	require.Len(t, report.packagesStatus, 1, "the confirmed-blocked ETARGET package must appear as a row")
	assert.Equal(t, "pinned-blocked", report.packagesStatus[0].PackageName)
	assert.Equal(t, "9.9.9", report.packagesStatus[0].PackageVersion)
}

// An advisory-only entry must not claim the shared dedup key and skip a same-name probeable entry.
func TestRunNpmLogFallback_SeenKeysDoesNotSkipCrossCategoryEntry(t *testing.T) {
	blockMsg := "Package widget:2.0.0 download was blocked by jfrog packages curation service due to the following policies violated " +
		"{cve-high, CVE with CVSS score of 9 or above, Package version contains a vulnerability, Upgrade to a fixed version}."
	blockJSON := fmt.Sprintf(`{"errors":[{"status":403,"message":%q}]}`, blockMsg)

	var widgetTarballHits int
	serverMock, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/widget-2.0.0.tgz") {
			widgetTarballHits++
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(blockJSON))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer serverMock.Close()

	repoConfig := (&project.RepositoryConfig{}).SetTargetRepo("my-npm-remote").SetServerDetails(serverDetails)
	ca := &CurationAuditCommand{
		PackageManagerConfig: repoConfig,
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
	}

	logDir := t.TempDir()
	logsDir := filepath.Join(logDir, "_logs")
	require.NoError(t, os.MkdirAll(logsDir, 0755))
	// "widget" appears twice: once via an unresolvable range (advisory-only, no probe),
	// once via a bare, exact, genuinely blocked version (ETARGET, must be probed).
	logContent := "0 verbose cli node npm\n" +
		"44 silly placeDep ROOT dep-a@1.0.0 OK for: myproj@1.0.0 want: ^1.0.0\n" +
		"45 silly placeDep ROOT dep-b@1.0.0 OK for: myproj@1.0.0 want: ^1.0.0\n" +
		"46 silly placeDep node_modules/dep-a widget@ OK for: dep-a@1.0.0 want: ^1.0.0\n" +
		"47 silly placeDep node_modules/dep-b widget@ OK for: dep-b@1.0.0 want: 2.0.0\n"
	require.NoError(t, os.WriteFile(filepath.Join(logsDir, "2026-01-01T00_00_00_000Z-debug-0.log"), []byte(logContent), 0644))

	projectDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{"name":"myproj","version":"1.0.0"}`), 0644))
	orig := osGetwd
	osGetwd = func() (string, error) { return projectDir, nil }
	t.Cleanup(func() { osGetwd = orig })

	results := map[string]*CurationReport{}
	originalErr := errors.New("error while running 'npm install': exit status 1")

	err := ca.runNpmLogFallback(logsDir, techutils.Npm, results, originalErr, false, 0)
	require.NoError(t, err)
	require.Len(t, results, 1)

	var report *CurationReport
	for _, r := range results {
		report = r
	}
	assert.Equal(t, 1, widgetTarballHits, "the ETARGET occurrence's own HTTP probe must run exactly once, not be skipped by the unresolvable-range occurrence's dedup entry")
	require.NotEmpty(t, report.packagesStatus, "widget's confirmed block must surface as a row (once per parent edge that pulls it in)")
	for _, ps := range report.packagesStatus {
		assert.Equal(t, "widget", ps.PackageName)
		assert.Equal(t, "2.0.0", ps.PackageVersion)
	}
}

// Two ETARGET entries for the same name but different pinned specifiers must both surface, not collide.
func TestRunNpmLogFallback_SameNameDifferentSpecifierETARGETEntriesDoNotCollide(t *testing.T) {
	blockJSON := func(name, version string) string {
		msg := fmt.Sprintf("Package %s:%s download was blocked by jfrog packages curation service due to the following policies violated "+
			"{cve-high, CVE with CVSS score of 9 or above, Package version contains a vulnerability, Upgrade to a fixed version}.", name, version)
		return fmt.Sprintf(`{"errors":[{"status":403,"message":%q}]}`, msg)
	}

	serverMock, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/widget-2.0.0.tgz"):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(blockJSON("widget", "2.0.0")))
		case strings.Contains(r.URL.Path, "/widget-3.0.0.tgz"):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(blockJSON("widget", "3.0.0")))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer serverMock.Close()

	repoConfig := (&project.RepositoryConfig{}).SetTargetRepo("my-npm-remote").SetServerDetails(serverDetails)
	ca := &CurationAuditCommand{
		PackageManagerConfig: repoConfig,
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
	}

	logDir := t.TempDir()
	logsDir := filepath.Join(logDir, "_logs")
	require.NoError(t, os.MkdirAll(logsDir, 0755))
	// "widget" pinned at two different blocked versions by two different parents.
	logContent := "0 verbose cli node npm\n" +
		"44 silly placeDep ROOT dep-a@1.0.0 OK for: myproj@1.0.0 want: ^1.0.0\n" +
		"45 silly placeDep ROOT dep-b@1.0.0 OK for: myproj@1.0.0 want: ^1.0.0\n" +
		"46 silly placeDep node_modules/dep-a widget@ OK for: dep-a@1.0.0 want: 2.0.0\n" +
		"47 silly placeDep node_modules/dep-b widget@ OK for: dep-b@1.0.0 want: 3.0.0\n"
	require.NoError(t, os.WriteFile(filepath.Join(logsDir, "2026-01-01T00_00_00_000Z-debug-0.log"), []byte(logContent), 0644))

	projectDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{"name":"myproj","version":"1.0.0"}`), 0644))
	orig := osGetwd
	osGetwd = func() (string, error) { return projectDir, nil }
	t.Cleanup(func() { osGetwd = orig })

	results := map[string]*CurationReport{}
	originalErr := errors.New("error while running 'npm install': exit status 1")

	err := ca.runNpmLogFallback(logsDir, techutils.Npm, results, originalErr, false, 0)
	require.NoError(t, err)
	require.Len(t, results, 1)

	var report *CurationReport
	for _, r := range results {
		report = r
	}
	versionsSeen := map[string]bool{}
	for _, ps := range report.packagesStatus {
		assert.Equal(t, "widget", ps.PackageName)
		versionsSeen[ps.PackageVersion] = true
	}
	assert.True(t, versionsSeen["2.0.0"], "dep-a's genuinely blocked 2.0.0 must appear, not be overwritten by 3.0.0")
	assert.True(t, versionsSeen["3.0.0"], "dep-b's genuinely blocked 3.0.0 must appear, not be lost to the shared blank-version key")
}

// When package.json can't be read, the root identity must be recovered from the log itself.
func TestRunNpmLogFallback_MissingPackageJsonStillRecoversReport(t *testing.T) {
	serverMock, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected HEAD-check for a whole-package-blocked entry: %s", r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer serverMock.Close()

	repoConfig := (&project.RepositoryConfig{}).SetTargetRepo("my-npm-remote").SetServerDetails(serverDetails)
	ca := &CurationAuditCommand{
		PackageManagerConfig: repoConfig,
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
	}

	logDir := t.TempDir()
	logsDir := filepath.Join(logDir, "_logs")
	require.NoError(t, os.MkdirAll(logsDir, 0755))
	// Root-level entry carries the real project identity ("realproj@9.9.9"); the working
	// directory's basename below is deliberately something else.
	logContent := "0 verbose cli node npm\n" +
		"43 notice All versions blocked - {policy:blocks open ssf,condition:open ssf}\n" +
		"44 http fetch GET 403 https://z0test.jfrogdev.org/artifactory/api/npm/my-npm-remote/blockedpkg 100ms (cache skip)\n" +
		"45 silly placeDep ROOT blockedpkg@ OK for: realproj@9.9.9 want: ^1.0.0\n"
	require.NoError(t, os.WriteFile(filepath.Join(logsDir, "2026-01-01T00_00_00_000Z-debug-0.log"), []byte(logContent), 0644))

	// No package.json written — readNpmProjectNameVersion fails.
	projectDir := filepath.Join(t.TempDir(), "unrelated-dir-name")
	require.NoError(t, os.MkdirAll(projectDir, 0755))
	orig := osGetwd
	osGetwd = func() (string, error) { return projectDir, nil }
	t.Cleanup(func() { osGetwd = orig })

	results := map[string]*CurationReport{}
	originalErr := errors.New("error while running 'npm install': exit status 1")

	err := ca.runNpmLogFallback(logsDir, techutils.Npm, results, originalErr, false, 0)
	require.NoError(t, err)
	require.Len(t, results, 1)

	var report *CurationReport
	for _, r := range results {
		report = r
	}
	require.NotEmpty(t, report.packagesStatus, "blockedpkg must still surface as a row even when package.json can't be read")
	assert.Equal(t, "blockedpkg", report.packagesStatus[0].PackageName)
	assert.True(t, directDepNamesContains(report, "blockedpkg"), "blockedpkg is a direct dependency of the real (log-recovered) root, so its recommendation must say so, not treat it as transitive")
}

// directDepNamesContains checks pkgName's recommendation uses the direct, not transitive, wording.
func directDepNamesContains(report *CurationReport, pkgName string) bool {
	for _, ps := range report.packagesStatus {
		if ps.PackageName != pkgName {
			continue
		}
		for _, p := range ps.Policy {
			if strings.Contains(p.Recommendation, "Remove this package from your project and replace with an alternate package") {
				return true
			}
		}
	}
	return false
}

// A key-construction failure must not silently vanish the package from the report the same way
// as ordinary dedup — it must surface as a warning, same as a probe failure.
func TestRunNpmLogFallback_KeyErrSurfacesAsWarningNotSilentDrop(t *testing.T) {
	serverMock, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer serverMock.Close()

	repoConfig := (&project.RepositoryConfig{}).SetTargetRepo("my-npm-remote").SetServerDetails(serverDetails)
	ca := &CurationAuditCommand{
		PackageManagerConfig: repoConfig,
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
	}

	logDir := t.TempDir()
	logsDir := filepath.Join(logDir, "_logs")
	require.NoError(t, os.MkdirAll(logsDir, 0755))
	// "widget-abc123"@0.0.0 matches isYarnBerryWorkspaceMember's pattern (name ends in
	// "-" + 6 hex chars, version "0.0.0"), so getNpmNameScopeAndVersion returns zero URLs
	// and npmPackageKey genuinely fails to derive a key — a real trigger, not a mock.
	logContent := "0 verbose cli node npm\n" +
		"10 silly placeDep ROOT widget-abc123@0.0.0 OK for: myproj@1.0.0 want: ^0.0.0\n"
	require.NoError(t, os.WriteFile(filepath.Join(logsDir, "2026-01-01T00_00_00_000Z-debug-0.log"), []byte(logContent), 0644))

	projectDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{"name":"myproj","version":"1.0.0"}`), 0644))
	orig := osGetwd
	osGetwd = func() (string, error) { return projectDir, nil }
	t.Cleanup(func() { osGetwd = orig })

	results := map[string]*CurationReport{}
	originalErr := errors.New("error while running 'npm install': exit status 1")

	err := ca.runNpmLogFallback(logsDir, techutils.Npm, results, originalErr, false, 0)
	require.NoError(t, err)
	require.Len(t, results, 1)

	var report *CurationReport
	for _, r := range results {
		report = r
	}
	for _, ps := range report.packagesStatus {
		assert.NotEqual(t, "widget-abc123", ps.PackageName, "a package whose key couldn't be derived must not be reported as confirmed clean or blocked")
	}
	require.NotEmpty(t, report.warnings, "a key-construction failure must surface as a warning, not vanish silently")
	assert.Contains(t, strings.Join(report.warnings, "\n"), "widget-abc123")
}

// A probe failure (network/5xx) for a resolved entry must not be silently treated as "clean" — it must surface as a warning.
func TestRunNpmLogFallback_ProbeErrorSurfacesAsWarningNotClean(t *testing.T) {
	serverMock, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/flaky-pkg-1.0.0.tgz") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer serverMock.Close()

	repoConfig := (&project.RepositoryConfig{}).SetTargetRepo("my-npm-remote").SetServerDetails(serverDetails)
	ca := &CurationAuditCommand{
		PackageManagerConfig: repoConfig,
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
	}

	logDir := t.TempDir()
	logsDir := filepath.Join(logDir, "_logs")
	require.NoError(t, os.MkdirAll(logsDir, 0755))
	logContent := "0 verbose cli node npm\n" +
		"10 silly placeDep ROOT flaky-pkg@1.0.0 OK for: myproj@1.0.0 want: ^1.0.0\n"
	require.NoError(t, os.WriteFile(filepath.Join(logsDir, "2026-01-01T00_00_00_000Z-debug-0.log"), []byte(logContent), 0644))

	projectDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{"name":"myproj","version":"1.0.0"}`), 0644))
	orig := osGetwd
	osGetwd = func() (string, error) { return projectDir, nil }
	t.Cleanup(func() { osGetwd = orig })

	results := map[string]*CurationReport{}
	originalErr := errors.New("error while running 'npm install': exit status 1")

	err := ca.runNpmLogFallback(logsDir, techutils.Npm, results, originalErr, false, 0)
	require.NoError(t, err)
	require.Len(t, results, 1)

	var report *CurationReport
	for _, r := range results {
		report = r
	}
	for _, ps := range report.packagesStatus {
		assert.NotEqual(t, "flaky-pkg", ps.PackageName, "a package whose probe failed must not be reported as confirmed clean or blocked")
	}
	require.NotEmpty(t, report.warnings, "a probe failure must surface as a warning, not vanish silently")
	assert.Contains(t, strings.Join(report.warnings, "\n"), "flaky-pkg")
}

// A blocked name shared by a direct edge and a transitive edge must get the recommendation for each edge, not one shared answer.
func TestRunNpmLogFallback_RecommendationIsPerEdgeNotPerName(t *testing.T) {
	serverMock, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer serverMock.Close()

	repoConfig := (&project.RepositoryConfig{}).SetTargetRepo("my-npm-remote").SetServerDetails(serverDetails)
	ca := &CurationAuditCommand{
		PackageManagerConfig: repoConfig,
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
	}

	logDir := t.TempDir()
	logsDir := filepath.Join(logDir, "_logs")
	require.NoError(t, os.MkdirAll(logsDir, 0755))
	// "blocked-name" is both a direct dep of myproj and a transitive dep of "otherdirect".
	logContent := "0 verbose cli node npm\n" +
		"10 silly placeDep ROOT blocked-name@ OK for: myproj@1.0.0 want: ^1.0.0\n" +
		"11 silly placeDep ROOT otherdirect@1.0.0 OK for: myproj@1.0.0 want: ^1.0.0\n" +
		"12 silly placeDep node_modules/otherdirect blocked-name@ OK for: otherdirect@1.0.0 want: ^2.0.0\n" +
		"40 notice All versions blocked - {policy:blocks open ssf,condition:open ssf}\n" +
		"41 http fetch GET 403 https://z0test.jfrogdev.org/artifactory/api/npm/my-npm-remote/blocked-name 50ms (cache skip)\n"
	require.NoError(t, os.WriteFile(filepath.Join(logsDir, "2026-01-01T00_00_00_000Z-debug-0.log"), []byte(logContent), 0644))

	projectDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{"name":"myproj","version":"1.0.0"}`), 0644))
	orig := osGetwd
	osGetwd = func() (string, error) { return projectDir, nil }
	t.Cleanup(func() { osGetwd = orig })

	results := map[string]*CurationReport{}
	originalErr := errors.New("error while running 'npm install': exit status 1")

	err := ca.runNpmLogFallback(logsDir, techutils.Npm, results, originalErr, false, 0)
	require.NoError(t, err)
	require.Len(t, results, 1)

	var report *CurationReport
	for _, r := range results {
		report = r
	}
	var directRow, transitiveRow *PackageStatus
	for _, ps := range report.packagesStatus {
		if ps.PackageName != "blocked-name" {
			continue
		}
		switch {
		case ps.DepRelation == directRelation:
			directRow = ps
		case ps.DepRelation == indirectRelation && ps.ParentName == "otherdirect":
			transitiveRow = ps
		}
	}
	require.NotNil(t, directRow, "blocked-name must appear as a direct edge")
	require.NotNil(t, transitiveRow, "blocked-name must appear as a transitive edge under otherdirect")

	require.Len(t, directRow.Policy, 1)
	assert.Equal(t, "Remove this package from your project and replace with an alternate package", directRow.Policy[0].Recommendation)

	require.Len(t, transitiveRow.Policy, 1)
	assert.Contains(t, transitiveRow.Policy[0].Recommendation, "transitive dependency of otherdirect",
		"the transitive edge must not get the direct-removal recommendation just because the same name is also a direct dependency elsewhere")
}

// The ETARGET probe path has the same probe-error-swallowing bug the npmEntryResolved case
// had (Fix #1) — a transient probe failure must surface as a warning, and must not make the
// whole report vanish (return originalErr) when it's the only recoverable entry.
func TestRunNpmLogFallback_ETARGETProbeErrorSurfacesAsWarningNotDiscarded(t *testing.T) {
	serverMock, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer serverMock.Close()

	repoConfig := (&project.RepositoryConfig{}).SetTargetRepo("my-npm-remote").SetServerDetails(serverDetails)
	ca := &CurationAuditCommand{
		PackageManagerConfig: repoConfig,
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
	}

	logDir := t.TempDir()
	logsDir := filepath.Join(logDir, "_logs")
	require.NoError(t, os.MkdirAll(logsDir, 0755))
	logContent := "0 verbose cli node npm\n" +
		"10 silly placeDep ROOT flaky-etarget@ OK for: myproj@1.0.0 want: 9.9.9\n"
	require.NoError(t, os.WriteFile(filepath.Join(logsDir, "2026-01-01T00_00_00_000Z-debug-0.log"), []byte(logContent), 0644))

	projectDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{"name":"myproj","version":"1.0.0"}`), 0644))
	orig := osGetwd
	osGetwd = func() (string, error) { return projectDir, nil }
	t.Cleanup(func() { osGetwd = orig })

	results := map[string]*CurationReport{}
	originalErr := errors.New("error while running 'npm install': exit status 1")

	err := ca.runNpmLogFallback(logsDir, techutils.Npm, results, originalErr, false, 0)
	require.NoError(t, err, "a probe failure must not make the whole recovered report vanish")
	require.Len(t, results, 1)

	var report *CurationReport
	for _, r := range results {
		report = r
	}
	require.NotEmpty(t, report.warnings, "a probe failure must surface as a warning, not vanish silently")
	assert.Contains(t, strings.Join(report.warnings, "\n"), "flaky-etarget")
}

// If the log has no placeDep lines at all, the original error is returned unchanged.
func TestRunNpmLogFallback_NoRecoverableEntries(t *testing.T) {
	ca := &CurationAuditCommand{
		PackageManagerConfig: (&project.RepositoryConfig{}).SetTargetRepo("repo"),
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
	}
	results := map[string]*CurationReport{}
	originalErr := errors.New("npm install failed before any resolution")

	err := ca.runNpmLogFallback(t.TempDir(), techutils.Npm, results, originalErr, false, 0)
	assert.Equal(t, originalErr, err)
	assert.Empty(t, results)
}

// A stale log left over from an earlier, unrelated run (e.g. a shared CI cache) must never be
// mistaken for this crash's own log — if npm never wrote a NEW log for this invocation (e.g. it
// failed before writing anything at all, missing binary, bad package.json), the fallback must
// return originalErr unchanged rather than fabricate a report from someone else's old log.
func TestRunNpmLogFallback_StaleLogPredatingBaselineIsIgnored(t *testing.T) {
	logsDir := t.TempDir()
	staleLogContent := "0 verbose cli node npm\n" +
		"10 silly placeDep ROOT stale-pkg@1.0.0 OK for: otherproj@1.0.0 want: ^1.0.0\n"
	staleLogPath := filepath.Join(logsDir, "2026-01-01T00_00_00_000Z-debug-0.log")
	require.NoError(t, os.WriteFile(staleLogPath, []byte(staleLogContent), 0644))

	// The baseline is captured AFTER the stale log already exists — exactly like the real
	// eager-lookup snapshot taken right before an install that then fails without logging.
	baselineKey, err := npmDebugLogNewestKey(logsDir)
	require.NoError(t, err)
	require.NotZero(t, baselineKey)

	ca := &CurationAuditCommand{
		PackageManagerConfig: (&project.RepositoryConfig{}).SetTargetRepo("repo"),
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
	}
	results := map[string]*CurationReport{}
	originalErr := errors.New("npm: command not found")

	gotErr := ca.runNpmLogFallback(logsDir, techutils.Npm, results, originalErr, false, baselineKey)
	assert.Equal(t, originalErr, gotErr, "no log newer than the baseline exists, so the original error must pass through unchanged")
	assert.Empty(t, results, "must not fabricate a report from a stale pre-existing log")

	// The stale log itself must survive untouched — it's not ours to touch.
	_, statErr := os.Stat(staleLogPath)
	assert.NoError(t, statErr)
}

// When logs-max was 0, only the specific log file read is removed — not the whole directory.
func TestRunNpmLogFallback_CleansUpLogWhenLogsMaxWasZero(t *testing.T) {
	cacheDir := t.TempDir()
	logsDir := filepath.Join(cacheDir, "_logs")
	require.NoError(t, os.MkdirAll(logsDir, 0755))
	logPath := filepath.Join(logsDir, "2026-01-01T00_00_00_000Z-debug-0.log")
	require.NoError(t, os.WriteFile(logPath, []byte("0 verbose cli npm\n"), 0644))
	otherPath := filepath.Join(logsDir, "unrelated-file.txt")
	require.NoError(t, os.WriteFile(otherPath, []byte("leave me alone\n"), 0644))

	ca := &CurationAuditCommand{
		PackageManagerConfig: (&project.RepositoryConfig{}).SetTargetRepo("repo"),
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
	}
	results := map[string]*CurationReport{}
	originalErr := errors.New("npm install failed before any resolution")

	// No placeDep lines in this fixture, so this hits the "nothing recoverable" early
	// return — cleanup must still fire on that path, not only on a fully successful one.
	err := ca.runNpmLogFallback(logsDir, techutils.Npm, results, originalErr, true, 0)
	assert.Equal(t, originalErr, err)

	_, statErr := os.Stat(logPath)
	assert.True(t, os.IsNotExist(statErr), "the log file itself should have been removed")
	_, otherStatErr := os.Stat(otherPath)
	assert.NoError(t, otherStatErr, "an unrelated file in the same directory must not be touched")
}

// The install-succeeded path forces the same --logs-max=10 override as the failure path, so it
// must clean up the resulting debug log the same way when the user had configured logs-max=0.
func TestCleanupForcedNpmDebugLog_RemovesLogWhenLogsMaxWasZero(t *testing.T) {
	cacheDir := t.TempDir()
	logsDir := filepath.Join(cacheDir, "_logs")
	require.NoError(t, os.MkdirAll(logsDir, 0755))
	logPath := filepath.Join(logsDir, "2026-01-01T00_00_00_000Z-debug-0.log")
	require.NoError(t, os.WriteFile(logPath, []byte("0 verbose cli npm\n"), 0644))

	cleanupForcedNpmDebugLog(logsDir, true, 0)

	_, statErr := os.Stat(logPath)
	assert.True(t, os.IsNotExist(statErr), "the forced debug log must be removed when logs-max was actually 0")
}

// When the user hadn't set logs-max=0 themselves, npm's own rotation already manages the log —
// nothing forced it into existence, so nothing should be removed here.
func TestCleanupForcedNpmDebugLog_LeavesLogWhenLogsMaxWasNotZero(t *testing.T) {
	cacheDir := t.TempDir()
	logsDir := filepath.Join(cacheDir, "_logs")
	require.NoError(t, os.MkdirAll(logsDir, 0755))
	logPath := filepath.Join(logsDir, "2026-01-01T00_00_00_000Z-debug-0.log")
	require.NoError(t, os.WriteFile(logPath, []byte("0 verbose cli npm\n"), 0644))

	cleanupForcedNpmDebugLog(logsDir, false, 0)

	_, statErr := os.Stat(logPath)
	assert.NoError(t, statErr, "must not remove a log npm would have written anyway")
}

// A transient npm-config-lookup failure must not abort an install that would've succeeded.
func TestDoCurationAudit_NpmConfigLookupFailureDoesNotAbortSuccessfulInstall(t *testing.T) {
	var fixture testCase
	for _, tt := range getTestCasesForDoCurationAudit() {
		if tt.name == "npm tree - two blocked package " {
			fixture = tt
			break
		}
	}
	require.NotEmpty(t, fixture.name, "expected fixture not found")

	basePathToTests, err := filepath.Abs(TestDataDir)
	require.NoError(t, err)
	cleanUpFlags := setCurationFlagsForTest(t)
	defer cleanUpFlags()

	runFixture := func(t *testing.T) (map[string]*CurationReport, error) {
		mockServer, config := curationServer(t, fixture.expectedBuildRequest, fixture.expectedRequest, fixture.requestToFail, fixture.requestToError, fixture.serveResources)
		defer mockServer.Close()
		cleanUp := createCurationTestEnv(t, basePathToTests, fixture, config)
		defer cleanUp()
		return createCurationCmdAndRun(fixture)
	}

	t.Run("baseline_succeeds_unmodified", func(t *testing.T) {
		t.Setenv("NPM_CONFIG_CACHE", t.TempDir())
		results, err := runFixture(t)
		require.NoError(t, err)
		assert.NotEmpty(t, results)
	})

	t.Run("forced_config_lookup_failure_must_not_abort", func(t *testing.T) {
		t.Setenv("NPM_CONFIG_CACHE", t.TempDir())
		orig := npmGetConfigValue
		npmGetConfigValue = func(string, string) (string, error) {
			return "", errors.New("simulated: npm config get failed")
		}
		t.Cleanup(func() { npmGetConfigValue = orig })

		results, err := runFixture(t)
		assert.NoError(t, err, "a transient npm-config-lookup failure must not abort an audit whose install would otherwise have succeeded")
		assert.NotEmpty(t, results, "the real, successful install result must still be reported")
	})

	// End-to-end with real ambient npm config (NPM_CONFIG_CACHE/LOGS_MAX), not just the Go-level mock.
	t.Run("logs_max_zero_leaves_no_stray_log_after_real_success", func(t *testing.T) {
		isolatedCache := t.TempDir()
		t.Setenv("NPM_CONFIG_CACHE", isolatedCache)
		t.Setenv("NPM_CONFIG_LOGS_MAX", "0")

		results, err := runFixture(t)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		entries, readErr := os.ReadDir(filepath.Join(isolatedCache, "_logs"))
		if readErr != nil {
			require.True(t, os.IsNotExist(readErr), "unexpected error reading _logs dir: %v", readErr)
			return
		}
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		assert.Empty(t, names, "no stray debug log should remain in a fresh, isolated cache after a successful install when logs-max was 0")
	})

	// A user's own, already-nonzero logs-max retention setting must never be forced down —
	// only logs-max=0 (which would suppress npm's debug log entirely) justifies an override.
	t.Run("nonzero_logs_max_is_never_overridden", func(t *testing.T) {
		isolatedCache := t.TempDir()
		logsDir := filepath.Join(isolatedCache, "_logs")
		require.NoError(t, os.MkdirAll(logsDir, 0755))
		// Seed more pre-existing logs than the old forced value (10) ever allowed, in npm's
		// real filename shape, so npm's own rotation would recognize and count them.
		for i := 0; i < 20; i++ {
			name := fmt.Sprintf("2025-01-01T00_00_%02d_000Z-debug-0.log", i)
			require.NoError(t, os.WriteFile(filepath.Join(logsDir, name), []byte("0 verbose cli npm\n"), 0644))
		}

		t.Setenv("NPM_CONFIG_CACHE", isolatedCache)
		t.Setenv("NPM_CONFIG_LOGS_MAX", "50")

		results, err := runFixture(t)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		entries, readErr := os.ReadDir(logsDir)
		require.NoError(t, readErr)
		assert.GreaterOrEqual(t, len(entries), 20,
			"a user's own logs-max=50 must not be overridden/pruned by a smaller forced value")
	})

	// An independently-configured logs-dir (not <cache>/_logs, npm's own default) must still be
	// found — assuming the default would silently defeat the whole fallback for anyone who sets it.
	t.Run("independent_logs_dir_is_respected_not_assumed_from_cache", func(t *testing.T) {
		isolatedCache := t.TempDir()
		isolatedLogsDir := t.TempDir()
		t.Setenv("NPM_CONFIG_CACHE", isolatedCache)
		t.Setenv("NPM_CONFIG_LOGS_DIR", isolatedLogsDir)
		t.Setenv("NPM_CONFIG_LOGS_MAX", "0")

		results, err := runFixture(t)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		// The forced-then-cleaned log must have gone to the configured logs-dir, not <cache>/_logs.
		_, cacheLogsErr := os.ReadDir(filepath.Join(isolatedCache, "_logs"))
		assert.True(t, os.IsNotExist(cacheLogsErr), "no log should ever land under <cache>/_logs when logs-dir is set independently")

		entries, readErr := os.ReadDir(isolatedLogsDir)
		require.NoError(t, readErr)
		assert.Empty(t, entries, "the log written to the independently-configured logs-dir must still be cleaned up when logs-max was 0")
	})
}

// A never-contacted dependency must not report the same BlockingReason/Action as a real block.
// The console warning must not embed npm's own error text (which can include its full
// captured stdout/stderr) — that goes to log.Debug only, so the console stays a clean one-liner.
func TestNpmLogPartialReportWarning_DoesNotEmbedRawNpmOutput(t *testing.T) {
	assert.NotContains(t, npmLogPartialReportWarning, "%s",
		"must be a fixed string, not a template that could embed npm's raw (potentially huge) error output")
}

// The "Found N blocked packages" count must not count non-registry "not evaluated" rows as blocked.
func TestCountBlockedPackages_ExcludesNotEvaluatedRows(t *testing.T) {
	rows := []*PackageStatus{
		{PackageName: "real-block", Action: blocked},
		{PackageName: "is-thirteen", Action: notEvaluated},
		{PackageName: "another-block", Action: blocked},
	}
	assert.Equal(t, 2, countBlockedPackages(rows))
}

// A not-evaluated row's placeholder Policy{"—","—"} must not leak into the Blocked list.
func TestGetBlocked_ExcludesNotEvaluatedRows(t *testing.T) {
	rows := []*PackageStatus{
		{PackageName: "real-block", PackageVersion: "1.0.0", Action: blocked,
			Policy: []Policy{{Policy: "cve-high", Condition: "cond1"}}},
		{PackageName: "git-dep", PackageVersion: "github:foo/bar (not evaluated)", Action: notEvaluated,
			Policy: []Policy{{Policy: "—", Condition: "—"}}},
	}
	blockedList := getBlocked(rows)
	require.Len(t, blockedList, 1)
	assert.Equal(t, "cve-high", blockedList[0].Policy)
	for _, bp := range blockedList {
		assert.NotContains(t, bp.Packages, getPackageId("git-dep", "github:foo/bar (not evaluated)"))
	}
}

// Cleanup must still fire when parsing itself fails partway through (e.g. an oversized line).
func TestRunNpmLogFallback_CleansUpLogEvenOnScanError(t *testing.T) {
	cacheDir := t.TempDir()
	logsDir := filepath.Join(cacheDir, "_logs")
	require.NoError(t, os.MkdirAll(logsDir, 0755))
	logPath := filepath.Join(logsDir, "2026-01-01T00_00_00_000Z-debug-0.log")
	oversizedLine := strings.Repeat("a", 9*1024*1024) // exceeds scanner.Buffer's 8MB max token size
	require.NoError(t, os.WriteFile(logPath, []byte(oversizedLine+"\n"), 0644))

	ca := &CurationAuditCommand{
		PackageManagerConfig: (&project.RepositoryConfig{}).SetTargetRepo("repo"),
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
	}
	results := map[string]*CurationReport{}
	originalErr := errors.New("npm install failed before any resolution")

	err := ca.runNpmLogFallback(logsDir, techutils.Npm, results, originalErr, true, 0)
	assert.Equal(t, originalErr, err)

	_, statErr := os.Stat(logPath)
	assert.True(t, os.IsNotExist(statErr), "the log file should be removed even though parsing hit a scan error, since logsMaxWasZero means it only exists because of our own --logs-max override")
}

// TestUniqueReportKey covers the disambiguation loop, including a 3-way collision where both
// the plain key and its first tech-suffixed candidate are already taken.
func TestUniqueReportKey(t *testing.T) {
	results := map[string]*CurationReport{
		"proj":          {},
		"proj (pip)":    {},
		"proj (pip) #2": {},
	}
	assert.Equal(t, "proj", uniqueReportKey(map[string]*CurationReport{}, "proj", techutils.Pip), "no collision — key returned as-is")
	assert.Equal(t, "proj (pip)", uniqueReportKey(map[string]*CurationReport{"proj": {}}, "proj", techutils.Pip), "single collision — first suffixed candidate")
	assert.Equal(t, "proj (pip) #3", uniqueReportKey(results, "proj", techutils.Pip), "triple collision — must skip to the next free numbered candidate")
}

// TestSetRepoFromUvTomlNoServerConfigured is a regression test for a garbled error
// message: ca.ServerDetails() (AuditBasicParams.ServerDetails) always returns a nil
// error, so wrapping it with %w produced "...: %!w(<nil>)" — a raw Go fmt-verb artifact
// leaking to the user instead of a clean "no server configured" message.
func TestSetRepoFromUvTomlNoServerConfigured(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	projectDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "pyproject.toml"), []byte(`[[tool.uv.index]]
name = "artifactory-repo"
url = "https://host/artifactory/api/pypi/uv-test-repo/simple"
`), 0644))
	prevWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(projectDir))
	defer clienttestutils.ChangeDirAndAssert(t, prevWd)

	ca := NewCurationAuditCommand()

	setErr := ca.setRepoFromUvToml()

	require.Error(t, setErr)
	assert.NotContains(t, setErr.Error(), "%!w", "error must not leak a raw Go fmt-verb artifact to the user")
	assert.Contains(t, setErr.Error(), "no 'jf c' server configured")
}

// TestAuditTreeSkipsRedundantSetRepoFromUvTomlWhenAlreadySet is a regression test:
// setRepoFromUvToml() used to run twice per uv run — once via GetAuth(Uv), again
// unconditionally in auditTree. auditTree now skips it once PackageManagerConfig is set.
func TestAuditTreeSkipsRedundantSetRepoFromUvTomlWhenAlreadySet(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	projectDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "pyproject.toml"), []byte(`[[tool.uv.index]]
name = "artifactory-repo"
url = "https://host/artifactory/api/pypi/uv-test-repo/simple"
`), 0644))
	prevWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(projectDir))
	defer clienttestutils.ChangeDirAndAssert(t, prevWd)

	ca := NewCurationAuditCommand()
	ca.SetServerDetails(&config.ServerDetails{Url: "https://host/", ArtifactoryUrl: "https://host/artifactory/"})

	var buf bytes.Buffer
	origLogger := log.Logger
	log.SetLogger(log.NewLogger(log.INFO, &buf))
	defer log.SetLogger(origLogger)

	firstServerDetails, err := ca.GetAuth(techutils.Uv)
	require.NoError(t, err)
	require.NotNil(t, firstServerDetails)
	require.NotNil(t, ca.PackageManagerConfig, "GetAuth must populate PackageManagerConfig via setRepoFromUvToml")
	logCountAfterGetAuth := strings.Count(buf.String(), "using Artifactory URL")
	assert.Equal(t, 2, logCountAfterGetAuth, "one setRepoFromUvToml() call must log exactly twice: "+
		"once from GetNativeUvRegistryConfig, once from setRepoFromUvToml itself")

	_ = ca.auditTree(techutils.Uv, map[string]*CurationReport{})

	logCountAfterAuditTree := strings.Count(buf.String(), "using Artifactory URL")
	assert.Equal(t, logCountAfterGetAuth, logCountAfterAuditTree,
		"auditTree must not re-read uv.toml when PackageManagerConfig is already set")
}

// TestSetRepoFromUvTomlRejectsHostMismatch: a pyproject.toml [[tool.uv.index]] entry
// pointing at a different host than the configured 'jf c' server must not receive that
// server's credentials.
func TestSetRepoFromUvTomlRejectsHostMismatch(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	projectDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "pyproject.toml"), []byte(`[[tool.uv.index]]
name = "artifactory-repo"
url = "https://attacker.example.com/artifactory/api/pypi/uv-test-repo/simple"
`), 0644))
	prevWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(projectDir))
	defer clienttestutils.ChangeDirAndAssert(t, prevWd)

	ca := NewCurationAuditCommand()
	ca.SetServerDetails(&config.ServerDetails{
		Url:            "https://configured-server.example.com/",
		ArtifactoryUrl: "https://configured-server.example.com/artifactory/",
		AccessToken:    "super-secret-token",
	})

	setErr := ca.setRepoFromUvToml()

	require.Error(t, setErr)
	assert.Contains(t, setErr.Error(), "does not match")
	assert.Nil(t, ca.PackageManagerConfig, "credentials must not be attached to the mismatched host")
}

// TestSetRepoFromUvTomlAcceptsMatchingHost: the host check must not block the legitimate
// same-host case.
func TestSetRepoFromUvTomlAcceptsMatchingHost(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	projectDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "pyproject.toml"), []byte(`[[tool.uv.index]]
name = "artifactory-repo"
url = "https://configured-server.example.com/artifactory/api/pypi/uv-test-repo/simple"
`), 0644))
	prevWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(projectDir))
	defer clienttestutils.ChangeDirAndAssert(t, prevWd)

	ca := NewCurationAuditCommand()
	ca.SetServerDetails(&config.ServerDetails{
		Url:            "https://configured-server.example.com/",
		ArtifactoryUrl: "https://configured-server.example.com/artifactory/",
	})

	require.NoError(t, ca.setRepoFromUvToml())
	require.NotNil(t, ca.PackageManagerConfig)
}

// TestSetRepoFromUvTomlRejectsSchemeDowngrade: a pyproject.toml
// [[tool.uv.index]] entry pointing at the *same host* as the configured 'jf c' server, but
// over http instead of https, must not receive that server's credentials — otherwise the
// host-only check would let a project-local file downgrade them to cleartext.
func TestSetRepoFromUvTomlRejectsSchemeDowngrade(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	projectDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "pyproject.toml"), []byte(`[[tool.uv.index]]
name = "artifactory-repo"
url = "http://configured-server.example.com/artifactory/api/pypi/uv-test-repo/simple"
`), 0644))
	prevWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(projectDir))
	defer clienttestutils.ChangeDirAndAssert(t, prevWd)

	ca := NewCurationAuditCommand()
	ca.SetServerDetails(&config.ServerDetails{
		Url:            "https://configured-server.example.com/",
		ArtifactoryUrl: "https://configured-server.example.com/artifactory/",
		AccessToken:    "super-secret-token",
	})

	setErr := ca.setRepoFromUvToml()

	require.Error(t, setErr)
	assert.Contains(t, setErr.Error(), "does not match")
	assert.Nil(t, ca.PackageManagerConfig, "credentials must not be downgraded to a cleartext http URL on the same host")
}

// TestPipWinsOverStrayUvLock verifies promotePipToUv's "pip-exclusive files win over
// uv.lock" rule: requirements.txt plus a stray leftover uv.lock must still audit as pip.
func TestPipWinsOverStrayUvLock(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("requests==2.31.0\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "uv.lock"), []byte("# stray uv.lock\n"), 0644))
	t.Chdir(root)

	techs := promotePipToUv(techutils.DetectedTechnologiesListForCurationAudit())

	assert.Contains(t, techs, techutils.Pip.String(), "a pip-exclusive file (requirements.txt) must win over a stray uv.lock")
	assert.NotContains(t, techs, techutils.Uv.String(), "must not report uv when a pip-exclusive file is present")
}

// TestPureUvProjectNotReportedAsPip guards the flip side: since Pip's indicators no
// longer exclude uv.lock, a plain uv project fires both pip (pyproject.toml) and uv
// (uv.lock) — promotePipToUv must still collapse that to uv alone.
func TestPureUvProjectNotReportedAsPip(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "pyproject.toml"), []byte("[project]\nname = \"demo\"\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "uv.lock"), []byte("version = 1\n"), 0644))
	t.Chdir(root)

	techs := promotePipToUv(techutils.DetectedTechnologiesListForCurationAudit())

	assert.Contains(t, techs, techutils.Uv.String(), "uv.lock present, no pip-exclusive files — must report uv")
	assert.NotContains(t, techs, techutils.Pip.String(), "must not also report pip for a plain uv-only project")
}

// TestTechsToAuditQueuesPep723HintForDeferredLogging: the PEP 723 hint must be queued in pendingWarnings.
func TestTechsToAuditQueuesPep723HintForDeferredLogging(t *testing.T) {
	projectDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "pyproject.toml"), []byte("[project]\nname = \"demo\"\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "uv.lock"), []byte("version = 1\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "script.py"),
		[]byte("# /// script\n# dependencies = [\"six\"]\n# ///\n\nimport six\n"), 0644))
	prevWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(projectDir))
	defer clienttestutils.ChangeDirAndAssert(t, prevWd)

	ca := NewCurationAuditCommand()

	techs := ca.techsToAudit()

	assert.Equal(t, []string{techutils.Uv.String()}, techs)
	require.Len(t, ca.pendingWarnings, 1, "the hint must be queued, not logged immediately")
	assert.Contains(t, ca.pendingWarnings[0], "--script")
}

// TestRunCvsFallbackNoMatchesFound covers runCvsFallback's empty-recovery branch: when
// fetchCvsBlockedStatus can't recover a policy for any of cvsErr's packages (e.g. the
// metadata API has no record of the stripped version), no partial table should be
// rendered. Instead: a generic curation-block message is joined to the original cause when
// the tech's forbidden-output pattern matches it, or the bare cvsErr is returned unchanged
// otherwise. Either way, results must stay untouched — no misleading empty/partial entry.
func TestRunCvsFallbackNoMatchesFound(t *testing.T) {
	const repo = "test-pip-repo"
	// Metadata API 404s for every package/version — fetchCvsBlockedStatus recovers nothing.
	serverMock, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer serverMock.Close()

	repoConfig := (&project.RepositoryConfig{}).
		SetTargetRepo(repo).
		SetServerDetails(serverDetails)
	ca := &CurationAuditCommand{
		PackageManagerConfig: repoConfig,
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
	}
	unresolvedPkg := []python.PinnedRequirement{{Name: "unresolvable-pkg", Version: "9.9.9", ParentName: "unresolvable-pkg", ParentVersion: "9.9.9"}}

	t.Run("forbidden-output cause — wraps cause with generic curation-block message", func(t *testing.T) {
		cvsErr := &python.CvsBlockedError{
			Packages: unresolvedPkg,
			Cause:    errors.New("ERROR: HTTP error 403 while getting https://example.com/simple/unresolvable-pkg/"),
		}
		results := map[string]*CurationReport{}
		err := ca.runCvsFallback(cvsErr, techutils.Pip, results)

		require.Error(t, err)
		assert.ErrorIs(t, err, cvsErr.Cause, "original cause must still be reachable via errors.Is")
		assert.Contains(t, err.Error(), fmt.Sprintf(technologies.CurationErrorMsgToUserTemplate, techutils.Pip),
			"generic curation-block guidance must be joined in when the tech's forbidden-output pattern matches")
		assert.Empty(t, results, "no partial/empty table entry must be recorded")
	})

	t.Run("non-forbidden cause — returns cvsErr unchanged", func(t *testing.T) {
		cvsErr := &python.CvsBlockedError{
			Packages: unresolvedPkg,
			Cause:    errors.New("some unrelated resolution failure"),
		}
		results := map[string]*CurationReport{}
		err := ca.runCvsFallback(cvsErr, techutils.Pip, results)

		assert.Same(t, cvsErr, err, "with no recognizable forbidden pattern, the bare cvsErr must be returned as-is")
		assert.Empty(t, results, "no partial/empty table entry must be recorded")
	})
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

func TestSetRepoFromPipfileRejectsInvalidPresentConfig(t *testing.T) {
	t.Chdir(t.TempDir())
	require.NoError(t, os.MkdirAll(filepath.Join(".jfrog", "projects"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(".jfrog", "projects", "pipenv.yaml"), []byte("resolver: [\n"), 0600))
	require.NoError(t, os.WriteFile("Pipfile", []byte(`[[source]]
name = "jfrog"
url = "https://user:token@acme.jfrog.io/artifactory/api/pypi/repo/simple"
`), 0600))

	ca := NewCurationAuditCommand()
	err := ca.setRepoFromPipfile()
	require.Error(t, err)
	assert.Nil(t, ca.PackageManagerConfig)
}

func TestSetRepoFromPipConfFallsBackToConfiguredServerCredentials(t *testing.T) {
	t.Chdir(t.TempDir())
	pipConfPath := filepath.Join(t.TempDir(), "pip.conf")
	require.NoError(t, os.WriteFile(pipConfPath, []byte(
		"[global]\nindex-url = https://acme.jfrog.io/artifactory/api/pypi/pypi-remote/simple\n"), 0600))
	t.Setenv("PIP_CONFIG_FILE", pipConfPath)

	ca := NewCurationAuditCommand()
	ca.SetServerDetails(&config.ServerDetails{
		ArtifactoryUrl: "https://acme.jfrog.io/artifactory/", User: "u", Password: "p",
	})

	err := ca.setRepoFromPipConf()
	require.NoError(t, err)
	serverDetails, err := ca.PackageManagerConfig.ServerDetails()
	require.NoError(t, err)
	assert.Equal(t, "u", serverDetails.GetUser())
	assert.Equal(t, "p", serverDetails.GetPassword())
	assert.Equal(t, "https://acme.jfrog.io/artifactory/", serverDetails.GetArtifactoryUrl())
}

func TestSetRepoFromPipConf_YamlPresent_Succeeds(t *testing.T) {
	tempHomeDir := t.TempDir()
	callbackHomeDir := clienttestutils.SetEnvWithCallbackAndAssert(t, coreutils.HomeDir, tempHomeDir)
	defer callbackHomeDir()
	WriteServerDetailsConfigFileBytes(t, "https://acme.jfrog.io/artifactory/", tempHomeDir, false)

	t.Chdir(t.TempDir())
	require.NoError(t, os.MkdirAll(filepath.Join(".jfrog", "projects"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(".jfrog", "projects", "pip.yaml"), []byte(`version: 1
type: pip
resolver:
    repo: pip-repo
    serverId: test
`), 0600))

	ca := NewCurationAuditCommand()
	err := ca.setRepoFromPipConf()
	require.NoError(t, err)
	require.NotNil(t, ca.PackageManagerConfig)
	assert.Equal(t, "pip-repo", ca.PackageManagerConfig.TargetRepo())
	serverDetails, err := ca.PackageManagerConfig.ServerDetails()
	require.NoError(t, err)
	assert.Equal(t, "https://acme.jfrog.io/artifactory/", serverDetails.GetArtifactoryUrl())
}

func TestSetRepoFromPipConf_PipConfOnly_UsesEmbeddedCredentials(t *testing.T) {
	t.Chdir(t.TempDir())
	pipConfPath := filepath.Join(t.TempDir(), "pip.conf")
	require.NoError(t, os.WriteFile(pipConfPath, []byte(
		"[global]\nindex-url = https://user:token@acme.jfrog.io/artifactory/api/pypi/pypi-remote/simple\n"), 0600))
	t.Setenv("PIP_CONFIG_FILE", pipConfPath)

	ca := NewCurationAuditCommand()
	err := ca.setRepoFromPipConf()
	require.NoError(t, err)
	require.NotNil(t, ca.PackageManagerConfig)
	assert.Equal(t, "pypi-remote", ca.PackageManagerConfig.TargetRepo())
	serverDetails, err := ca.PackageManagerConfig.ServerDetails()
	require.NoError(t, err)
	assert.Equal(t, "user", serverDetails.GetUser())
	assert.Equal(t, "token", serverDetails.GetPassword())
}

func TestSetRepoFromPipConf_RejectsMalformedYaml(t *testing.T) {
	t.Chdir(t.TempDir())
	require.NoError(t, os.MkdirAll(filepath.Join(".jfrog", "projects"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(".jfrog", "projects", "pip.yaml"), []byte("resolver: [\n"), 0600))

	ca := NewCurationAuditCommand()
	err := ca.setRepoFromPipConf()
	require.Error(t, err)
	assert.Nil(t, ca.PackageManagerConfig)
}

func TestSetRepoFromPipConf_ErrorsWhenNeitherResolves(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("PIP_CONFIG_FILE", "")

	ca := NewCurationAuditCommand()
	err := ca.setRepoFromPipConf()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jf pip-config")
	assert.Contains(t, err.Error(), "pip.conf")
	assert.Nil(t, ca.PackageManagerConfig)
}

func TestSetRepoFromPipConf_RejectsUnparsablePipConfUrl(t *testing.T) {
	t.Chdir(t.TempDir())
	pipConfPath := filepath.Join(t.TempDir(), "pip.conf")
	require.NoError(t, os.WriteFile(pipConfPath, []byte(
		"[global]\nindex-url = https://admin:<token>@acme.jfrog.io/artifactory/api/pypi/pypi-remote/simple\n"), 0600))
	t.Setenv("PIP_CONFIG_FILE", pipConfPath)

	ca := NewCurationAuditCommand()
	err := ca.setRepoFromPipConf()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid Artifactory PyPI URL")
	assert.Nil(t, ca.PackageManagerConfig)
}

func TestSetRepoFromPipConf_NonArtifactoryPipConfFallsToGenericError(t *testing.T) {
	t.Chdir(t.TempDir())
	pipConfPath := filepath.Join(t.TempDir(), "pip.conf")
	require.NoError(t, os.WriteFile(pipConfPath, []byte(
		"[global]\nindex-url = https://pypi.org/simple\n"), 0600))
	t.Setenv("PIP_CONFIG_FILE", pipConfPath)

	ca := NewCurationAuditCommand()
	err := ca.setRepoFromPipConf()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jf pip-config")
	assert.Contains(t, err.Error(), "pip.conf")
	assert.Nil(t, ca.PackageManagerConfig)
}

func TestSendBoundedRequestRejectsRedirectOutsideRepository(t *testing.T) {
	for _, tech := range []techutils.Technology{techutils.Pip, techutils.Poetry, techutils.Pipenv} {
		t.Run(tech.String(), func(t *testing.T) {
			var outsideRequested atomic.Bool
			var requests atomic.Int32
			server, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path == "/api/system/configuration" {
					outsideRequested.Store(true)
					w.WriteHeader(http.StatusOK)
					return
				}
				http.Redirect(w, r, "/api/system/configuration", http.StatusFound)
			})
			defer server.Close()
			rtManager, err := rtUtils.CreateServiceManager(serverDetails, 0, 0, false)
			require.NoError(t, err)
			rtAuth := rtManager.GetConfig().GetServiceDetails()
			analyzer := treeAnalyzer{
				rtManager:         rtManager,
				httpClientDetails: rtAuth.CreateHttpClientDetails(),
				url:               rtAuth.GetUrl(),
				repo:              "repo",
				tech:              tech,
			}
			requestDetails := analyzer.httpClientDetails.Clone()
			requestDetails.Headers["X-Artifactory-Curation-Request-Waiver"] = "syn"

			_, _, err = analyzer.sendBoundedRequest(http.MethodGet,
				strings.TrimSuffix(analyzer.url, "/")+"/api/pypi/repo/packages/pkg.whl", requestDetails)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unsafe redirect")
			assert.False(t, outsideRequested.Load())
			assert.Equal(t, int32(1), requests.Load())
		})
	}
}

func TestCvsMetadataRejectsRedirectOutsideRepository(t *testing.T) {
	tests := []struct {
		name string
		call func(*treeAnalyzer) error
	}{
		{
			name: "all versions metadata",
			call: func(analyzer *treeAnalyzer) error {
				_, err := analyzer.lookupPypiAllVersions("urllib3")
				return err
			},
		},
		{
			name: "version download metadata",
			call: func(analyzer *treeAnalyzer) error {
				_, err := analyzer.lookupPypiNormalDownloadURL("urllib3", "2.0.7")
				return err
			},
		},
	}
	for _, tech := range []techutils.Technology{techutils.Pip, techutils.Poetry, techutils.Pipenv} {
		for _, test := range tests {
			t.Run(tech.String()+"/"+test.name, func(t *testing.T) {
				var outsideRequested atomic.Bool
				var requests atomic.Int32
				server, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if r.URL.Path == "/api/system/configuration" {
						outsideRequested.Store(true)
						w.WriteHeader(http.StatusOK)
						return
					}
					http.Redirect(w, r, "/api/system/configuration", http.StatusFound)
				})
				defer server.Close()
				rtManager, err := rtUtils.CreateServiceManager(serverDetails, 0, 0, false)
				require.NoError(t, err)
				rtAuth := rtManager.GetConfig().GetServiceDetails()
				analyzer := &treeAnalyzer{
					rtManager:         rtManager,
					httpClientDetails: rtAuth.CreateHttpClientDetails(),
					url:               rtAuth.GetUrl(),
					repo:              "repo",
					tech:              tech,
				}

				err = test.call(analyzer)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unsafe redirect")
				assert.False(t, outsideRequested.Load())
				assert.Equal(t, int32(1), requests.Load())
			})
		}
	}
}

// TestFetchNodeStatusRoutesPipAndPoetryThroughBoundedRedirects exercises the actual
// tech-branch in fetchNodeStatus (not sendBoundedRequest directly) to guard against a
// regression that silently narrows the bounded-redirect condition back to Pipenv only.
func TestFetchNodeStatusRoutesPipAndPoetryThroughBoundedRedirects(t *testing.T) {
	for _, tech := range []techutils.Technology{techutils.Pip, techutils.Poetry, techutils.Pipenv} {
		t.Run(tech.String(), func(t *testing.T) {
			var outsideRequested atomic.Bool
			var requests atomic.Int32
			server, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path == "/api/system/configuration" {
					outsideRequested.Store(true)
					w.WriteHeader(http.StatusOK)
					return
				}
				http.Redirect(w, r, "/api/system/configuration", http.StatusFound)
			})
			defer server.Close()
			rtManager, err := rtUtils.CreateServiceManager(serverDetails, 0, 0, false)
			require.NoError(t, err)
			rtAuth := rtManager.GetConfig().GetServiceDetails()
			nodeId := python.PythonPackageTypeIdentifier + "pkg:1.0.0"
			packageUrl := strings.TrimSuffix(rtAuth.GetUrl(), "/") + "/api/pypi/repo/packages/pkg.whl"
			analyzer := treeAnalyzer{
				rtManager:         rtManager,
				httpClientDetails: rtAuth.CreateHttpClientDetails(),
				url:               rtAuth.GetUrl(),
				repo:              "repo",
				tech:              tech,
				downloadUrls:      map[string]string{nodeId: packageUrl},
			}

			err = analyzer.fetchNodeStatus(xrayUtils.GraphNode{Id: nodeId}, &sync.Map{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unsafe redirect")
			assert.False(t, outsideRequested.Load())
			assert.Equal(t, int32(1), requests.Load())
		})
	}
}

// TestValidateRunNativeForTech checks that --run-native is accepted for the
// allow-listed native-config techs (npm, pnpm, yarn, uv) and rejected for all other
// techs with an error that names the offending tech.
func TestValidateRunNativeForTech(t *testing.T) {
	// Sanity: npm and pnpm are allow-listed techs. Both flag states pass.
	assert.NoError(t, validateRunNativeForTech(techutils.Npm, true))
	assert.NoError(t, validateRunNativeForTech(techutils.Npm, false))
	assert.NoError(t, validateRunNativeForTech(techutils.Pnpm, true))
	assert.NoError(t, validateRunNativeForTech(techutils.Pnpm, false))

	// --run-native has no effect for yarn regardless of version; a warning is emitted in auditTree.
	t.Run("yarn accepts --run-native as a redundant no-op", func(t *testing.T) {
		assert.NoError(t, validateRunNativeForTech(techutils.Yarn, true))
		assert.NoError(t, validateRunNativeForTech(techutils.Yarn, false))
	})

	// uv has no 'jf uv-config', so --run-native must be a no-op like pnpm/yarn
	t.Run("uv accepts --run-native as a redundant no-op", func(t *testing.T) {
		assert.NoError(t, validateRunNativeForTech(techutils.Uv, true))
		assert.NoError(t, validateRunNativeForTech(techutils.Uv, false))
	})

	// pip/pipenv already resolve automatically (yaml, then pip.conf, then — for pipenv —
	// the Pipfile [[source]]); --run-native has nothing to switch between, so it's
	// accepted as a no-op, same as pnpm/yarn — a warning is emitted in auditTree.
	t.Run("pip accepts --run-native as a redundant no-op", func(t *testing.T) {
		assert.NoError(t, validateRunNativeForTech(techutils.Pip, true))
		assert.NoError(t, validateRunNativeForTech(techutils.Pip, false))
	})
	t.Run("pipenv accepts --run-native as a redundant no-op", func(t *testing.T) {
		assert.NoError(t, validateRunNativeForTech(techutils.Pipenv, true))
		assert.NoError(t, validateRunNativeForTech(techutils.Pipenv, false))
	})

	// Every other supported tech follows the same contract. Catch silent
	// acceptance for any tech that's in the doc-table-of-supported but
	// hasn't implemented a native flow — same UX as yarn.
	otherTechs := []techutils.Technology{
		techutils.Gradle,
		techutils.Maven,
		techutils.Gem,
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
			// Defensive: isolate the OS home too so a real ~/.yarnrc.yml can't leak
			// in if this code path ever starts probing os.UserHomeDir().
			dummyHome := t.TempDir()
			t.Setenv("HOME", dummyHome)
			t.Setenv("USERPROFILE", dummyHome)
			restoreCwd := changeDirForTest(t, tempProjectDir)
			defer restoreCwd()

			got := resolveResolverTechForCuration(tc.tech)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestResolveNpmYarnTech(t *testing.T) {
	type setup struct {
		writeYarnYaml           bool
		writeNpmYaml            bool
		writeLocalYarnrc        bool // write .yarnrc.yml into the project dir (V4 native, local)
		writeGlobalYarnrc       bool // write .yarnrc.yml into dummyHome (V4 native, global)
		writePackageLockJSON    bool // write package-lock.json — marks project as npm, blocks promotion
		writeYarnPackageManager bool // package.json pins yarn via Corepack "packageManager"
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
		// V4 native-mode paths: no yarn.yaml / npm.yaml, detection via yarn indicator files.
		{
			name:  "npm, local .yarnrc.yml present — promoted to yarn (V4 native, local indicator)",
			tech:  techutils.Npm.String(),
			setup: setup{writeLocalYarnrc: true},
			want:  techutils.Yarn.String(),
		},
		{
			name:  "npm, global ~/.yarnrc.yml + package.json pins yarn — promoted to yarn (V4 native, global indicator)",
			tech:  techutils.Npm.String(),
			setup: setup{writeGlobalYarnrc: true, writeYarnPackageManager: true},
			want:  techutils.Yarn.String(),
		},
		{
			name:  "npm, global ~/.yarnrc.yml but package.json does NOT pin yarn — stays npm (guard against personal global config)",
			tech:  techutils.Npm.String(),
			setup: setup{writeGlobalYarnrc: true},
			want:  techutils.Npm.String(),
		},
		{
			name:  "npm, yarn indicator present but package-lock.json exists — NOT promoted",
			tech:  techutils.Npm.String(),
			setup: setup{writeLocalYarnrc: true, writePackageLockJSON: true},
			want:  techutils.Npm.String(),
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
			if tc.setup.writeLocalYarnrc {
				require.NoError(t, os.WriteFile(filepath.Join(tempProjectDir, ".yarnrc.yml"), []byte("npmRegistryServer: https://example.com\n"), 0o644))
			}
			if tc.setup.writePackageLockJSON {
				require.NoError(t, os.WriteFile(filepath.Join(tempProjectDir, "package-lock.json"), []byte("{}"), 0o644))
			}
			if tc.setup.writeYarnPackageManager {
				require.NoError(t, os.WriteFile(filepath.Join(tempProjectDir, "package.json"), []byte(`{"packageManager":"yarn@4.1.0"}`), 0o644))
			}
			restoreHome := clienttestutils.SetEnvWithCallbackAndAssert(t, coreutils.HomeDir, t.TempDir())
			defer restoreHome()
			// resolveNpmYarnTech also probes the OS home (~/.yarnrc.yml) via
			// os.UserHomeDir(); point it at an empty dir so a real one on the
			// developer's machine can't leak in and flip "neither yaml" to yarn.
			// HOME (unix) and USERPROFILE (windows) cover os.UserHomeDir on all OSes.
			dummyHome := t.TempDir()
			t.Setenv("HOME", dummyHome)
			t.Setenv("USERPROFILE", dummyHome)
			if tc.setup.writeGlobalYarnrc {
				require.NoError(t, os.WriteFile(filepath.Join(dummyHome, ".yarnrc.yml"), []byte("npmRegistryServer: https://example.com\n"), 0o644))
			}
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

// TestFetchCvsBlockedStatusUv verifies the CVS fallback for uv: metadata fetch → HEAD probe → policy parse.
func TestFetchCvsBlockedStatusUv(t *testing.T) {
	const (
		repo            = "test-uv-pypi-repo"
		blockedPkg      = "requests"
		blockedVer      = "2.19.1"
		expectedPolicy  = "immature-30"
		expectedCond    = "Package version is immature (strict)"
		expectedExpl    = "Package version is 3 days old"
		expectedRec     = "Use an older version or wait until this version is no longer immature"
		whlRelativePath = "packages/re/qu/requests-2.19.1-py2.py3-none-any.whl"
	)

	blockMsg := fmt.Sprintf(
		"Package %s:%s download was blocked by JFrog Packages Curation service due to the following policies violated {%s, %s, %s, %s}.",
		blockedPkg, blockedVer, expectedPolicy, expectedCond, expectedExpl, expectedRec,
	)
	blockResponse := fmt.Sprintf(`{"errors":[{"status":403,"message":%q}]}`, blockMsg)
	versionMetaJSON := fmt.Sprintf(`{"urls":[{"packagetype":"bdist_wheel","url":"../../%s"}]}`, whlRelativePath)

	serverMock, _, rtManager := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/pypi/"+blockedPkg+"/"+blockedVer+"/json"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(versionMetaJSON))
		case r.Method == http.MethodHead && strings.Contains(r.URL.Path, whlRelativePath):
			w.WriteHeader(http.StatusForbidden)
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
		tech:                 techutils.Uv,
		parallelRequests:     1,
	}

	pins := []python.PinnedRequirement{
		{Name: blockedPkg, Version: blockedVer, ParentName: blockedPkg, ParentVersion: blockedVer},
	}

	statuses := analyzer.fetchCvsBlockedStatus(pins)
	require.Len(t, statuses, 1)

	s := statuses[0]
	assert.Equal(t, blockedPkg, s.PackageName)
	assert.Equal(t, blockedVer, s.PackageVersion)
	assert.Equal(t, string(techutils.Uv), s.PkgType, "package type must be uv")
	require.Len(t, s.Policy, 1)
	assert.Equal(t, expectedPolicy, s.Policy[0].Policy)
	assert.Equal(t, expectedCond, s.Policy[0].Condition)
	assert.Equal(t, expectedExpl, s.Policy[0].Explanation)
	assert.Equal(t, expectedRec, s.Policy[0].Recommendation)
	assert.Equal(t, blocked, s.Action)
}

// TestFetchCvsBlockedStatusUvTransitive verifies the CVS fallback for a transitive
// blocker under uv
func TestFetchCvsBlockedStatusUvTransitive(t *testing.T) {
	const (
		repo            = "test-uv-pypi-repo"
		blockedPkg      = "langchain-core"
		blockedVer      = "1.4.7"
		parentPkg       = "deepagents"
		parentVer       = "0.6.12"
		rangeSpec       = ">=1.4.0"
		expectedPolicy  = "immature-strict"
		expectedCond    = "Package version is immature (strict)"
		expectedExpl    = "Package version is 3 days old"
		expectedRec     = "Use an older version or wait until this version is no longer immature"
		whlRelativePath = "packages/ab/cd/langchain_core-1.4.7-py3-none-any.whl"
	)

	blockMsg := fmt.Sprintf(
		"Package %s:%s download was blocked by JFrog Packages Curation service due to the following policies violated {%s, %s, %s, %s}.",
		blockedPkg, blockedVer, expectedPolicy, expectedCond, expectedExpl, expectedRec,
	)
	blockResponse := fmt.Sprintf(`{"errors":[{"status":403,"message":%q}]}`, blockMsg)
	allVersionsJSON := `{"releases":{"1.4.0":[],"1.4.1":[],"1.4.5":[],"1.4.7":[]}}`
	versionMetaJSON := fmt.Sprintf(`{"urls":[{"packagetype":"bdist_wheel","url":"../../%s"}]}`, whlRelativePath)

	serverMock, _, rtManager := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/pypi/"+blockedPkg+"/json"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(allVersionsJSON))
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/pypi/"+blockedPkg+"/"+blockedVer+"/json"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(versionMetaJSON))
		case r.Method == http.MethodHead && strings.Contains(r.URL.Path, whlRelativePath):
			w.WriteHeader(http.StatusForbidden)
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
		tech:                 techutils.Uv,
		parallelRequests:     1,
	}

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

	// Parent (direct dep) attribution — must differ from the blocked package.
	assert.Equal(t, parentPkg, s.ParentName, "direct dependency name")
	assert.Equal(t, parentVer, s.ParentVersion, "direct dependency version")
	assert.NotEqual(t, s.PackageName, s.ParentName, "transitive blocker must show a different direct-dependency name")

	assert.Equal(t, string(techutils.Uv), s.PkgType, "package type must be uv")
	require.Len(t, s.Policy, 1)
	assert.Equal(t, expectedPolicy, s.Policy[0].Policy)
	assert.Equal(t, expectedCond, s.Policy[0].Condition)
	assert.Equal(t, expectedExpl, s.Policy[0].Explanation)
	assert.Equal(t, expectedRec, s.Policy[0].Recommendation)
	assert.Equal(t, blocked, s.Action)
}

// TestResolveUvTech verifies that pip is promoted to uv when the right config signals are present.
func TestPromoteYarnWorkspaceMember(t *testing.T) {
	npm := techutils.Npm.String()
	yarn := techutils.Yarn.String()
	other := "maven"

	tests := []struct {
		name            string
		techs           []string
		ancestorFile    string // indicator file created in the ancestor dir ("" = none)
		expectedHasYarn bool
		expectedHasNpm  bool
	}{
		{
			name:            "already has yarn — no change",
			techs:           []string{yarn, npm},
			expectedHasYarn: true,
			expectedHasNpm:  true,
		},
		{
			name:            "no npm — no change",
			techs:           []string{other},
			expectedHasYarn: false,
			expectedHasNpm:  false,
		},
		{
			name:            "npm only, no ancestor indicator — no promotion",
			techs:           []string{npm},
			expectedHasYarn: false,
			expectedHasNpm:  true,
		},
		{
			name:            "npm only, ancestor has .yarnrc.yml — promote",
			techs:           []string{npm},
			ancestorFile:    ".yarnrc.yml",
			expectedHasYarn: true,
			expectedHasNpm:  false,
		},
		{
			name:            "npm only, ancestor has yarn.lock — promote",
			techs:           []string{npm},
			ancestorFile:    "yarn.lock",
			expectedHasYarn: true,
			expectedHasNpm:  false,
		},
		{
			name:            "npm + other, ancestor has .yarnrc.yml — npm promoted, other kept",
			techs:           []string{npm, other},
			ancestorFile:    ".yarnrc.yml",
			expectedHasYarn: true,
			expectedHasNpm:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			sub := filepath.Join(root, "sub")
			require.NoError(t, os.MkdirAll(sub, 0o755))
			if tc.ancestorFile != "" {
				require.NoError(t, os.WriteFile(filepath.Join(root, tc.ancestorFile), []byte{}, 0o644))
			}
			t.Chdir(sub)

			result := promoteYarnWorkspaceMember(tc.techs)

			hasYarn, hasNpm := false, false
			for _, tech := range result {
				switch tech {
				case yarn:
					hasYarn = true
				case npm:
					hasNpm = true
				}
			}
			assert.Equal(t, tc.expectedHasYarn, hasYarn, "yarn presence mismatch")
			assert.Equal(t, tc.expectedHasNpm, hasNpm, "npm presence mismatch")
		})
	}

	// A personal ~/.yarnrc.yml must not misclassify an npm project under $HOME as a
	// yarn workspace member: the walk stops at $HOME before statting it.
	t.Run("indicator at $HOME — no promotion", func(t *testing.T) {
		home := t.TempDir()
		sub := filepath.Join(home, "project")
		require.NoError(t, os.MkdirAll(sub, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(home, ".yarnrc.yml"), []byte{}, 0o644))
		// HOME (unix) and USERPROFILE (windows) cover os.UserHomeDir on all OSes.
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		t.Chdir(sub)

		result := promoteYarnWorkspaceMember([]string{npm})

		assert.Contains(t, result, npm, "npm should be kept when the only indicator is at $HOME")
		assert.NotContains(t, result, yarn, "npm must not be promoted to yarn from a $HOME-level indicator")
	})
}

// TestPromotePipToUv covers every uv signal promotePipToUv checks (uv.lock, pyproject.toml
// [tool.uv]/[[tool.uv.index]], ~/.config/uv/uv.toml), confirms pip-exclusive files always
// win, and confirms it collapses a tech list already containing both pip and uv into one.
func TestPromotePipToUv(t *testing.T) {
	pip := techutils.Pip.String()
	uv := techutils.Uv.String()
	other := "maven"

	tests := []struct {
		name           string
		techs          []string
		pyprojectTOML  string // content written to pyproject.toml; empty = don't create
		hasPipFile     string // name of a pip-exclusive file to create (e.g. "requirements.txt")
		hasUvLock      bool   // create uv.lock in the project dir
		hasUvToml      bool   // create ~/.config/uv/uv.toml
		expectedHasPip bool
		expectedHasUv  bool
	}{
		{
			name:  "no pip in techs — no change",
			techs: []string{other},
		},
		{
			name:           "pip with requirements.txt — stays pip",
			techs:          []string{pip},
			hasPipFile:     "requirements.txt",
			expectedHasPip: true,
		},
		{
			name:           "pip with setup.py — stays pip",
			techs:          []string{pip},
			hasPipFile:     "setup.py",
			expectedHasPip: true,
		},
		{
			name:          "pip + uv.lock — promoted to uv",
			techs:         []string{pip},
			hasUvLock:     true,
			expectedHasUv: true,
		},
		{
			name:           "pip-exclusive file takes priority over uv.lock — stays pip",
			techs:          []string{pip},
			hasPipFile:     "requirements.txt",
			hasUvLock:      true,
			expectedHasPip: true,
		},
		{
			name:          "pip + pyproject.toml with [tool.uv] — promoted to uv",
			techs:         []string{pip},
			pyprojectTOML: "[tool.uv]\npython = \"3.12\"\n",
			expectedHasUv: true,
		},
		{
			name:          "pip + pyproject.toml with [[tool.uv.index]] — promoted to uv",
			techs:         []string{pip},
			pyprojectTOML: "[[tool.uv.index]]\nurl = \"https://example.jfrog.io/api/pypi/pypi-virtual/simple\"\n",
			expectedHasUv: true,
		},
		{
			name:           "pip-exclusive file takes priority over [tool.uv] in pyproject.toml — stays pip",
			techs:          []string{pip},
			hasPipFile:     "requirements.txt",
			pyprojectTOML:  "[tool.uv]\npython = \"3.12\"\n",
			expectedHasPip: true,
		},
		{
			name:          "pip + ~/.config/uv/uv.toml — promoted to uv",
			techs:         []string{pip},
			hasUvToml:     true,
			expectedHasUv: true,
		},
		{
			name:           "pip-exclusive file takes priority over ~/.config/uv/uv.toml — stays pip",
			techs:          []string{pip},
			hasPipFile:     "Pipfile",
			hasUvToml:      true,
			expectedHasPip: true,
		},
		{
			name:           "plain pip project with bare pyproject.toml — stays pip",
			techs:          []string{pip},
			pyprojectTOML:  "[build-system]\nrequires = [\"setuptools\"]\n",
			expectedHasPip: true,
		},
		{
			name:          "already detected as both pip and uv, uv.lock present — collapses to uv alone",
			techs:         []string{pip, uv},
			hasUvLock:     true,
			expectedHasUv: true,
		},
		{
			name:           "already detected as both pip and uv, pip-exclusive file present — collapses to pip alone",
			techs:          []string{pip, uv},
			hasPipFile:     "requirements.txt",
			expectedHasPip: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			projectDir := t.TempDir()
			fakeHome := t.TempDir()

			t.Setenv("HOME", fakeHome)
			t.Setenv("USERPROFILE", fakeHome)
			t.Chdir(projectDir)

			if tc.hasPipFile != "" {
				require.NoError(t, os.WriteFile(filepath.Join(projectDir, tc.hasPipFile), []byte{}, 0o644))
			}
			if tc.hasUvLock {
				require.NoError(t, os.WriteFile(filepath.Join(projectDir, "uv.lock"), []byte{}, 0o644))
			}
			if tc.pyprojectTOML != "" {
				require.NoError(t, os.WriteFile(filepath.Join(projectDir, "pyproject.toml"), []byte(tc.pyprojectTOML), 0o644))
			}
			if tc.hasUvToml {
				uvCfgDir := filepath.Join(fakeHome, ".config", "uv")
				require.NoError(t, os.MkdirAll(uvCfgDir, 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(uvCfgDir, "uv.toml"), []byte("[[index]]\nurl = \"https://example.jfrog.io/api/pypi/pypi-virtual/simple\"\n"), 0o644))
			}

			result := promotePipToUv(tc.techs)

			hasPip, hasUv := false, false
			for _, tech := range result {
				switch tech {
				case pip:
					hasPip = true
				case uv:
					hasUv = true
				}
			}
			assert.Equal(t, tc.expectedHasPip, hasPip, "pip presence")
			assert.Equal(t, tc.expectedHasUv, hasUv, "uv presence")
		})
	}
}

// =============================================================================
// Tests for Pipenv support added to curationaudit.go.
// =============================================================================

func TestSupportedTechContainsPipenv(t *testing.T) {
	_, ok := supportedTech[techutils.Pipenv]
	assert.True(t, ok, "techutils.Pipenv must be registered in supportedTech so that 'jf curation-audit' processes pipenv projects")
}

func TestGetUrlNameAndVersionByTechPipenv(t *testing.T) {
	const whlUrl = "https://test.jfrog.io/artifactory/api/pypi/pypi-remote/packages/aa/bb/requests-2.31.0-py3-none-any.whl"
	downloadUrlsMap := map[string]string{"pypi://requests:2.31.0": whlUrl}

	downloadUrls, name, scope, ver := getUrlNameAndVersionByTech(techutils.Pipenv, &xrayUtils.GraphNode{Id: "pypi://requests:2.31.0"}, downloadUrlsMap, "https://test.jfrog.io", "pypi-remote")

	assert.Equal(t, []string{whlUrl}, downloadUrls)
	assert.Equal(t, "requests", name)
	assert.Equal(t, "", scope, "python packages have no scope")
	assert.Equal(t, "2.31.0", ver)
}
