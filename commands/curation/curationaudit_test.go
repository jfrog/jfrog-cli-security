package curation

import (
	"encoding/json"
	"fmt"
	"github.com/jfrog/gofrog/datastructures"
	coretests "github.com/jfrog/jfrog-cli-core/v2/common/tests"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	clienttestutils "github.com/jfrog/jfrog-client-go/utils/tests"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			tech:            coreutils.Npm.String(),
			wantDownloadUrl: "http://localhost:8000/artifactory/api/npm/npm/test/-/test-1.0.0.tgz",
			wantName:        "test",
			wantVersion:     "1.0.0",
		},
		{
			name:            "npm component with scope",
			componentId:     "npm://dev/test:1.0.0",
			artiUrl:         "http://localhost:8000/artifactory",
			repo:            "npm",
			tech:            coreutils.Npm.String(),
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
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			currentDir, err := os.Getwd()
			assert.NoError(t, err)
			configurationDir := tt.pathToTest
			callback := clienttestutils.SetEnvWithCallbackAndAssert(t, coreutils.HomeDir, filepath.Join(currentDir, configurationDir))
			defer callback()
			callback2 := clienttestutils.SetEnvWithCallbackAndAssert(t, "JFROG_CLI_CURATION_MAVEN", "true")
			defer callback2()
			mockServer, config := curationServer(t, tt.expectedBuildRequest, tt.expectedRequest, tt.requestToFail, tt.requestToError)
			defer mockServer.Close()
			configFilePath := WriteServerDetailsConfigFileBytes(t, config.ArtifactoryUrl, configurationDir)
			defer func() {
				assert.NoError(t, fileutils.RemoveTempDir(configFilePath))
			}()
			curationCmd := NewCurationAuditCommand()
			curationCmd.SetIsCurationCmd(true)
			curationCmd.parallelRequests = 3
			curationCmd.SetIgnoreConfigFile(tt.shouldIgnoreConfigFile)
			rootDir, err := os.Getwd()
			assert.NoError(t, err)
			// Set the working dir for npm project.
			require.NoError(t, err)
			if tt.preTestExec != "" {
				callbackPreTest := clienttestutils.ChangeDirWithCallback(t, rootDir, tt.pathToPreTest)
				_, err := exec.Command(tt.preTestExec, tt.funcToGetGoals(t)...).CombinedOutput()
				assert.NoError(t, err)
				callbackPreTest()
			}
			callback3 := clienttestutils.ChangeDirWithCallback(t, rootDir, strings.TrimSuffix(tt.pathToTest, "/.jfrog"))
			defer func() {
				cacheFolder, err := utils.GetCurationCacheFolder()
				require.NoError(t, err)
				assert.NoError(t, fileutils.RemoveTempDir(cacheFolder))
				callback3()
			}()
			results := map[string][]*PackageStatus{}
			if tt.requestToError == nil {
				assert.NoError(t, curationCmd.doCurateAudit(results))
			} else {
				gotError := curationCmd.doCurateAudit(results)
				assert.Error(t, gotError)
				startUrl := strings.Index(tt.expectedError, "/")
				assert.GreaterOrEqual(t, startUrl, 0)
				errMsgExpected := tt.expectedError[:startUrl] + config.ArtifactoryUrl +
					tt.expectedError[strings.Index(tt.expectedError, "/")+1:]
				assert.EqualError(t, gotError, errMsgExpected)
			}
			defer func() {
				if tt.cleanDependencies != nil {
					assert.NoError(t, tt.cleanDependencies())
				}
			}()
			// Add the mock server to the expected blocked message url
			for key := range tt.expectedResp {
				for index := range tt.expectedResp[key] {
					tt.expectedResp[key][index].BlockedPackageUrl = fmt.Sprintf("%s%s", strings.TrimSuffix(config.GetArtifactoryUrl(), "/"), tt.expectedResp[key][index].BlockedPackageUrl)
				}
			}
			assert.Equal(t, tt.expectedResp, results)
			for _, requestDone := range tt.expectedRequest {
				assert.True(t, requestDone)
			}
			for _, requestDone := range tt.expectedBuildRequest {
				assert.True(t, requestDone)
			}
		})
	}
}

type testCase struct {
	name                   string
	pathToTest             string
	pathToPreTest          string
	preTestExec            string
	funcToGetGoals         func(t *testing.T) []string
	shouldIgnoreConfigFile bool
	expectedBuildRequest   map[string]bool
	expectedRequest        map[string]bool
	requestToFail          map[string]bool
	expectedResp           map[string][]*PackageStatus
	requestToError         map[string]bool
	expectedError          string
	cleanDependencies      func() error
}

func getTestCasesForDoCurationAudit() []testCase {
	tests := []testCase{
		{
			name:          "maven tree - one blocked package",
			pathToPreTest: filepath.Join(TestDataDir, "projects", "package-managers", "maven", "maven-curation", "pretest"),
			preTestExec:   "mvn",
			funcToGetGoals: func(t *testing.T) []string {
				curationCache, err := utils.GetCurationMavenCacheFolder()
				require.NoError(t, err)
				return []string{"com.jfrog:maven-dep-tree:tree", "-DdepsTreeOutputFile=output", "-Dmaven.repo.local=" + curationCache}
			},
			pathToTest: filepath.Join(TestDataDir, "projects", "package-managers", "maven", "maven-curation", "test", ".jfrog"),
			expectedBuildRequest: map[string]bool{
				"/api/curation/audit/maven-remote/org/webjars/npm/underscore/1.13.6/underscore-1.13.6.pom": false,
			},
			cleanDependencies: func() error {
				return os.RemoveAll(filepath.Join(TestDataDir, "projects", "package-managers", "maven", "maven-curation",
					".jfrog", "curation", "cache", "maven", "org", "webjars", "npm"))
			},
			requestToFail: map[string]bool{
				"/maven-remote/org/webjars/npm/underscore/1.13.6/underscore-1.13.6.jar": false,
			},
			expectedResp: map[string][]*PackageStatus{
				"test:my-app:1.0.0": {
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
			},
			requestToError: nil,
			expectedError:  "",
		},
		{
			name:                   "npm tree - two blocked package ",
			pathToTest:             filepath.Join(TestDataDir, "projects", "package-managers", "npm", "npm-project", ".jfrog"),
			shouldIgnoreConfigFile: true,
			expectedRequest: map[string]bool{
				"/api/npm/npms/lightweight/-/lightweight-0.1.0.tgz": false,
				"/api/npm/npms/underscore/-/underscore-1.13.6.tgz":  false,
			},
			requestToFail: map[string]bool{
				"/api/npm/npms/underscore/-/underscore-1.13.6.tgz": false,
			},
			expectedResp: map[string][]*PackageStatus{
				"npm_test:1.0.0": {
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
			},
		},
		{
			name:                   "npm tree - two blocked one error",
			pathToTest:             filepath.Join(TestDataDir, "projects", "package-managers", "npm", "npm-project", ".jfrog"),
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
			expectedResp: map[string][]*PackageStatus{
				"npm_test:1.0.0": {
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
			},
			expectedError: fmt.Sprintf("failed sending HEAD request to %s for package '%s'. Status-code: %v. "+
				"Cause: executor timeout after 2 attempts with 0 milliseconds wait intervals",
				"/api/npm/npms/lightweight/-/lightweight-0.1.0.tgz", "lightweight:0.1.0", http.StatusInternalServerError),
		},
	}
	return tests
}

func curationServer(t *testing.T, expectedBuildRequest map[string]bool, expectedRequest map[string]bool, requestToFail map[string]bool, requestToError map[string]bool) (*httptest.Server, *config.ServerDetails) {
	mapLockReadWrite := sync.Mutex{}
	serverMock, config, _ := coretests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
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
			if _, exist := expectedBuildRequest[r.RequestURI]; exist {
				expectedBuildRequest[r.RequestURI] = true
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
	return serverMock, config
}

func WriteServerDetailsConfigFileBytes(t *testing.T, url string, configPath string) string {
	serverDetails := config.ConfigV5{
		Servers: []*config.ServerDetails{
			{
				User:           "admin",
				Password:       "password",
				ServerId:       "test",
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
