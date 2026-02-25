package curation

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/techutils"

	gotech "github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/go"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/npm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectInstallHandler(t *testing.T) {
	originalDir, err := os.Getwd()
	require.NoError(t, err)
	defer func() { require.NoError(t, os.Chdir(originalDir)) }()

	tests := []struct {
		name          string
		files         map[string]string
		expectedType  interface{}
		expectError   bool
		errorContains string
	}{
		{
			name: "detect npm from package.json",
			files: map[string]string{
				"package.json": `{"name": "test-project", "version": "1.0.0"}`,
			},
			expectedType: &npm.NpmInstallHandler{},
		},
		{
			name: "detect go from go.mod",
			files: map[string]string{
				"go.mod": "module example.com/test\n\ngo 1.21\n",
			},
			expectedType: &gotech.GoInstallHandler{},
		},
		{
			name:          "no supported technology detected",
			files:         map[string]string{},
			expectError:   true,
			errorContains: "could not detect a supported technology",
		},
		{
			name: "unsupported technology only (e.g. Python)",
			files: map[string]string{
				"requirements.txt": "flask==2.0.0\n",
			},
			expectError:   true,
			errorContains: "could not detect a supported technology",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			for name, content := range tt.files {
				require.NoError(t, os.WriteFile(filepath.Join(tempDir, name), []byte(content), 0644))
			}
			require.NoError(t, os.Chdir(tempDir))

			handler, err := detectInstallHandler()

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, handler)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.IsType(t, tt.expectedType, handler)
			}
		})
	}
}

func TestGetSupportedInstallTechnologies(t *testing.T) {
	techs := getSupportedInstallTechnologies()
	assert.Len(t, techs, len(installHandlers))
	for tech := range installHandlers {
		assert.Contains(t, techs, tech.ToFormal())
	}
}

func TestInstallModeFiltersAuditResults(t *testing.T) {
	basePathToTests, err := filepath.Abs(TestDataDir)
	require.NoError(t, err)

	cleanUpFlags := setCurationFlagsForTest(t)
	defer cleanUpFlags()

	tests := []testCase{
		{
			name:                   "npm install mode - only audits installed package",
			tech:                   techutils.Npm,
			pathToProject:          filepath.Join("projects", "package-managers", "npm", "npm-project"),
			shouldIgnoreConfigFile: true,
			installPackage:         "underscore@1.13.6",
			expectedRequest: map[string]bool{
				"/api/npm/npms/underscore/-/underscore-1.13.6.tgz": false,
			},
			requestToFail: map[string]bool{
				"/api/npm/npms/underscore/-/underscore-1.13.6.tgz": false,
			},
			expectedResp: map[string]*CurationReport{
				"npm_test:1.0.0": {
					packagesStatus: []*PackageStatus{
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
			name:                     "go install mode - only audits installed package and its transitives",
			tech:                     techutils.Go,
			pathToProject:            filepath.Join("projects", "package-managers", "go", "curation-project"),
			createServerWithoutCreds: true,
			installPackage:           "rsc.io/quote@v1.5.2",
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
				"/api/go/go-virtual/rsc.io/quote/@v/v1.5.2.zip": false,
			},
			expectedResp: map[string]*CurationReport{
				"github.com/you/hello": {
					packagesStatus: []*PackageStatus{
						{
							Action:            "blocked",
							ParentName:        "rsc.io/quote",
							ParentVersion:     "v1.5.2",
							BlockedPackageUrl: "/api/go/go-virtual/rsc.io/quote/@v/v1.5.2.zip",
							PackageName:       "rsc.io/quote",
							PackageVersion:    "v1.5.2",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockServer, serverConfig := curationServer(t, tt.expectedBuildRequest, tt.expectedRequest, tt.requestToFail, tt.requestToError, tt.serveResources)
			defer mockServer.Close()

			cleanUp := createCurationTestEnv(t, basePathToTests, tt, serverConfig)
			defer cleanUp()

			results, err := createCurationCmdAndRun(tt)
			assert.NoError(t, err)

			for key := range tt.expectedResp {
				for index := range tt.expectedResp[key].packagesStatus {
					tt.expectedResp[key].packagesStatus[index].BlockedPackageUrl = fmt.Sprintf("%s%s",
						strings.TrimSuffix(serverConfig.GetArtifactoryUrl(), "/"),
						tt.expectedResp[key].packagesStatus[index].BlockedPackageUrl)
				}
			}
			assert.Equal(t, tt.expectedResp, results)

			for _, requestDone := range tt.expectedRequest {
				assert.True(t, requestDone)
			}
		})
	}
}
