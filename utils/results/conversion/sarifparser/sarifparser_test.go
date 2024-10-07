package sarifparser

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/build-info-go/tests"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
)

func TestGetComponentSarifLocation(t *testing.T) {
	testCases := []struct {
		name           string
		cmdType        utils.CommandType
		component      formats.ComponentRow
		expectedOutput *sarif.Location
	}{
		{
			name: "Component with name and version",
			component: formats.ComponentRow{
				Name:    "example-package",
				Version: "1.0.0",
			},
			expectedOutput: sarif.NewLocation().WithPhysicalLocation(sarif.NewPhysicalLocation().
				WithArtifactLocation(sarif.NewArtifactLocation().WithUri("file://Package-Descriptor")),
			),
		},
		{
			name: "Component with location",
			component: formats.ComponentRow{
				Name:     "example-package",
				Version:  "1.0.0",
				Location: &formats.Location{File: filepath.Join("dir", "file.txt")},
			},
			expectedOutput: sarif.NewLocation().WithPhysicalLocation(sarif.NewPhysicalLocation().
				WithArtifactLocation(sarif.NewArtifactLocation().WithUri(fmt.Sprintf("file://%s", filepath.Join("dir", "file.txt")))),
			),
		},
		{
			name:      "Component with location and logical location",
			cmdType:   utils.DockerImage,
			component: formats.ComponentRow{Name: "sha256__3a8bca98bcad879bca98b9acd.tar"},
			expectedOutput: sarif.NewLocation().WithPhysicalLocation(sarif.NewPhysicalLocation().
				WithArtifactLocation(sarif.NewArtifactLocation().WithUri("file://Package-Descriptor")),
			).WithLogicalLocations([]*sarif.LogicalLocation{sarifutils.CreateLogicalLocationWithProperty("3a8bca98bcad879bca98b9acd", "layer", "algorithm", "sha256")}),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedOutput, getComponentSarifLocation(tc.cmdType, tc.component))
		})
	}
}

func TestGetVulnerabilityOrViolationSarifHeadline(t *testing.T) {
	assert.Equal(t, "[CVE-2022-1234] loadsh 1.4.1", getScaIssueSarifHeadline("loadsh", "1.4.1", "CVE-2022-1234"))
	assert.NotEqual(t, "[CVE-2022-1234] comp 1.4.1", getScaIssueSarifHeadline("comp", "1.2.1", "CVE-2022-1234"))
}

func TestGetXrayLicenseSarifHeadline(t *testing.T) {
	assert.Equal(t, "License violation [MIT] in loadsh 1.4.1", getXrayLicenseSarifHeadline("loadsh", "1.4.1", "MIT"))
	assert.NotEqual(t, "License violation [] in comp 1.2.1", getXrayLicenseSarifHeadline("comp", "1.2.1", "MIT"))
}

func TestGetLicenseViolationSummary(t *testing.T) {
	assert.Equal(t, "Dependency loadsh version 1.4.1 is using a license (MIT) that is not allowed.", getLicenseViolationSummary("loadsh", "1.4.1", "MIT"))
	assert.NotEqual(t, "Dependency comp version 1.2.1 is using a license () that is not allowed.", getLicenseViolationSummary("comp", "1.2.1", "MIT"))
}

func TestGetSarifTableDescription(t *testing.T) {
	testCases := []struct {
		name                string
		directDependencies  []formats.ComponentRow
		cveScore            string
		applicableStatus    jasutils.ApplicabilityStatus
		fixedVersions       []string
		expectedDescription string
	}{
		{
			name: "Applicable vulnerability",
			directDependencies: []formats.ComponentRow{
				{Name: "example-package", Version: "1.0.0"},
			},
			cveScore:            "7.5",
			applicableStatus:    jasutils.Applicable,
			fixedVersions:       []string{"1.0.1", "1.0.2"},
			expectedDescription: "| Severity Score | Contextual Analysis | Direct Dependencies | Fixed Versions     |\n|  :---:  |  :---:  |  :---:  |  :---:  |\n| 7.5      | Applicable       | `example-package 1.0.0`       | 1.0.1, 1.0.2   |",
		},
		{
			name: "Not-scanned vulnerability",
			directDependencies: []formats.ComponentRow{
				{Name: "example-package", Version: "2.0.0"},
			},
			cveScore:            "6.2",
			applicableStatus:    jasutils.NotScanned,
			fixedVersions:       []string{"2.0.1"},
			expectedDescription: "| Severity Score | Direct Dependencies | Fixed Versions     |\n| :---:        |    :----:   |          :---: |\n| 6.2      | `example-package 2.0.0`       | 2.0.1   |",
		},
		{
			name: "No fixed versions",
			directDependencies: []formats.ComponentRow{
				{Name: "example-package", Version: "3.0.0"},
			},
			cveScore:            "3.0",
			applicableStatus:    jasutils.NotScanned,
			fixedVersions:       []string{},
			expectedDescription: "| Severity Score | Direct Dependencies | Fixed Versions     |\n| :---:        |    :----:   |          :---: |\n| 3.0      | `example-package 3.0.0`       | No fix available   |",
		},
		{
			name: "Not-covered vulnerability",
			directDependencies: []formats.ComponentRow{
				{Name: "example-package", Version: "3.0.0"},
			},
			cveScore:            "3.0",
			applicableStatus:    jasutils.NotCovered,
			fixedVersions:       []string{"3.0.1"},
			expectedDescription: "| Severity Score | Contextual Analysis | Direct Dependencies | Fixed Versions     |\n|  :---:  |  :---:  |  :---:  |  :---:  |\n| 3.0      | Not Covered       | `example-package 3.0.0`       | 3.0.1   |",
		},
		{
			name: "Undetermined vulnerability",
			directDependencies: []formats.ComponentRow{
				{Name: "example-package", Version: "3.0.0"},
			},
			cveScore:            "3.0",
			applicableStatus:    jasutils.ApplicabilityUndetermined,
			fixedVersions:       []string{"3.0.1"},
			expectedDescription: "| Severity Score | Contextual Analysis | Direct Dependencies | Fixed Versions     |\n|  :---:  |  :---:  |  :---:  |  :---:  |\n| 3.0      | Undetermined       | `example-package 3.0.0`       | 3.0.1   |",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := getScaIssueMarkdownDescription(tc.directDependencies, tc.cveScore, tc.applicableStatus, tc.fixedVersions)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedDescription, output)
		})
	}
}

func TestGetDirectDependenciesFormatted(t *testing.T) {
	testCases := []struct {
		name           string
		directDeps     []formats.ComponentRow
		expectedOutput string
	}{
		{
			name: "Single direct dependency",
			directDeps: []formats.ComponentRow{
				{Name: "example-package", Version: "1.0.0"},
			},
			expectedOutput: "`example-package 1.0.0`",
		},
		{
			name: "Multiple direct dependencies",
			directDeps: []formats.ComponentRow{
				{Name: "dependency1", Version: "1.0.0"},
				{Name: "dependency2", Version: "2.0.0"},
			},
			expectedOutput: "`dependency1 1.0.0`<br/>`dependency2 2.0.0`",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := getDirectDependenciesFormatted(tc.directDeps)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}

func TestGetScaLicenseViolationMarkdown(t *testing.T) {
	testCases := []struct {
		name               string
		license            string
		impactedDepName    string
		impactedDepVersion string
		directDeps         []formats.ComponentRow
		expectedOutput     string
	}{
		{
			name:               "Single direct dependency",
			license:            "MIT",
			impactedDepName:    "example-package",
			impactedDepVersion: "1.0.0",
			directDeps: []formats.ComponentRow{
				{Name: "dependency1", Version: "1.0.0"},
			},
			expectedOutput: "Dependency example-package version 1.0.0 is using a license (MIT) that is not allowed.<br/>Direct dependencies:<br/>`dependency1 1.0.0`",
		},
		{
			name:               "Multiple direct dependencies",
			license:            "MIT",
			impactedDepName:    "example-package",
			impactedDepVersion: "1.0.0",
			directDeps: []formats.ComponentRow{
				{Name: "dependency1", Version: "1.0.0"},
				{Name: "dependency2", Version: "2.0.0"},
			},
			expectedOutput: "Dependency example-package version 1.0.0 is using a license (MIT) that is not allowed.<br/>Direct dependencies:<br/>`dependency1 1.0.0`<br/>`dependency2 2.0.0`",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := getScaLicenseViolationMarkdown(tc.impactedDepName, tc.impactedDepVersion, tc.license, tc.directDeps)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}

func TestGetLayerContentFromComponentId(t *testing.T) {
	testCases := []struct {
		name              string
		path              string
		expectedAlgorithm string
		expectedLayerHash string
	}{
		{
			name:              "Valid path",
			path:              "sha256__cedb364ef937c7e51179d8e514bdd98644bac5fdc82a45d784ef91afe4bc647e.tar",
			expectedAlgorithm: "sha256",
			expectedLayerHash: "cedb364ef937c7e51179d8e514bdd98644bac5fdc82a45d784ef91afe4bc647e",
		},
		{
			name: "Invalid path - not hex",
			path: "sha256__NOT_HEX.tar",
		},
		{
			name: "Invalid path - no algorithm",
			path: "_cedb364ef937c7e51179d8e514bdd98644bac5fdc82a45d784ef91afe4bc647e.tar",
		},
		{
			name: "Invalid path - no suffix",
			path: "sha256__cedb364ef937c7e51179d8e514bdd98644bac5fdc82a45d784ef91afe4bc647e",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			algorithm, layerHash := getLayerContentFromComponentId(tc.path)
			assert.Equal(t, tc.expectedAlgorithm, algorithm)
			assert.Equal(t, tc.expectedLayerHash, layerHash)
		})
	}
}

func preparePatchTestEnv(t *testing.T) (string, string, func()) {
	currentWd, err := os.Getwd()
	assert.NoError(t, err)
	wd, cleanUpTempDir := tests.CreateTempDirWithCallbackAndAssert(t)
	cleanUpWd := clientTests.ChangeDirWithCallback(t, currentWd, wd)
	dockerfileDir := filepath.Join(wd, "DockerfileDir")
	err = fileutils.CreateDirIfNotExist(dockerfileDir)
	// Prepare env content
	assert.NoError(t, err)
	createDummyDockerfile(t, dockerfileDir)
	createDummyGithubWorkflow(t, dockerfileDir)
	createDummyGithubWorkflow(t, wd)
	return wd, dockerfileDir, func() {
		cleanUpWd()
		cleanUpTempDir()
	}
}

func createDummyGithubWorkflow(t *testing.T, baseDir string) {
	assert.NoError(t, fileutils.CreateDirIfNotExist(filepath.Join(baseDir, GithubBaseWorkflowDir)))
	assert.NoError(t, os.WriteFile(filepath.Join(baseDir, GithubBaseWorkflowDir, "workflowFile.yml"), []byte("workflow name"), 0644))
}

func createDummyDockerfile(t *testing.T, baseDir string) {
	assert.NoError(t, os.WriteFile(filepath.Join(baseDir, "Dockerfile"), []byte("Dockerfile data"), 0644))
}

func TestPatchRunsToPassIngestionRules(t *testing.T) {
	wd, dockerfileDir, cleanUp := preparePatchTestEnv(t)
	defer cleanUp()

	testCases := []struct {
		name            string
		target          results.ScanTarget
		cmdType         utils.CommandType
		subScan         utils.SubScanType
		withEnvVars     bool
		withDockerfile  bool
		input           []*sarif.Run
		expectedResults []*sarif.Run
	}{
		{
			name:            "No runs",
			target:          results.ScanTarget{Name: "dockerImage:imageVersion"},
			cmdType:         utils.DockerImage,
			subScan:         utils.SecretsScan,
			input:           []*sarif.Run{},
			expectedResults: []*sarif.Run{},
		},
		{
			name:    "Build scan - SCA",
			target:  results.ScanTarget{Name: "buildName (buildNumber)"},
			cmdType: utils.Build,
			subScan: utils.ScaScan,
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd, sarifutils.CreateDummyResultInPath(fmt.Sprintf("file://%s", filepath.Join(wd, "dir", "file")))),
			},
			expectedResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd, sarifutils.CreateDummyResultInPath(filepath.Join("dir", "file"))),
			},
		},
		{
			name:    "Docker image scan - SCA",
			target:  results.ScanTarget{Name: "dockerImage:imageVersion"},
			cmdType: utils.DockerImage,
			subScan: utils.ScaScan,
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultAndRuleProperties(
					sarifutils.CreateDummyResultWithPathAndLogicalLocation("sha256__f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "layer", "algorithm", "sha256").WithMessage(sarif.NewTextMessage("some-msg")),
					[]string{"applicability"}, []string{"applicable"}).WithInvocations([]*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(wd))}),
				sarifutils.CreateRunWithDummyResultsInWd(wd,
					sarifutils.CreateDummyResultWithPathAndLogicalLocation("sha256__f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "layer", "algorithm", "sha256").WithMessage(sarif.NewTextMessage("some-msg")),
				),
			},
			expectedResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultAndRuleProperties(
					sarifutils.CreateDummyResultWithFingerprint("some-msg\nImage: dockerImage:imageVersion\nLayer (sha256): f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "some-msg", jfrogFingerprintAlgorithmName, "9522c1d915eef55b4a0dc9e160bf5dc7",
						sarifutils.CreateDummyLocationWithPathAndLogicalLocation("sha256__f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "layer", "algorithm", "sha256"),
					),
					[]string{"applicability"}, []string{"applicable"}).WithInvocations([]*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(wd))}),
				sarifutils.CreateRunWithDummyResultsInWd(wd,
					sarifutils.CreateDummyResultWithFingerprint("some-msg\nImage: dockerImage:imageVersion\nLayer (sha256): f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "some-msg", jfrogFingerprintAlgorithmName, "9522c1d915eef55b4a0dc9e160bf5dc7",
						sarifutils.CreateDummyLocationWithPathAndLogicalLocation("sha256__f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "layer", "algorithm", "sha256"),
					),
				),
			},
		},
		{
			name:        "Docker image scan - with env vars",
			target:      results.ScanTarget{Name: "dockerImage:imageVersion"},
			cmdType:     utils.DockerImage,
			subScan:     utils.ScaScan,
			withEnvVars: true,
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd,
					sarifutils.CreateDummyResultWithPathAndLogicalLocation("sha256__f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "layer", "algorithm", "sha256").WithMessage(sarif.NewTextMessage("some-msg")),
					// No location, should be removed in the output
					sarifutils.CreateDummyResult("some-markdown", "some-other-msg", "rule", "level"),
				),
			},
			expectedResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd,
					sarifutils.CreateDummyResultWithFingerprint(fmt.Sprintf("some-msg\nGithub Actions Workflow: %s\nRun: 123\nImage: dockerImage:imageVersion\nLayer (sha256): f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", filepath.Join(GithubBaseWorkflowDir, "workflowFile.yml")), "some-msg", jfrogFingerprintAlgorithmName, "eda26ae830c578197aeda65a82d7f093",
						sarifutils.CreateDummyLocationWithPathAndLogicalLocation("", "f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "layer", "algorithm", "sha256").WithPhysicalLocation(
							sarif.NewPhysicalLocation().WithArtifactLocation(sarif.NewSimpleArtifactLocation(filepath.Join(GithubBaseWorkflowDir, "workflowFile.yml"))),
						),
					),
				),
			},
		},
		{
			name:           "Docker image scan - with Dockerfile in wd",
			target:         results.ScanTarget{Name: "dockerImage:imageVersion"},
			cmdType:        utils.DockerImage,
			subScan:        utils.ScaScan,
			withEnvVars:    true,
			withDockerfile: true,
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(dockerfileDir,
					sarifutils.CreateDummyResultWithPathAndLogicalLocation("sha256__f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "layer", "algorithm", "sha256").WithMessage(sarif.NewTextMessage("some-msg")),
				),
			},
			expectedResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(dockerfileDir,
					sarifutils.CreateDummyResultWithFingerprint(fmt.Sprintf("some-msg\nGithub Actions Workflow: %s\nRun: 123\nImage: dockerImage:imageVersion\nLayer (sha256): f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", filepath.Join(GithubBaseWorkflowDir, "workflowFile.yml")), "some-msg", jfrogFingerprintAlgorithmName, "8cbd7268a4d20f2358ba2667ebd18956",
						sarifutils.CreateDummyLocationWithPathAndLogicalLocation("", "f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "layer", "algorithm", "sha256").WithPhysicalLocation(
							sarif.NewPhysicalLocation().WithArtifactLocation(sarif.NewSimpleArtifactLocation("Dockerfile")),
						),
					),
				),
			},
		},
		{
			name:    "Docker image scan - Secrets",
			target:  results.ScanTarget{Name: "dockerImage:imageVersion"},
			cmdType: utils.DockerImage,
			subScan: utils.SecretsScan,
			input: []*sarif.Run{
				sarifutils.CreateRunNameWithResults("some tool name",
					sarifutils.CreateDummyResultInPath(fmt.Sprintf("file://%s", filepath.Join(wd, "unpacked", "filesystem", "blobs", "sha1", "9e88ea9de1b44baba5e96a79e33e4af64334b2bf129e838e12f6dae71b5c86f0", "usr", "src", "app", "server", "index.js"))),
				).WithInvocations([]*sarif.Invocation{
					sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(wd)),
				}),
			},
			expectedResults: []*sarif.Run{
				{
					Tool: sarif.Tool{
						Driver: sarifutils.CreateDummyDriver(BinarySecretScannerToolName, &sarif.ReportingDescriptor{
							ID:               "rule",
							ShortDescription: sarif.NewMultiformatMessageString("[Secret in Binary found] "),
						}),
					},
					Invocations: []*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(wd))},
					Results: []*sarif.Result{
						sarifutils.CreateDummyResultWithFingerprint(fmt.Sprintf("🔒 Found Secrets in Binary docker scanning:\nImage: dockerImage:imageVersion\nLayer (sha1): 9e88ea9de1b44baba5e96a79e33e4af64334b2bf129e838e12f6dae71b5c86f0\nFilepath: %s\nEvidence: snippet", filepath.Join("usr", "src", "app", "server", "index.js")), "", jfrogFingerprintAlgorithmName, "93d660ebfd39b1220c42c0beb6e4e863",
							sarifutils.CreateDummyLocationWithPathAndLogicalLocation(filepath.Join("usr", "src", "app", "server", "index.js"), "9e88ea9de1b44baba5e96a79e33e4af64334b2bf129e838e12f6dae71b5c86f0", "layer", "algorithm", "sha1"),
						),
					},
				},
			},
		},
		{
			name:    "Binary scan - SCA",
			target:  results.ScanTarget{Target: filepath.Join(wd, "dir", "binary")},
			cmdType: utils.Binary,
			subScan: utils.ScaScan,
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd,
					sarifutils.CreateDummyResultInPath(fmt.Sprintf("file://%s", filepath.Join(wd, "dir", "binary"))),
				),
			},
			expectedResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd,
					sarifutils.CreateDummyResultWithFingerprint("", "", jfrogFingerprintAlgorithmName, "e72a936dc73acbc4283a93230ff9b6e8", sarifutils.CreateDummyLocationInPath(filepath.Join("dir", "binary"))),
				),
			},
		},
		{
			name:    "Audit scan - SCA",
			target:  results.ScanTarget{Target: wd},
			cmdType: utils.SourceCode,
			subScan: utils.ScaScan,
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd,
					sarifutils.CreateDummyResultInPath(filepath.Join(wd, "Package-Descriptor")),
					// No location, should be removed in the output
					sarifutils.CreateDummyResult("some-markdown", "some-other-msg", "rule", "level"),
				),
			},
			expectedResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd,
					sarifutils.CreateDummyResultInPath("Package-Descriptor"),
				),
			},
		},
		{
			name:    "Audit scan - Secrets",
			target:  results.ScanTarget{Target: wd},
			cmdType: utils.SourceCode,
			subScan: utils.SecretsScan,
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd,
					sarifutils.CreateDummyResultInPath(fmt.Sprintf("file://%s", filepath.Join(wd, "dir", "file"))),
					// No location, should be removed in the output
					sarifutils.CreateDummyResult("some-markdown", "some-other-msg", "rule", "level"),
				),
			},
			expectedResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd,
					sarifutils.CreateDummyResultInPath(filepath.Join("dir", "file")),
				),
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.withEnvVars {
				cleanFileEnv := clientTests.SetEnvWithCallbackAndAssert(t, CurrentWorkflowNameEnvVar, "workflow name")
				defer cleanFileEnv()
				cleanRunNumEnv := clientTests.SetEnvWithCallbackAndAssert(t, CurrentWorkflowRunNumberEnvVar, "123")
				defer cleanRunNumEnv()
			} else {
				// Since the the env are provided by the
				cleanFileEnv := clientTests.SetEnvWithCallbackAndAssert(t, CurrentWorkflowNameEnvVar, "")
				defer cleanFileEnv()
				cleanRunNumEnv := clientTests.SetEnvWithCallbackAndAssert(t, CurrentWorkflowRunNumberEnvVar, "")
				defer cleanRunNumEnv()
			}
			if tc.withDockerfile {
				revertWd := clientTests.ChangeDirWithCallback(t, wd, dockerfileDir)
				defer revertWd()
			}
			patchedRuns := patchRunsToPassIngestionRules(tc.cmdType, tc.subScan, true, tc.target, tc.input...)
			assert.ElementsMatch(t, tc.expectedResults, patchedRuns)
		})
	}
}
