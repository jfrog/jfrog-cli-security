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
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
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
				WithArtifactLocation(sarif.NewArtifactLocation().WithURI("file://Package-Descriptor")),
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
				WithArtifactLocation(sarif.NewArtifactLocation().WithURI(fmt.Sprintf("file://%s", filepath.Join("dir", "file.txt")))),
			),
		},
		{
			name:      "Component with location and logical location",
			cmdType:   utils.DockerImage,
			component: formats.ComponentRow{Name: "sha256__3a8bca98bcad879bca98b9acd.tar"},
			expectedOutput: sarif.NewLocation().WithPhysicalLocation(sarif.NewPhysicalLocation().
				WithArtifactLocation(sarif.NewArtifactLocation().WithURI("file://Package-Descriptor")),
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
	assert.Equal(t, "[CVE-2022-1234] loadsh 1.4.1", getScaVulnerabilitySarifHeadline("loadsh", "1.4.1", "CVE-2022-1234", ""))
	assert.NotEqual(t, "[CVE-2022-1234] comp 1.4.1", getScaVulnerabilitySarifHeadline("comp", "1.2.1", "CVE-2022-1234", ""))
	assert.Equal(t, "[CVE-2022-1234] loadsh 1.4.1 (watch)", getScaVulnerabilitySarifHeadline("loadsh", "1.4.1", "CVE-2022-1234", "watch"))
	assert.NotEqual(t, "[CVE-2022-1234] comp 1.4.1", getScaVulnerabilitySarifHeadline("comp", "1.2.1", "CVE-2022-1234", "watch"))
}

func TestGetScaSecurityViolationSarifHeadline(t *testing.T) {
	assert.Equal(t, "Security Violation [CVE-2022-1234] loadsh 1.4.1", getScaSecurityViolationSarifHeadline("loadsh", "1.4.1", "CVE-2022-1234", ""))
	assert.NotEqual(t, "[CVE-2022-1234] comp 1.2.1", getScaSecurityViolationSarifHeadline("comp", "1.2.1", "CVE-2022-1234", ""))
	assert.Equal(t, "[CVE-2022-1234] loadsh 1.4.1 (watch)", getScaSecurityViolationSarifHeadline("loadsh", "1.4.1", "CVE-2022-1234", "watch"))
	assert.NotEqual(t, "[CVE-2022-1234] comp 1.2.1", getScaSecurityViolationSarifHeadline("comp", "1.2.1", "CVE-2022-1234", "watch"))
}

func TestGetXrayLicenseSarifHeadline(t *testing.T) {
	assert.Equal(t, "License violation [MIT] in loadsh 1.4.1", getXrayLicenseSarifHeadline("loadsh", "1.4.1", "MIT", ""))
	assert.NotEqual(t, "License violation [] in comp 1.2.1", getXrayLicenseSarifHeadline("comp", "1.2.1", "MIT", ""))
	assert.Equal(t, "[MIT] in loadsh 1.4.1 (watch)", getXrayLicenseSarifHeadline("loadsh", "1.4.1", "MIT", "watch"))
	assert.NotEqual(t, "License violation [] in comp 1.2.1", getXrayLicenseSarifHeadline("comp", "1.2.1", "MIT", "watch"))
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

func TestGetScaIssueSarifRule(t *testing.T) {
	impactPathsTC1 := [][]formats.ComponentRow{
		{
			{
				Name:    "example-package",
				Version: "1.0.0",
			},
			{
				Name:    "dependency1",
				Version: "1.0.0",
			},
		},
	}
	impactPathsTC2 := [][]formats.ComponentRow{
		{
			{
				Name:    "example-package",
				Version: "2.0.0",
			},
			{
				Name:    "dependency1",
				Version: "1.0.0",
			},
			{
				Name:    "dependency2",
				Version: "2.0.0",
			},
		},
	}
	impactPathsTC3 := [][]formats.ComponentRow{
		{
			{
				Name:    "example-package-1",
				Version: "1.0.0",
			},
			{
				Name:    "dependency1",
				Version: "1.0.0",
			},
		},
		{
			{
				Name:    "example-package-2",
				Version: "2.0.0",
			},
			{
				Name:    "dependency2",
				Version: "2.0.0",
			},
		},
	}
	testCases := []struct {
		name                string
		impactPaths         [][]formats.ComponentRow
		ruleId              string
		ruleDescription     string
		maxCveScore         string
		summary             string
		markdownDescription string
		expectedRule        *sarif.ReportingDescriptor
	}{
		{
			name:                "rule with impact paths",
			impactPaths:         impactPathsTC1,
			ruleId:              "rule-id-tc1",
			ruleDescription:     "rule-description-tc1",
			maxCveScore:         "7.5",
			summary:             "summary-tc1",
			markdownDescription: "markdown-description-tc1",
			expectedRule:        sarifutils.CreateDummyRule(impactPathsTC1, "rule-id-tc1", "rule-description-tc1", "summary-tc1", "markdown-description-tc1", "7.5"),
		},
		{
			name:                "rule with impact paths with multiple dependencies",
			impactPaths:         impactPathsTC2,
			ruleId:              "rule-id-tc2",
			ruleDescription:     "rule-description-tc2",
			maxCveScore:         "8.0",
			summary:             "summary-tc2",
			markdownDescription: "markdown-description-tc2",
			expectedRule:        sarifutils.CreateDummyRule(impactPathsTC2, "rule-id-tc2", "rule-description-tc2", "summary-tc2", "markdown-description-tc2", "8.0"),
		},
		{
			name:                "rule with multiple impact paths",
			impactPaths:         impactPathsTC3,
			ruleId:              "rule-id-tc3",
			ruleDescription:     "rule-description-tc3",
			maxCveScore:         "9.0",
			summary:             "summary-tc3",
			markdownDescription: "markdown-description-tc3",
			expectedRule:        sarifutils.CreateDummyRule(impactPathsTC3, "rule-id-tc3", "rule-description-tc3", "summary-tc3", "markdown-description-tc3", "9.0"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := getScaIssueSarifRule(tc.impactPaths, tc.ruleId, tc.ruleDescription, tc.maxCveScore, tc.summary, tc.markdownDescription)
			assert.Equal(t, tc.expectedRule, output)
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
		isJasViolations bool
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
				sarifutils.CreateRunWithDummyResultsInWd(fmt.Sprintf("file://%s", wd), sarifutils.CreateDummyResultInPath(fmt.Sprintf("file://%s", filepath.Join(wd, "dir", "file")))),
			},
			expectedResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWdWithHelp("rule-msg", "rule-markdown", fmt.Sprintf("file://%s", wd), sarifutils.CreateDummyResultInPath(filepath.ToSlash(filepath.Join("dir", "file")))),
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
				sarifutils.CreateRunWithDummyResultsInWdWithHelp("rule-msg", "rule-markdown", wd,
					sarifutils.CreateDummyResultWithPathAndLogicalLocation("sha256__f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "layer", "algorithm", "sha256").WithMessage(sarif.NewTextMessage("some-msg")),
				),
			},
			expectedResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultAndRuleInformation(
					sarifutils.CreateDummyResultWithFingerprint("some-msg\nImage: dockerImage:imageVersion\nLayer (sha256): f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "some-msg", jfrogFingerprintAlgorithmName, "9522c1d915eef55b4a0dc9e160bf5dc7",
						sarifutils.CreateDummyLocationWithPathAndLogicalLocation("sha256__f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "layer", "algorithm", "sha256"),
					),
					"rule-msg", "rule-markdown",
					[]string{"applicability"}, []string{"applicable"}).WithInvocations([]*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(wd))}),
				sarifutils.CreateRunWithDummyResultsInWdWithHelp("rule-msg", "rule-markdown", wd,
					sarifutils.CreateDummyResultWithFingerprint("some-msg\nImage: dockerImage:imageVersion\nLayer (sha256): f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "some-msg", jfrogFingerprintAlgorithmName, "9522c1d915eef55b4a0dc9e160bf5dc7",
						sarifutils.CreateDummyLocationWithPathAndLogicalLocation("sha256__f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "layer", "algorithm", "sha256"),
					),
				),
			},
		},
		{
			name:        "Docker image scan - with env vars (SCA)",
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
				sarifutils.CreateRunWithDummyResultsWithRuleInformation("", "", "rule-msg", "![](url/ui/api/v1/u?s=1&m=2&job_id=job-id&run_id=run-id&git_repo=repo&type=sca)\nrule-markdown", "rule-msg", "![](url/ui/api/v1/u?s=1&m=2&job_id=job-id&run_id=run-id&git_repo=repo&type=sca)\nrule-markdown", wd,
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
				sarifutils.CreateRunWithDummyResultsWithRuleInformation("", "", "rule-msg", "![](url/ui/api/v1/u?s=1&m=2&job_id=job-id&run_id=run-id&git_repo=repo&type=sca)\nrule-markdown", "rule-msg", "![](url/ui/api/v1/u?s=1&m=2&job_id=job-id&run_id=run-id&git_repo=repo&type=sca)\nrule-markdown", dockerfileDir,
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
				sarifutils.CreateRunWithDummyResultsWithRuleInformation(BinarySecretScannerToolName, "[Secret in Binary found] ", "rule-msg", "rule-markdown", "rule-msg", "rule-markdown", wd,
					sarifutils.CreateDummyResultWithFingerprint(fmt.Sprintf("🔒 Found Secrets in Binary docker scanning:\nImage: dockerImage:imageVersion\nLayer (sha1): 9e88ea9de1b44baba5e96a79e33e4af64334b2bf129e838e12f6dae71b5c86f0\nFilepath: %s\nEvidence: snippet", filepath.ToSlash(filepath.Join("usr", "src", "app", "server", "index.js"))), "result-msg", jfrogFingerprintAlgorithmName, "dee156c9fd75a4237102dc8fb29277a2",
						sarifutils.CreateDummyLocationWithPathAndLogicalLocation(filepath.ToSlash(filepath.Join("usr", "src", "app", "server", "index.js")), "9e88ea9de1b44baba5e96a79e33e4af64334b2bf129e838e12f6dae71b5c86f0", "layer", "algorithm", "sha1"),
					),
				),
			},
		},
		{
			name:        "Docker image scan - with env vars (Secrets)",
			target:      results.ScanTarget{Name: "dockerImage:imageVersion"},
			cmdType:     utils.DockerImage,
			subScan:     utils.SecretsScan,
			withEnvVars: true,
			input: []*sarif.Run{
				sarifutils.CreateRunNameWithResults("some tool name",
					sarifutils.CreateDummyResultInPath(fmt.Sprintf("file://%s", filepath.Join(wd, "unpacked", "filesystem", "blobs", "sha1", "9e88ea9de1b44baba5e96a79e33e4af64334b2bf129e838e12f6dae71b5c86f0", "usr", "src", "app", "server", "index.js"))),
				).WithInvocations([]*sarif.Invocation{
					sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(wd)),
				}),
			},
			expectedResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsWithRuleInformation(BinarySecretScannerToolName, "[Secret in Binary found] ", "rule-msg", "![](url/ui/api/v1/u?s=1&m=2&job_id=job-id&run_id=run-id&git_repo=repo&type=secrets)\nrule-markdown", "rule-msg", "![](url/ui/api/v1/u?s=1&m=2&job_id=job-id&run_id=run-id&git_repo=repo&type=secrets)\nrule-markdown", wd,
					sarifutils.CreateDummyResultWithFingerprint(fmt.Sprintf("🔒 Found Secrets in Binary docker scanning:\nGithub Actions Workflow: %s\nRun: 123\nImage: dockerImage:imageVersion\nLayer (sha1): 9e88ea9de1b44baba5e96a79e33e4af64334b2bf129e838e12f6dae71b5c86f0\nFilepath: %s\nEvidence: snippet", filepath.Join(GithubBaseWorkflowDir, "workflowFile.yml"), filepath.ToSlash(filepath.Join("usr", "src", "app", "server", "index.js"))), "result-msg", jfrogFingerprintAlgorithmName, "e721eacf317da6090eca3522308abd28",
						sarifutils.CreateDummyLocationWithPathAndLogicalLocation("", "9e88ea9de1b44baba5e96a79e33e4af64334b2bf129e838e12f6dae71b5c86f0", "layer", "algorithm", "sha1").WithPhysicalLocation(
							sarif.NewPhysicalLocation().WithArtifactLocation(sarif.NewSimpleArtifactLocation(filepath.Join(GithubBaseWorkflowDir, "workflowFile.yml"))),
						),
					),
				),
			},
		},
		{
			name:    "Binary scan - SCA",
			target:  results.ScanTarget{Target: filepath.Join(wd, "dir", "binary")},
			cmdType: utils.Binary,
			subScan: utils.ScaScan,
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(fmt.Sprintf("file://%s", wd),
					sarifutils.CreateDummyResultInPath(fmt.Sprintf("file://%s", filepath.Join(wd, "dir", "binary"))),
				),
			},
			expectedResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWdWithHelp("rule-msg", "rule-markdown", fmt.Sprintf("file://%s", wd),
					sarifutils.CreateDummyResultWithFingerprint("result-msg", "result-msg", jfrogFingerprintAlgorithmName, "e72a936dc73acbc4283a93230ff9b6e8", sarifutils.CreateDummyLocationInPath(filepath.ToSlash(filepath.Join("dir", "binary")))),
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
				sarifutils.CreateRunWithDummyResultsInWdWithHelp("rule-msg", "rule-markdown", wd,
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
				sarifutils.CreateRunWithDummyResultsInWd(fmt.Sprintf("file://%s", wd),
					sarifutils.CreateDummyResultInPathWithPartialFingerprint(fmt.Sprintf("file://%s", filepath.Join(wd, "dir", "file")), map[string]string{"jfrog-algo": "jfrog-algo-value"}),
					// No location, should be removed in the output
					sarifutils.CreateDummyResult("some-markdown", "some-other-msg", "rule", "level"),
				),
			},
			expectedResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWdWithHelp("rule-msg", "rule-markdown", fmt.Sprintf("file://%s", wd),
					sarifutils.CreateDummyResultInPathWithPartialFingerprint(filepath.ToSlash(filepath.Join("dir", "file")), map[string]string{"jfrog-algo": "jfrog-algo-value"}),
				),
			},
		},
		{
			name:            "Audit scan - Secrets violations",
			target:          results.ScanTarget{Target: wd},
			cmdType:         utils.SourceCode,
			subScan:         utils.SecretsScan,
			isJasViolations: true,
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(fmt.Sprintf("file://%s", wd),
					sarifutils.CreateDummyResultInPath(fmt.Sprintf("file://%s", filepath.Join(wd, "dir", "file"))),
				),
			},
			expectedResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsWithRuleInformation("", "[Security Violation] ", "rule-msg", "rule-markdown", "rule-msg", "rule-markdown", fmt.Sprintf("file://%s", wd),
					sarifutils.CreateDummyResult("Security Violation result-markdown", "result-msg", "rule", "level", sarifutils.CreateDummyLocationInPath(filepath.ToSlash(filepath.Join("dir", "file")))),
				),
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cleanUps := []func(){}
			if tc.withEnvVars {
				// Some content depends on env vars values
				cleanUps = append(cleanUps, clientTests.SetEnvWithCallbackAndAssert(t, CurrentWorkflowNameEnvVar, "workflow name"))
				cleanUps = append(cleanUps, clientTests.SetEnvWithCallbackAndAssert(t, CurrentWorkflowRunNumberEnvVar, "123"))
				cleanUps = append(cleanUps, clientTests.SetEnvWithCallbackAndAssert(t, utils.JfrogExternalJobIdEnv, "job-id"))
				cleanUps = append(cleanUps, clientTests.SetEnvWithCallbackAndAssert(t, utils.JfrogExternalRunIdEnv, "run-id"))
				cleanUps = append(cleanUps, clientTests.SetEnvWithCallbackAndAssert(t, utils.JfrogExternalGitRepoEnv, "repo"))
			} else {
				// Since some of the env vars are provided by the test in GitHub Actions, we need to clean them up before running the test
				cleanUps = append(cleanUps, clientTests.SetEnvWithCallbackAndAssert(t, CurrentWorkflowNameEnvVar, ""))
				cleanUps = append(cleanUps, clientTests.SetEnvWithCallbackAndAssert(t, CurrentWorkflowRunNumberEnvVar, ""))
			}
			defer func() {
				for _, cleanUp := range cleanUps {
					cleanUp()
				}
			}()
			if tc.withDockerfile {
				revertWd := clientTests.ChangeDirWithCallback(t, wd, dockerfileDir)
				defer revertWd()
			}
			patchedRuns := patchRunsToPassIngestionRules("url/", tc.cmdType, tc.subScan, true, tc.isJasViolations, tc.target, tc.input...)
			assert.ElementsMatch(t, tc.expectedResults, patchedRuns)
		})
	}
}
