package runner

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-core/v2/common/cliutils"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/jas/applicability"
	"github.com/jfrog/jfrog-cli-security/jas/secrets"
	testUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/stretchr/testify/assert"
)

func TestJasRunner_AnalyzerManagerNotExist(t *testing.T) {
	tmpDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()
	assert.NoError(t, os.Setenv(coreutils.HomeDir, tmpDir))
	defer func() {
		assert.NoError(t, os.Unsetenv(coreutils.HomeDir))
	}()
	scanner, err := jas.NewJasScanner(&jas.FakeServerDetails)
	assert.NoError(t, err)
	if scanner.AnalyzerManager.AnalyzerManagerFullPath, err = jas.GetAnalyzerManagerExecutable(); err != nil {
		return
	}
	assert.Error(t, err)
	assert.NotNil(t, scanner)
	assert.ErrorContains(t, err, "unable to locate the analyzer manager package. Advanced security scans cannot be performed without this package")
}

func TestShouldFetchIndirectCvePaths(t *testing.T) {
	newTargetResultsWithSbom := func(withSbom bool) *results.TargetResults {
		targetResults := results.NewCommandResults(utils.SourceCode).NewScanResults(results.ScanTarget{Target: "target"})
		if withSbom {
			targetResults.SetSbom(cyclonedx.NewBOM())
		}
		return targetResults
	}

	testCases := []struct {
		name           string
		newFlow        bool
		entitled       bool
		indirectCves   []string
		scanResults    *results.TargetResults
		expectedResult bool
	}{
		{
			name:           "V2 flow - not fetched even when entitled with cves and sbom",
			newFlow:        false,
			entitled:       true,
			indirectCves:   []string{"CVE-2024-1234"},
			scanResults:    newTargetResultsWithSbom(true),
			expectedResult: false,
		},
		{
			name:           "not entitled - not fetched even on new flow with cves and sbom",
			newFlow:        true,
			entitled:       false,
			indirectCves:   []string{"CVE-2024-1234"},
			scanResults:    newTargetResultsWithSbom(true),
			expectedResult: false,
		},
		{
			name:           "no indirect cves - not fetched",
			newFlow:        true,
			entitled:       true,
			indirectCves:   nil,
			scanResults:    newTargetResultsWithSbom(true),
			expectedResult: false,
		},
		{
			name:           "no sca results - not fetched",
			newFlow:        true,
			entitled:       true,
			indirectCves:   []string{"CVE-2024-1234"},
			scanResults:    results.NewCommandResults(utils.SourceCode).NewScanResults(results.ScanTarget{Target: "target"}),
			expectedResult: false,
		},
		{
			name:           "sca results with no sbom - not fetched",
			newFlow:        true,
			entitled:       true,
			indirectCves:   []string{"CVE-2024-1234"},
			scanResults:    newTargetResultsWithSbom(false),
			expectedResult: false,
		},
		{
			name:           "new flow, entitled, indirect cves and sbom - fetched",
			newFlow:        true,
			entitled:       true,
			indirectCves:   []string{"CVE-2024-1234"},
			scanResults:    newTargetResultsWithSbom(true),
			expectedResult: true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			params := &JasRunnerParams{
				V3Flow:                              testCase.newFlow,
				TransitiveContextualAnalysisEnabled: testCase.entitled,
				ScanResults:                         testCase.scanResults,
			}
			assert.Equal(t, testCase.expectedResult, shouldFetchIndirectCvePaths(params, testCase.indirectCves))
		})
	}
}

func TestJasRunner(t *testing.T) {
	assert.NoError(t, testUtils.PrepareAnalyzerManagerResource())
	securityParallelRunnerForTest := utils.CreateSecurityParallelRunner(cliutils.Threads)
	targetResults := results.NewCommandResults(utils.SourceCode).SetEntitledForJas(true).SetSecretValidation(true).NewScanResults(results.ScanTarget{Target: "target", Technologies: []techutils.Technology{techutils.Pip}})

	jasScanner, err := jas.NewJasScanner(&jas.FakeServerDetails, jas.WithEnvVars(jas.NotDiffScanEnvValue, jas.GetAnalyzerManagerXscEnvVars(false, "", "", "", "", []string{}, targetResults.GetTechnologies()...)))
	assert.NoError(t, err)
	jasScanner.AnalyzerManager.AnalyzerManagerFullPath, err = jas.GetAnalyzerManagerExecutable()
	assert.NoError(t, err)

	targetResults.ScaScanResults(0, jas.FakeBasicXrayResults[0])
	directComponents := []string{"issueId_1_direct_dependency", "issueId_2_direct_dependency"}
	testParams := JasRunnerParams{
		Runner:             securityParallelRunnerForTest,
		Scanner:            jasScanner,
		ScanResults:        targetResults,
		ScansToPerform:     utils.GetAllSupportedScans(),
		ApplicableScanType: applicability.ApplicabilityScannerType,
		SecretsScanType:    secrets.SecretsScannerType,
		CvesProvider: func() (directCves []string, indirectCves []string) {
			return results.ExtractCvesFromScanResponse(targetResults.GetScaScansXrayResults(), directComponents)
		},
	}
	assert.NoError(t, AddJasScannersTasks(testParams))
}

func TestJasRunner_Module_AnalyzerManagerReturnsError(t *testing.T) {
	assert.NoError(t, testUtils.PrepareAnalyzerManagerResource())

	jfrogAppsConfigForTest, _ := jas.CreateJFrogAppsConfig(nil)
	scanner, _ := jas.NewJasScanner(&jas.FakeServerDetails)
	directCves, indirectCves := results.ExtractCvesFromScanResponse(jas.FakeBasicXrayResults, []string{"issueId_2_direct_dependency", "issueId_1_direct_dependency"})
	_, err := applicability.RunApplicabilityScan(
		applicability.ContextualAnalysisScanParams{
			DirectDependenciesCves:   directCves,
			IndirectDependenciesCves: indirectCves,
			ScanType:                 applicability.ApplicabilityScannerType,
			Target:                   results.ScanTarget{Target: "target", DeprecatedAppsConfigModule: &jfrogAppsConfigForTest.Modules[0]},
		},
		scanner,
	)
	// Expect error:
	assert.ErrorContains(t, jas.ParseAnalyzerManagerError(jasutils.Applicability, err), "failed to run Applicability scan")
}

func TestJasRunner_Target_AnalyzerManagerReturnsError(t *testing.T) {
	assert.NoError(t, testUtils.PrepareAnalyzerManagerResource())

	scanner, _ := jas.NewJasScanner(&jas.FakeServerDetails)
	directCves, indirectCves := results.ExtractCvesFromScanResponse(jas.FakeBasicXrayResults, []string{"issueId_2_direct_dependency", "issueId_1_direct_dependency"})
	_, err := applicability.RunApplicabilityScan(
		applicability.ContextualAnalysisScanParams{
			DirectDependenciesCves:   directCves,
			IndirectDependenciesCves: indirectCves,
			ScanType:                 applicability.ApplicabilityScannerType,
			Target:                   results.ScanTarget{Target: "target"},
		},
		scanner,
	)
	// Expect error:
	assert.ErrorContains(t, jas.ParseAnalyzerManagerError(jasutils.Applicability, err), "failed to run Applicability scan")
}

func TestAddJasScanTaskIfNeededSkipsCoveredDirectoryScan(t *testing.T) {
	runner := utils.CreateSecurityParallelRunner(1)
	target := newDirTarget(t.TempDir(), nil, nil)
	var secretsRan, applicabilityRan bool
	params := JasRunnerParams{
		Runner:      runner,
		ScanResults: target,
		CoveredDirectoryScans: []utils.SubScanType{
			utils.SecretsScan, utils.IacScan, utils.SastScan, utils.ServicesScan, utils.ContextualAnalysisScan,
		},
	}
	assert.NoError(t, addJasScanTaskIfNeeded(params, utils.SecretsScan, func(int) error {
		defer runner.JasScannersWg.Done()
		secretsRan = true
		return nil
	}))
	assert.NoError(t, addJasScanTaskIfNeeded(params, utils.ContextualAnalysisScan, func(int) error {
		defer runner.JasScannersWg.Done()
		applicabilityRan = true
		return nil
	}))
	done := make(chan struct{})
	runner.OnScanEnd(func() { close(done) })
	go runner.Start()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runner did not finish")
	}
	assert.False(t, secretsRan)
	assert.True(t, applicabilityRan)
}

func TestComputedCoverageSkipsNestedDirectoryScans(t *testing.T) {
	root := t.TempDir()
	parent := newDirTarget(root, nil, nil)
	child := newDirTarget(filepath.Join(root, "subproject"), nil, nil)
	targets := []*results.TargetResults{parent, child}
	covered, coveredBy := CoveredDirectoryScans(targets, 1, nil, nil, nil)
	assert.NotEmpty(t, covered)
	assert.Equal(t, root, coveredBy[utils.SecretsScan])

	parallelRunner := utils.CreateSecurityParallelRunner(1)
	var ran bool
	params := JasRunnerParams{Runner: parallelRunner, ScanResults: child, CoveredDirectoryScans: covered, CoveredBy: coveredBy}
	for _, scan := range covered {
		assert.NoError(t, addJasScanTaskIfNeeded(params, scan, func(int) error {
			defer parallelRunner.JasScannersWg.Done()
			ran = true
			return nil
		}))
	}
	done := make(chan struct{})
	parallelRunner.OnScanEnd(func() { close(done) })
	go parallelRunner.Start()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runner did not finish")
	}
	assert.False(t, ran)
}

func newDirTarget(dir string, exclude []string, excludeScanners []string, include ...string) *results.TargetResults {
	target := results.ScanTarget{Target: dir, Exclude: exclude, Include: include}
	if len(excludeScanners) > 0 {
		target.DeprecatedAppsConfigModule = &jfrogappsconfig.Module{ExcludeScanners: excludeScanners}
	}
	return results.NewCommandResults(utils.SourceCode).NewScanResults(target)
}

func TestCoveredDirectoryScans(t *testing.T) {
	root := t.TempDir()
	parent := root
	child := filepath.Join(root, "subproject")
	inner := filepath.Join(child, "inner")
	sibling := filepath.Join(root, "other")
	insideModules := filepath.Join(root, "node_modules", "leftpad")
	frontend := filepath.Join(root, "frontend")
	frontendApp := filepath.Join(frontend, "app")
	directoryScans := []utils.SubScanType{utils.SecretsScan, utils.IacScan, utils.SastScan, utils.ServicesScan}
	withoutSecrets := []utils.SubScanType{utils.IacScan, utils.SastScan, utils.ServicesScan}

	pipAtRoot := newDirTarget(parent, nil, nil)
	pipAtRoot.Technologies = []techutils.Technology{techutils.Pip}
	npmAtRoot := newDirTarget(parent, nil, nil)
	npmAtRoot.Technologies = []techutils.Technology{techutils.Npm}
	unnamedAtRoot := newDirTarget(parent, nil, nil)
	sastOutsideChild := newDirTarget(parent, nil, nil)
	sastOutsideChild.DeprecatedAppsConfigModule = &jfrogappsconfig.Module{
		SourceRoot: parent,
		Scanners: jfrogappsconfig.Scanners{Sast: &jfrogappsconfig.SastScanner{
			Scanner: jfrogappsconfig.Scanner{WorkingDirs: []string{"src"}},
		}},
	}
	childDifferentRules := newDirTarget(child, nil, nil)
	childDifferentRules.CentralConfigModules = []services.Module{{
		ScanConfig: services.ScanConfig{SastScannerConfig: services.SastScannerConfig{ExcludeRules: []string{"python-hardcoded-credentials"}}},
	}}
	parentValidatesSecrets := newDirTarget(parent, nil, nil)
	parentValidatesSecrets.CentralConfigModules = []services.Module{{
		ScanConfig: services.ScanConfig{SecretsScannerConfig: services.SecretsScannerConfig{EnableSecretsScan: true, ValidateSecrets: true}},
	}}
	parentSkipsSecretsInProfile := newDirTarget(parent, nil, nil)
	parentSkipsSecretsInProfile.CentralConfigModules = []services.Module{{
		ScanConfig: services.ScanConfig{
			IacScannerConfig:      services.IacScannerConfig{EnableIacScan: true},
			SastScannerConfig:     services.SastScannerConfig{EnableSastScan: true},
			ServicesScannerConfig: services.ServicesScannerConfig{EnableServicesScan: true},
		},
	}}
	profile := &services.ConfigProfile{ProfileName: "review"}

	tests := []struct {
		name             string
		targets          []*results.TargetResults
		index            int
		scans            []utils.SubScanType
		profile          *services.ConfigProfile
		runnable         []bool
		secretsEnabled   bool
		secretsRequested bool
		want             []utils.SubScanType
	}{
		{
			name:    "nested target skips directory scans the parent will run",
			targets: []*results.TargetResults{newDirTarget(parent, nil, nil), newDirTarget(child, nil, nil)},
			index:   1,
			want:    directoryScans,
		},
		{
			name:    "parent is not covered by its nested target",
			targets: []*results.TargetResults{newDirTarget(parent, nil, nil), newDirTarget(child, nil, nil)},
			index:   0,
		},
		{
			name:    "nested target listed before the parent still skips",
			targets: []*results.TargetResults{newDirTarget(child, nil, nil), newDirTarget(parent, nil, nil)},
			index:   0,
			want:    directoryScans,
		},
		{
			name:    "single target keeps every scan",
			targets: []*results.TargetResults{newDirTarget(parent, nil, nil)},
			index:   0,
		},
		{
			name:    "sibling directories both keep their scans",
			targets: []*results.TargetResults{newDirTarget(child, nil, nil), newDirTarget(sibling, nil, nil)},
			index:   1,
		},
		{
			name:    "targets sharing a directory both keep their scans",
			targets: []*results.TargetResults{newDirTarget(parent, nil, nil), newDirTarget(parent, nil, nil)},
			index:   1,
		},
		{
			name:    "first target sharing a directory keeps the scan",
			targets: []*results.TargetResults{newDirTarget(parent, nil, nil), newDirTarget(parent, nil, nil)},
			index:   0,
		},
		{
			name:    "deeper nested target is covered by the outermost",
			targets: []*results.TargetResults{newDirTarget(parent, nil, nil), newDirTarget(child, nil, nil), newDirTarget(inner, nil, nil)},
			index:   2,
			want:    directoryScans,
		},
		{
			name:    "parent exclude leaves the nested target to scan itself",
			targets: []*results.TargetResults{newDirTarget(parent, []string{"subproject"}, nil), newDirTarget(child, nil, nil)},
			index:   1,
		},
		{
			name:    "default excludes leave a node_modules target to scan itself",
			targets: []*results.TargetResults{newDirTarget(parent, utils.DefaultScaExcludePatterns, nil), newDirTarget(insideModules, nil, nil)},
			index:   1,
		},
		{
			name: "a repository path containing test still covers a nested project",
			targets: []*results.TargetResults{
				newDirTarget(filepath.Join(root, "my-test-repo"), utils.DefaultScaExcludePatterns, nil),
				newDirTarget(filepath.Join(root, "my-test-repo", "subproject"), utils.DefaultScaExcludePatterns, nil),
			},
			index: 1,
			want:  directoryScans,
		},
		{
			name:    "parent that skips secrets does not cover secrets",
			targets: []*results.TargetResults{newDirTarget(parent, utils.DefaultScaExcludePatterns, []string{"secrets"}), newDirTarget(child, utils.DefaultScaExcludePatterns, nil)},
			index:   1,
			want:    withoutSecrets,
		},
		{
			name:    "targets sharing a directory both scan when only one runs secrets",
			targets: []*results.TargetResults{newDirTarget(parent, utils.DefaultScaExcludePatterns, []string{"secrets"}), newDirTarget(parent, utils.DefaultScaExcludePatterns, nil)},
			index:   1,
		},
		{
			name:    "only a requested scan can cover a nested target",
			targets: []*results.TargetResults{newDirTarget(parent, nil, nil), newDirTarget(child, nil, nil)},
			index:   1,
			scans:   []utils.SubScanType{utils.SecretsScan},
			want:    []utils.SubScanType{utils.SecretsScan},
		},
		{
			name:    "include roots cover only directories they contain",
			targets: []*results.TargetResults{newDirTarget(parent, nil, nil, frontend), newDirTarget(child, nil, nil)},
			index:   1,
		},
		{
			name:    "include root covers a target inside it",
			targets: []*results.TargetResults{newDirTarget(parent, nil, nil, frontend), newDirTarget(frontendApp, nil, nil)},
			index:   1,
			want:    directoryScans,
		},
		{
			name:    "target with no directory keeps its scans",
			targets: []*results.TargetResults{newDirTarget(parent, nil, nil), newDirTarget("", nil, nil)},
			index:   1,
		},
		{
			name:    "a target with no directory does not cover another",
			targets: []*results.TargetResults{newDirTarget("", nil, nil), newDirTarget(child, nil, nil)},
			index:   1,
		},
		{
			name:     "a target that will not run does not cover a nested target",
			targets:  []*results.TargetResults{newDirTarget(parent, nil, nil), newDirTarget(child, nil, nil)},
			index:    1,
			runnable: []bool{false, true},
		},
		{
			name:    "two technologies at the same directory both keep their scans",
			targets: []*results.TargetResults{pipAtRoot, npmAtRoot},
			index:   0,
		},
		{
			name:    "a named technology and a target with no technology both keep a shared directory",
			targets: []*results.TargetResults{unnamedAtRoot, npmAtRoot},
			index:   0,
		},
		{
			name:    "a sast working directory does not cover a nested project outside it",
			targets: []*results.TargetResults{sastOutsideChild, newDirTarget(child, utils.DefaultScaExcludePatterns, nil)},
			index:   1,
			want:    []utils.SubScanType{utils.SecretsScan, utils.IacScan, utils.ServicesScan},
		},
		{
			name:    "different sast excluded rules still leave the nested scans to the outer target",
			targets: []*results.TargetResults{newDirTarget(parent, nil, nil), childDifferentRules},
			index:   1,
			want:    directoryScans,
		},
		{
			name:    "different file excludes still leave the nested scans to the outer target",
			targets: []*results.TargetResults{newDirTarget(parent, nil, nil), newDirTarget(child, []string{"*.py"}, nil)},
			index:   1,
			want:    directoryScans,
		},
		{
			name:    "a config profile that disables secrets does not cover secrets",
			targets: []*results.TargetResults{parentSkipsSecretsInProfile, newDirTarget(child, nil, nil)},
			index:   1,
			profile: profile,
			want:    withoutSecrets,
		},
		{
			name:           "different secret validation still leaves the nested scans to the outer target",
			targets:        []*results.TargetResults{parentValidatesSecrets, newDirTarget(child, nil, nil)},
			index:          1,
			secretsEnabled: true,
			want:           directoryScans,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, _ := CoveredDirectoryScans(test.targets, test.index, test.scans, test.profile, test.runnable)
			assert.ElementsMatch(t, test.want, got)
			assert.NotContains(t, got, utils.ContextualAnalysisScan)
		})
	}
}

func TestSastChangedFilesMode(t *testing.T) {
	profileWithDiffMode := &services.ConfigProfile{Modules: []services.Module{{
		ScanConfig: services.ScanConfig{SastScannerConfig: services.SastScannerConfig{EnableFastDiffMode: true}},
	}}}
	profileWithoutDiffMode := &services.ConfigProfile{Modules: []services.Module{{
		ScanConfig: services.ScanConfig{SastScannerConfig: services.SastScannerConfig{EnableSastScan: true}},
	}}}

	tests := []struct {
		name     string
		params   JasRunnerParams
		expected bool
	}{
		{name: "no profile and no flag", params: JasRunnerParams{}},
		{name: "flag only", params: JasRunnerParams{SastChangedFilesMode: true}, expected: true},
		{name: "profile differential scanning enabled", params: JasRunnerParams{ConfigProfile: profileWithDiffMode}, expected: true},
		{name: "profile differential scanning disabled", params: JasRunnerParams{ConfigProfile: profileWithoutDiffMode}},
		{name: "profile without modules", params: JasRunnerParams{ConfigProfile: &services.ConfigProfile{}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, test.params.sastChangedFilesMode())
		})
	}
}
