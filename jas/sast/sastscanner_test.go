package sast

import (
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"testing"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"

	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
)

func TestNewSastScanManager(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{"currentDir"})
	assert.NoError(t, err)
	// Act
	sastScanManager, err := newSastScanManager(scanner, "tempDirPath", true, false, "", nil)
	assert.NoError(t, err)

	// Assert
	if assert.NotNil(t, sastScanManager) {
		assert.NotEmpty(t, sastScanManager.configFileName)
		assert.True(t, sastScanManager.signedDescriptions)
		assert.NotEmpty(t, sastScanManager.resultsFileName)
		assert.NotEmpty(t, jfrogAppsConfigForTest.Modules[0].SourceRoot)
		assert.Equal(t, &jas.FakeServerDetails, sastScanManager.scanner.ServerDetails)
		assert.Empty(t, sastScanManager.sastRules)
	}
}

func TestNewSastScanManagerWithFilesToCompare(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	tempDir, cleanUpTempDir := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer cleanUpTempDir()

	scanner.TempDir = tempDir
	scannerTempDir, err := jas.CreateScannerTempDirectory(scanner, jasutils.Secrets.String(), 0)
	require.NoError(t, err)

	sastScanManager, err := newSastScanManager(scanner, scannerTempDir, false, false, "", nil, sarifutils.CreateRunWithDummyResults(sarifutils.CreateDummyResult("test-markdown", "test-msg", "test-rule-id", "note")))
	require.NoError(t, err)

	// Check if path value exists and file is created
	assert.NotEmpty(t, sastScanManager.resultsToCompareFileName)
	assert.True(t, fileutils.IsPathExists(sastScanManager.resultsToCompareFileName, false))
}

func TestSastParseResults_EmptyResults(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{})
	assert.NoError(t, err)

	// Arrange
	sastScanManager, err := newSastScanManager(scanner, "tempDirPath", true, false, "", nil)
	assert.NoError(t, err)
	sastScanManager.resultsFileName = filepath.Join(jas.GetTestDataPath(), "sast-scan", "no-violations.sarif")

	// Act
	vulnerabilitiesResults, _, err := jas.ReadJasScanRunsFromFile(sastScanManager.resultsFileName, sastDocsUrlSuffix, scanner.MinSeverity, jfrogAppsConfigForTest.Modules[0].SourceRoot)

	// Assert
	if assert.NoError(t, err) && assert.NotNil(t, vulnerabilitiesResults) {
		assert.Len(t, vulnerabilitiesResults, 1)
		assert.Empty(t, vulnerabilitiesResults[0].Results)
		groupResultsByLocation(vulnerabilitiesResults)
		assert.Len(t, vulnerabilitiesResults, 1)
		assert.Empty(t, vulnerabilitiesResults[0].Results)
	}
}

func TestSastParseResults_ResultsContainIacViolations(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{})
	assert.NoError(t, err)
	// Arrange
	sastScanManager, err := newSastScanManager(scanner, "tempDirPath", false, false, "", nil)
	assert.NoError(t, err)
	sastScanManager.resultsFileName = filepath.Join(jas.GetTestDataPath(), "sast-scan", "contains-sast-violations.sarif")

	// Act
	vulnerabilitiesResults, _, err := jas.ReadJasScanRunsFromFile(sastScanManager.resultsFileName, sastDocsUrlSuffix, scanner.MinSeverity, jfrogAppsConfigForTest.Modules[0].SourceRoot)

	// Assert
	if assert.NoError(t, err) && assert.NotNil(t, vulnerabilitiesResults) {
		assert.Len(t, vulnerabilitiesResults, 1)
		assert.NotEmpty(t, vulnerabilitiesResults[0].Results)
		groupResultsByLocation(vulnerabilitiesResults)
		// File has 4 results, 2 of them at the same location different codeFlow
		assert.Len(t, vulnerabilitiesResults[0].Results, 3)
	}
}

func TestGroupResultsByLocation(t *testing.T) {
	tests := []struct {
		run            *sarif.Run
		expectedOutput *sarif.Run
	}{
		{
			run:            sarifutils.CreateRunWithDummyResults(),
			expectedOutput: sarifutils.CreateRunWithDummyResults(),
		},
		{
			// No similar groups at all
			run: sarifutils.CreateRunWithDummyResults(
				sarifutils.CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "info"),
				sarifutils.CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "note"),
				sarifutils.CreateResultWithOneLocation("file", 5, 6, 7, 8, "snippet", "rule1", "info"),
				sarifutils.CreateResultWithOneLocation("file2", 1, 2, 3, 4, "snippet", "rule1", "info").WithCodeFlows([]*sarif.CodeFlow{
					sarifutils.CreateCodeFlow(sarifutils.CreateThreadFlow(
						sarifutils.CreateLocation("other", 0, 0, 0, 0, "other-snippet"),
						sarifutils.CreateLocation("file2", 1, 2, 3, 4, "snippet"),
					)),
				}),
				sarifutils.CreateResultWithOneLocation("file2", 1, 2, 3, 4, "snippet", "rule2", "info").WithCodeFlows([]*sarif.CodeFlow{
					sarifutils.CreateCodeFlow(sarifutils.CreateThreadFlow(
						sarifutils.CreateLocation("other2", 1, 1, 1, 1, "other-snippet2"),
						sarifutils.CreateLocation("file2", 1, 2, 3, 4, "snippet"),
					)),
				}),
			),
			expectedOutput: sarifutils.CreateRunWithDummyResults(
				sarifutils.CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "info"),
				sarifutils.CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "note"),
				sarifutils.CreateResultWithOneLocation("file", 5, 6, 7, 8, "snippet", "rule1", "info"),
				sarifutils.CreateResultWithOneLocation("file2", 1, 2, 3, 4, "snippet", "rule1", "info").WithCodeFlows([]*sarif.CodeFlow{
					sarifutils.CreateCodeFlow(sarifutils.CreateThreadFlow(
						sarifutils.CreateLocation("other", 0, 0, 0, 0, "other-snippet"),
						sarifutils.CreateLocation("file2", 1, 2, 3, 4, "snippet"),
					)),
				}),
				sarifutils.CreateResultWithOneLocation("file2", 1, 2, 3, 4, "snippet", "rule2", "info").WithCodeFlows([]*sarif.CodeFlow{
					sarifutils.CreateCodeFlow(sarifutils.CreateThreadFlow(
						sarifutils.CreateLocation("other2", 1, 1, 1, 1, "other-snippet2"),
						sarifutils.CreateLocation("file2", 1, 2, 3, 4, "snippet"),
					)),
				}),
			),
		},
		{
			// With similar groups
			run: sarifutils.CreateRunWithDummyResults(
				sarifutils.CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "info").WithCodeFlows([]*sarif.CodeFlow{
					sarifutils.CreateCodeFlow(sarifutils.CreateThreadFlow(
						sarifutils.CreateLocation("other", 0, 0, 0, 0, "other-snippet"),
						sarifutils.CreateLocation("file", 1, 2, 3, 4, "snippet"),
					)),
				}),
				sarifutils.CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "info").WithCodeFlows([]*sarif.CodeFlow{
					sarifutils.CreateCodeFlow(sarifutils.CreateThreadFlow(
						sarifutils.CreateLocation("other2", 1, 1, 1, 1, "other-snippet"),
						sarifutils.CreateLocation("file", 1, 2, 3, 4, "snippet"),
					)),
				}),
				sarifutils.CreateResultWithOneLocation("file", 5, 6, 7, 8, "snippet", "rule1", "info"),
				sarifutils.CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "info"),
			),
			expectedOutput: sarifutils.CreateRunWithDummyResults(
				sarifutils.CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "info").WithCodeFlows([]*sarif.CodeFlow{
					sarifutils.CreateCodeFlow(sarifutils.CreateThreadFlow(
						sarifutils.CreateLocation("other", 0, 0, 0, 0, "other-snippet"),
						sarifutils.CreateLocation("file", 1, 2, 3, 4, "snippet"),
					)),
					sarifutils.CreateCodeFlow(sarifutils.CreateThreadFlow(
						sarifutils.CreateLocation("other2", 1, 1, 1, 1, "other-snippet"),
						sarifutils.CreateLocation("file", 1, 2, 3, 4, "snippet"),
					)),
				}),
				sarifutils.CreateResultWithOneLocation("file", 5, 6, 7, 8, "snippet", "rule1", "info"),
			),
		},
	}

	for _, test := range tests {
		groupResultsByLocation([]*sarif.Run{test.run})
		assert.ElementsMatch(t, test.expectedOutput.Results, test.run.Results)
	}
}

func TestSastRules(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	tempDir, cleanUpTempDir := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer cleanUpTempDir()

	scanner.TempDir = tempDir
	scannerTempDir, err := jas.CreateScannerTempDirectory(scanner, jasutils.Sast.String(), 0)
	require.NoError(t, err)

	sastScanManager, err := newSastScanManager(scanner, scannerTempDir, false, false, "test-rules.json", nil)
	require.NoError(t, err)
	assert.Equal(t, "test-rules.json", sastScanManager.sastRules)
	assert.Equal(t, filepath.Join(scannerTempDir, "config.yaml"), sastScanManager.configFileName)
	assert.Equal(t, filepath.Join(scannerTempDir, "results.sarif"), sastScanManager.resultsFileName)
}

// xscGitInfoWithChanged builds an XscGitInfoContext the way the client defines it (GitDiffContext with changed files).
// Must match the shape expected by SastChangedFilesForTarget in sastscanner.go.
func xscGitInfoWithChanged(t *testing.T, files ...string) *xscservices.XscGitInfoContext {
	t.Helper()
	return &xscservices.XscGitInfoContext{GitDiffContext: xscservices.GitDiffContext{ChangedFiles: files}}
}

func TestSastChangedFilesForTarget(t *testing.T) {
	base := t.TempDir()
	modA := filepath.Join(base, "modA")
	modB := filepath.Join(base, "modB")
	require.NoError(t, os.MkdirAll(modA, 0o755))
	require.NoError(t, os.MkdirAll(modB, 0o755))
	// collectSastChangedAbsPaths only keeps paths that exist on disk
	for _, rel := range []string{
		"modA/a.go", "modA/b.go", "modB/x.go", "modA/abs.go", "foo/x.go", "foobar/y.go",
	} {
		p := filepath.Join(base, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte("// test\n"), 0o644))
	}

	threeFiles := xscGitInfoWithChanged(t, "modA/a.go", "modA/b.go", "modB/x.go")

	tests := []struct {
		name             string
		gitCtx           *xscservices.XscGitInfoContext
		targetPath       string
		rootDir          string
		changedFilesMode bool
		// wantEmpty: expect no file roots (nil or empty slice) when mode is off or there is nothing to return.
		wantEmpty bool
		want      []string
	}{
		{name: "nil_context", gitCtx: nil, targetPath: base, rootDir: base, changedFilesMode: true, wantEmpty: true},
		{name: "changed_files_mode_off", gitCtx: threeFiles, targetPath: modA, rootDir: base, changedFilesMode: false, wantEmpty: true},
		{name: "empty_changed_files", gitCtx: xscGitInfoWithChanged(t), targetPath: modA, rootDir: base, changedFilesMode: true, wantEmpty: true},
		{name: "empty_root_dir", gitCtx: threeFiles, targetPath: modA, rootDir: "", changedFilesMode: true, wantEmpty: true},
		{name: "empty_target_path", gitCtx: threeFiles, targetPath: "", rootDir: base, changedFilesMode: true, wantEmpty: true},
		{
			name:             "target_is_repo_root_returns_all_as_abs",
			gitCtx:           threeFiles,
			targetPath:       base,
			rootDir:          base,
			changedFilesMode: true,
			want:             []string{filepath.Join(base, "modA", "a.go"), filepath.Join(base, "modA", "b.go"), filepath.Join(base, "modB", "x.go")},
		},
		{
			name:             "filters_to_modA_only",
			gitCtx:           threeFiles,
			targetPath:       modA,
			rootDir:          base,
			changedFilesMode: true,
			want:             []string{filepath.Join(base, "modA", "a.go"), filepath.Join(base, "modA", "b.go")},
		},
		{
			name:             "prefix_foo_does_not_match_foobar",
			gitCtx:           &xscservices.XscGitInfoContext{GitDiffContext: xscservices.GitDiffContext{ChangedFiles: []string{"foo/x.go", "foobar/y.go"}}},
			targetPath:       filepath.Join(base, "foo"),
			rootDir:          base,
			changedFilesMode: true,
			want:             []string{filepath.Join(base, "foo", "x.go")},
		},
		{
			// belong-to-target matching uses repo-relative paths (as git reports); resolve to absolute under rootDir afterward.
			name:             "repo_relative_changed_file_under_target",
			gitCtx:           xscGitInfoWithChanged(t, "modA/abs.go"),
			targetPath:       modA,
			rootDir:          base,
			changedFilesMode: true,
			want:             []string{filepath.Join(base, "modA", "abs.go")},
		},
		{
			name:             "deduplicates_same_paths",
			gitCtx:           &xscservices.XscGitInfoContext{GitDiffContext: xscservices.GitDiffContext{ChangedFiles: []string{"modA/a.go", "modA/a.go", "./modA/a.go"}}},
			targetPath:       modA,
			rootDir:          base,
			changedFilesMode: true,
			want:             []string{filepath.Join(base, "modA", "a.go")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SastChangedFilesForTarget(tt.changedFilesMode, tt.gitCtx, tt.targetPath, tt.rootDir)
			if tt.wantEmpty {
				assert.Empty(t, got, "SastChangedFilesForTarget should not return any paths in this case")
			} else {
				assert.ElementsMatch(t, tt.want, got, "SastChangedFilesForTarget per-target paths (order may be sorted in implementation)")
			}
		})
	}
}

func TestCreateConfigFile_ChangedFilesModeRoots(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	tempDir, cleanUpTempDir := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer cleanUpTempDir()
	scanner.TempDir = tempDir
	scannerTempDir, err := jas.CreateScannerTempDirectory(scanner, jasutils.Sast.String(), 0)
	require.NoError(t, err)

	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{})
	require.NoError(t, err)
	module := jfrogAppsConfigForTest.Modules[0]
	sastScanner := module.Scanners.Sast
	if sastScanner == nil {
		sastScanner = &jfrogappsconfig.SastScanner{}
	}
	expectedDefaultRoots, err := jas.GetSourceRoots(module, &sastScanner.Scanner)
	require.NoError(t, err)

	changed := []string{"src/a.go", "src/b.go"}
	ssm, err := newSastScanManager(scanner, scannerTempDir, false, false, "", nil)
	require.NoError(t, err)

	type yamlCfg struct {
		Scans []struct {
			Roots []string `yaml:"roots,omitempty"`
		} `yaml:"scans,omitempty"`
	}
	readConfigRoots := func(t *testing.T) []string {
		t.Helper()
		data, err := os.ReadFile(ssm.configFileName)
		require.NoError(t, err)
		var cfg yamlCfg
		require.NoError(t, yaml.Unmarshal(data, &cfg))
		require.Len(t, cfg.Scans, 1)
		return cfg.Scans[0].Roots
	}

	for _, tc := range []struct {
		name             string
		changedFilesMode bool
		// sastForCall is the slice passed to deprecatedCreateConfigFile; nil to pass nil.
		sastForCall []string
		want        []string
		emptyRoots  bool
	}{
		{
			name:             "env_true_uses_changed_files_as_roots",
			changedFilesMode: true,
			sastForCall:      changed,
			want:             changed,
		},
		{
			name:             "env_1_uses_changed_files_as_roots",
			changedFilesMode: true,
			sastForCall:      changed,
			want:             changed,
		},
		{
			name:             "env_false_ignores_changed_files",
			changedFilesMode: false,
			sastForCall:      changed,
			want:             expectedDefaultRoots,
		},
		{
			// In changed-files mode, do not use full module roots; RunSastScan skips the analyzer with no diff baseline.
			name:             "env_true_no_changed_file_list_uses_no_module_roots",
			changedFilesMode: true,
			sastForCall:      nil,
			emptyRoots:       true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ssm.changedFilesMode = tc.changedFilesMode
			require.NoError(t, ssm.deprecatedCreateConfigFile(module, false, tc.sastForCall, nil))
			got := readConfigRoots(t)
			if tc.emptyRoots {
				assert.Empty(t, got, "with changed-files mode on and no per-target list, roots should be nil/empty in YAML, not the default module source roots")
			} else {
				assert.ElementsMatch(t, tc.want, got)
			}
		})
	}
}
