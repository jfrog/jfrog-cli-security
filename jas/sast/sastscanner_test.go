package sast

import (
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"testing"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"

	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
)

func TestNewSastScanManager(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{"currentDir"})
	assert.NoError(t, err)
	// Act
	sastScanManager, err := newSastScanManager(scanner, "tempDirPath", true, false, "", nil, nil)
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

	sastScanManager, err := newSastScanManager(scanner, scannerTempDir, false, false, "", nil, nil, sarifutils.CreateRunWithDummyResults(sarifutils.CreateDummyResult("test-markdown", "test-msg", "test-rule-id", "note")))
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
	sastScanManager, err := newSastScanManager(scanner, "tempDirPath", true, false, "", nil, nil)
	assert.NoError(t, err)
	sastScanManager.resultsFileName = filepath.Join(jas.GetTestDataPath(), "sast-scan", "no-violations.sarif")

	// Act
	vulnerabilitiesResults, _, err := jas.ReadJasScanRunsFromFile(sastScanManager.resultsFileName, sastDocsUrlSuffix, scanner.MinSeverity, jfrogAppsConfigForTest.Modules[0].SourceRoot)

	// Assert
	if assert.NoError(t, err) && assert.NotNil(t, vulnerabilitiesResults) {
		assert.Len(t, vulnerabilitiesResults, 1)
		assert.Empty(t, vulnerabilitiesResults[0].Results)
		grouped := sarifutils.GroupResultsByLocation(vulnerabilitiesResults)
		assert.Len(t, grouped, 1)
		assert.Empty(t, grouped[0].Results)
	}
}

func TestSastParseResults_ResultsContainIacViolations(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{})
	assert.NoError(t, err)
	// Arrange
	sastScanManager, err := newSastScanManager(scanner, "tempDirPath", false, false, "", nil, nil)
	assert.NoError(t, err)
	sastScanManager.resultsFileName = filepath.Join(jas.GetTestDataPath(), "sast-scan", "contains-sast-violations.sarif")

	// Act
	vulnerabilitiesResults, _, err := jas.ReadJasScanRunsFromFile(sastScanManager.resultsFileName, sastDocsUrlSuffix, scanner.MinSeverity, jfrogAppsConfigForTest.Modules[0].SourceRoot)

	// Assert
	if assert.NoError(t, err) && assert.NotNil(t, vulnerabilitiesResults) {
		assert.Len(t, vulnerabilitiesResults, 1)
		assert.NotEmpty(t, vulnerabilitiesResults[0].Results)
		grouped := sarifutils.GroupResultsByLocation(vulnerabilitiesResults)
		// File has 4 results, 2 of them at the same location different codeFlow
		assert.Len(t, grouped[0].Results, 3)
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

	sastScanManager, err := newSastScanManager(scanner, scannerTempDir, false, false, "test-rules.json", nil, nil)
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
		name       string
		gitCtx     *xscservices.XscGitInfoContext
		targetPath string
		rootDir    string
		// wantEmpty: expect no file roots (nil or empty slice) when mode is off or there is nothing to return.
		wantEmpty bool
		want      []string
	}{
		{name: "nil_context", gitCtx: nil, targetPath: base, rootDir: base, wantEmpty: true},
		{name: "empty_changed_files", gitCtx: xscGitInfoWithChanged(t), targetPath: modA, rootDir: base, wantEmpty: true},
		{name: "empty_root_dir", gitCtx: threeFiles, targetPath: modA, rootDir: "", wantEmpty: true},
		{name: "empty_target_path", gitCtx: threeFiles, targetPath: "", rootDir: base, wantEmpty: true},
		{
			name:       "target_is_repo_root_returns_all_as_abs",
			gitCtx:     threeFiles,
			targetPath: base,
			rootDir:    base,
			want:       []string{filepath.Join(base, "modA", "a.go"), filepath.Join(base, "modA", "b.go"), filepath.Join(base, "modB", "x.go")},
		},
		{
			name:       "filters_to_modA_only",
			gitCtx:     threeFiles,
			targetPath: modA,
			rootDir:    base,
			want:       []string{filepath.Join(base, "modA", "a.go"), filepath.Join(base, "modA", "b.go")},
		},
		{
			name:       "prefix_foo_does_not_match_foobar",
			gitCtx:     &xscservices.XscGitInfoContext{GitDiffContext: xscservices.GitDiffContext{ChangedFiles: []string{"foo/x.go", "foobar/y.go"}}},
			targetPath: filepath.Join(base, "foo"),
			rootDir:    base,
			want:       []string{filepath.Join(base, "foo", "x.go")},
		},
		{
			// belong-to-target matching uses repo-relative paths (as git reports); resolve to absolute under rootDir afterward.
			name:       "repo_relative_changed_file_under_target",
			gitCtx:     xscGitInfoWithChanged(t, "modA/abs.go"),
			targetPath: modA,
			rootDir:    base,
			want:       []string{filepath.Join(base, "modA", "abs.go")},
		},
		{
			name:       "deduplicates_same_paths",
			gitCtx:     &xscservices.XscGitInfoContext{GitDiffContext: xscservices.GitDiffContext{ChangedFiles: []string{"modA/a.go", "modA/a.go", "./modA/a.go"}}},
			targetPath: modA,
			rootDir:    base,
			want:       []string{filepath.Join(base, "modA", "a.go")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SastChangedFilesForTarget(tt.gitCtx, tt.targetPath, tt.rootDir)
			if tt.wantEmpty {
				assert.Empty(t, got, "SastChangedFilesForTarget should not return any paths in this case")
			} else {
				assert.ElementsMatch(t, tt.want, got, "SastChangedFilesForTarget per-target paths (order may be sorted in implementation)")
			}
		})
	}
}

func readConfigRoots(t *testing.T, configFileName string) []string {
	t.Helper()
	data, err := os.ReadFile(configFileName)
	require.NoError(t, err)
	var cfg struct {
		Scans []struct {
			Roots []string `yaml:"roots,omitempty"`
		} `yaml:"scans,omitempty"`
	}
	require.NoError(t, yaml.Unmarshal(data, &cfg))
	require.Len(t, cfg.Scans, 1)
	return cfg.Scans[0].Roots
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
	ssm, err := newSastScanManager(scanner, scannerTempDir, false, false, "", nil, nil)
	require.NoError(t, err)

	for _, tc := range []struct {
		name             string
		changedFilesMode bool
		// sastForCall is the slice passed to deprecatedCreateConfigFile; nil to pass nil.
		sastForCall []string
		want        []string
		emptyRoots  bool
	}{
		{
			name:             "changed_files_mode_uses_changed_files_as_roots",
			changedFilesMode: true,
			sastForCall:      changed,
			want:             changed,
		},
		{
			name:             "changed_files_mode_off_ignores_changed_files",
			changedFilesMode: false,
			sastForCall:      changed,
			want:             expectedDefaultRoots,
		},
		{
			// In changed-files mode, do not use full module roots; RunSastScan skips the analyzer with no diff baseline.
			name:             "changed_files_mode_no_changed_file_list_uses_no_module_roots",
			changedFilesMode: true,
			sastForCall:      nil,
			emptyRoots:       true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ssm.changedFilesMode = tc.changedFilesMode
			ssm.sastChangedFiles = tc.sastForCall
			require.NoError(t, ssm.deprecatedCreateConfigFile(module, false, nil))
			got := readConfigRoots(t, ssm.configFileName)
			if tc.emptyRoots {
				assert.Empty(t, got, "with changed-files mode on and no per-target list, roots should be nil/empty in YAML, not the default module source roots")
			} else {
				assert.ElementsMatch(t, tc.want, got)
			}
		})
	}
}

func TestCreateConfigFileForTarget_ChangedFilesModeRoots(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	tempDir, cleanUpTempDir := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer cleanUpTempDir()
	scanner.TempDir = tempDir
	scannerTempDir, err := jas.CreateScannerTempDirectory(scanner, jasutils.Sast.String(), 0)
	require.NoError(t, err)

	target := results.ScanTarget{Target: filepath.Join("root", "repository")}
	changed := []string{filepath.Join("root", "repository", "src", "a.go")}

	for _, tc := range []struct {
		name             string
		changedFilesMode bool
		changedFiles     []string
		want             []string
		emptyRoots       bool
	}{
		{
			name:             "changed_files_mode_uses_changed_files_as_roots",
			changedFilesMode: true,
			changedFiles:     changed,
			want:             changed,
		},
		{
			name:         "mode_off_uses_target_roots",
			changedFiles: changed,
			want:         []string{target.Target},
		},
		{
			// RunSastScan skips the analyzer in this case, so the target must not fall back to the whole tree.
			name:             "changed_files_mode_without_changed_files_uses_no_roots",
			changedFilesMode: true,
			emptyRoots:       true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ssm, err := newSastScanManager(scanner, scannerTempDir, false, tc.changedFilesMode, "", tc.changedFiles, nil)
			require.NoError(t, err)
			require.NoError(t, ssm.createConfigFileForTarget(target))
			got := readConfigRoots(t, ssm.configFileName)
			if tc.emptyRoots {
				assert.Empty(t, got, "with changed-files mode on and no changed files, roots should be empty, not the scan target")
			} else {
				assert.ElementsMatch(t, tc.want, got)
			}
		})
	}
}

func TestExcludedRulesFromCentralConfig(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	tempDir, cleanUpTempDir := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer cleanUpTempDir()
	scanner.TempDir = tempDir

	profileRules := []string{"java-stored-command-injection"}
	appsConfigRules := []string{"java-sql-injection"}
	target := results.ScanTarget{Target: filepath.Join("root", "repository")}
	targetWithProfileRules := results.ScanTarget{
		Target: target.Target,
		CentralConfigModules: []xscservices.Module{{
			ScanConfig: xscservices.ScanConfig{SastScannerConfig: xscservices.SastScannerConfig{ExcludeRules: profileRules}},
		}},
	}

	readExcludedRules := func(t *testing.T, configFileName string) []string {
		t.Helper()
		data, err := os.ReadFile(configFileName)
		require.NoError(t, err)
		var cfg struct {
			Scans []struct {
				ExcludedRules []string `yaml:"excluded_rules,omitempty"`
			} `yaml:"scans,omitempty"`
		}
		require.NoError(t, yaml.Unmarshal(data, &cfg))
		require.Len(t, cfg.Scans, 1)
		return cfg.Scans[0].ExcludedRules
	}
	newManager := func(t *testing.T, excludeRules []string) *SastScanManager {
		t.Helper()
		scannerTempDir, err := jas.CreateScannerTempDirectory(scanner, jasutils.Sast.String(), 0)
		require.NoError(t, err)
		ssm, err := newSastScanManager(scanner, scannerTempDir, false, false, "", nil, excludeRules)
		require.NoError(t, err)
		return ssm
	}

	appsConfig, err := jas.CreateJFrogAppsConfig([]string{})
	require.NoError(t, err)
	appsModule := appsConfig.Modules[0]
	appsModule.Scanners.Sast = &jfrogappsconfig.SastScanner{ExcludedRules: appsConfigRules}

	t.Run("target flow uses the central config rules", func(t *testing.T) {
		ssm := newManager(t, nil)
		require.NoError(t, ssm.createConfigFileForTarget(targetWithProfileRules))
		assert.ElementsMatch(t, profileRules, readExcludedRules(t, ssm.configFileName))
	})

	t.Run("target flow without central config rules excludes nothing", func(t *testing.T) {
		ssm := newManager(t, nil)
		require.NoError(t, ssm.createConfigFileForTarget(target))
		assert.Empty(t, readExcludedRules(t, ssm.configFileName))
	})

	t.Run("central config rules take precedence over jfrog-apps-config", func(t *testing.T) {
		ssm := newManager(t, profileRules)
		require.NoError(t, ssm.deprecatedCreateConfigFile(appsModule, false, nil))
		assert.ElementsMatch(t, profileRules, readExcludedRules(t, ssm.configFileName))
	})

	t.Run("jfrog-apps-config rules are kept when the central config has none", func(t *testing.T) {
		ssm := newManager(t, nil)
		require.NoError(t, ssm.deprecatedCreateConfigFile(appsModule, false, nil))
		assert.ElementsMatch(t, appsConfigRules, readExcludedRules(t, ssm.configFileName))
	})
}
