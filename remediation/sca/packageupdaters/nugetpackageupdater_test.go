package packageupdaters

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

// writeFakeDotnetRestore stands in for the real dotnet CLI: it writes lockFileContent next to the
// project file passed as its second argument (mirroring where 'dotnet restore' would write
// packages.lock.json), appends the received arguments to <dir>/args.log, optionally creates an
// obj/ directory alongside the project (mirroring dotnet restore's own build-artifact output),
// then exits with exitCode - letting the regeneration/rollback/cleanup paths, and the exact flags
// used, be tested deterministically without a real .NET SDK, on POSIX and Windows alike.
func writeFakeDotnetRestore(t *testing.T, dir string, exitCode int, lockFileContent string, createObjDir bool) {
	lockContentPath := filepath.Join(dir, "lockfile-content.json")
	assert.NoError(t, os.WriteFile(lockContentPath, []byte(lockFileContent), 0o644))
	argsLogPath := filepath.Join(dir, "args.log")

	if runtime.GOOS == "windows" {
		mkObjLine := ""
		if createObjDir {
			mkObjLine = "if not exist \"%projdir%obj\" mkdir \"%projdir%obj\"\r\n"
		}
		script := "@echo off\r\n" +
			"echo %*>>\"" + argsLogPath + "\"\r\n" +
			"for %%F in (\"%2\") do set projdir=%%~dpF\r\n" +
			"copy /Y \"" + lockContentPath + "\" \"%projdir%packages.lock.json\">nul\r\n" +
			mkObjLine +
			"exit /b " + strconv.Itoa(exitCode) + "\r\n"
		assert.NoError(t, os.WriteFile(filepath.Join(dir, "dotnet.cmd"), []byte(script), 0o755))
		return
	}

	mkObjLine := ""
	if createObjDir {
		mkObjLine = "mkdir -p \"$projdir/obj\"\n"
	}
	script := "#!/bin/sh\n" +
		"echo \"$@\" >> \"" + argsLogPath + "\"\n" +
		"projdir=$(dirname \"$2\")\n" +
		"cp \"" + lockContentPath + "\" \"$projdir/packages.lock.json\"\n" +
		mkObjLine +
		"exit " + strconv.Itoa(exitCode) + "\n"
	assert.NoError(t, os.WriteFile(filepath.Join(dir, "dotnet"), []byte(script), 0o755))
}

func TestNugetUpdateDependency(t *testing.T) {
	integration.InitUnitTest(t)
	testProjectPath := filepath.Join("..", "..", "..", "tests", "testdata", "projects", "package-managers", "nuget", "remediation-packageupdaters")
	currDir, err := os.Getwd()
	assert.NoError(t, err)

	updateAttributeCsproj := `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Update="Microsoft.NET.Test.Sdk" Version="17.8.0" />
  </ItemGroup>
</Project>`

	childElementVersionCsproj := `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json">
      <Version>12.0.3</Version>
    </PackageReference>
  </ItemGroup>
</Project>`

	testCases := []struct {
		name               string
		customCsproj       string
		fixDetails         *FixDetails
		expectedContains   []string
		expectedNotContain []string
	}{
		{
			name: "IncludeThenVersion",
			fixDetails: &FixDetails{
				SuggestedFixedVersion:  "13.0.1",
				IsDirectDependency:     true,
				Technology:             techutils.Nuget,
				ImpactedDependencyName: "Newtonsoft.Json",
				Components:             []formats.ComponentRow{{Evidences: []formats.Location{{File: "Project.csproj"}}}},
			},
			expectedContains:   []string{`Include="Newtonsoft.Json" Version="13.0.1"`},
			expectedNotContain: []string{`Version="12.0.3"`},
		},
		{
			name: "VersionThenInclude",
			fixDetails: &FixDetails{
				SuggestedFixedVersion:  "2.12.0",
				IsDirectDependency:     true,
				Technology:             techutils.Nuget,
				ImpactedDependencyName: "Serilog",
				Components:             []formats.ComponentRow{{Evidences: []formats.Location{{File: "Project.csproj"}}}},
			},
			expectedContains:   []string{`Version="2.12.0" Include="Serilog"`},
			expectedNotContain: []string{`Version="2.10.0"`},
		},
		{
			name:         "UpdateAttribute",
			customCsproj: updateAttributeCsproj,
			fixDetails: &FixDetails{
				SuggestedFixedVersion:  "17.9.0",
				IsDirectDependency:     true,
				Technology:             techutils.Nuget,
				ImpactedDependencyName: "Microsoft.NET.Test.Sdk",
				Components:             []formats.ComponentRow{{Evidences: []formats.Location{{File: "Project.csproj"}}}},
			},
			expectedContains:   []string{`Update="Microsoft.NET.Test.Sdk" Version="17.9.0"`},
			expectedNotContain: []string{`Version="17.8.0"`},
		},
		{
			name:         "ChildElementVersion",
			customCsproj: childElementVersionCsproj,
			fixDetails: &FixDetails{
				SuggestedFixedVersion:  "13.0.1",
				IsDirectDependency:     true,
				Technology:             techutils.Nuget,
				ImpactedDependencyName: "Newtonsoft.Json",
				Components:             []formats.ComponentRow{{Evidences: []formats.Location{{File: "Project.csproj"}}}},
			},
			expectedContains:   []string{`<Version>13.0.1</Version>`},
			expectedNotContain: []string{`<Version>12.0.3</Version>`},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "nuget-test-*")
			assert.NoError(t, err)
			defer func() {
				assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
			}()

			assert.NoError(t, biutils.CopyDir(testProjectPath, tmpDir, true, nil))
			if tc.customCsproj != "" {
				assert.NoError(t, os.WriteFile(filepath.Join(tmpDir, "Project.csproj"), []byte(tc.customCsproj), 0644))
			}
			assert.NoError(t, os.Chdir(tmpDir))
			defer func() {
				assert.NoError(t, os.Chdir(currDir))
			}()

			updater := &NugetPackageUpdater{}
			err = updater.UpdateDependency(tc.fixDetails)
			assert.NoError(t, err)

			modifiedCsproj, err := os.ReadFile("Project.csproj")
			assert.NoError(t, err)
			content := string(modifiedCsproj)
			for _, s := range tc.expectedContains {
				assert.Contains(t, content, s)
			}
			for _, s := range tc.expectedNotContain {
				assert.NotContains(t, content, s)
			}
		})
	}
}

func TestNugetUpdateDependencyPartialSuccess(t *testing.T) {
	integration.InitUnitTest(t)
	testProjectPath := filepath.Join("..", "..", "..", "tests", "testdata", "projects", "package-managers", "nuget", "remediation-packageupdaters")
	currDir, err := os.Getwd()
	assert.NoError(t, err)

	tmpDir, err := os.MkdirTemp("", "nuget-test-*")
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()
	assert.NoError(t, biutils.CopyDir(testProjectPath, tmpDir, true, nil))
	assert.NoError(t, os.Chdir(tmpDir))
	defer func() {
		assert.NoError(t, os.Chdir(currDir))
	}()

	fixDetails := &FixDetails{
		SuggestedFixedVersion:  "13.0.1",
		IsDirectDependency:     true,
		Technology:             techutils.Nuget,
		ImpactedDependencyName: "Newtonsoft.Json",
		Components: []formats.ComponentRow{{Evidences: []formats.Location{
			{File: "Project.csproj"},
			{File: filepath.Join("CpmSibling", "CpmSibling.csproj")},
		}}},
	}

	updater := &NugetPackageUpdater{}
	err = updater.UpdateDependency(fixDetails)
	// A successful sibling fix must not be reported as an error just because the CPM-governed one
	// couldn't be fixed - the failure is logged, not surfaced as the call's result.
	assert.NoError(t, err)

	fixedProject, err := os.ReadFile("Project.csproj")
	assert.NoError(t, err)
	assert.Contains(t, string(fixedProject), `Include="Newtonsoft.Json" Version="13.0.1"`)

	cpmSibling, err := os.ReadFile(filepath.Join("CpmSibling", "CpmSibling.csproj"))
	assert.NoError(t, err)
	assert.Contains(t, string(cpmSibling), `Include="Newtonsoft.Json" />`)
}

func TestNugetUpdateDependencyRegeneratesLockFile(t *testing.T) {
	integration.InitUnitTest(t)
	testProjectPath := filepath.Join("..", "..", "..", "tests", "testdata", "projects", "package-managers", "nuget", "remediation-packageupdaters")
	currDir, err := os.Getwd()
	assert.NoError(t, err)

	tmpDir, err := os.MkdirTemp("", "nuget-test-*")
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()
	assert.NoError(t, biutils.CopyDir(testProjectPath, tmpDir, true, nil))
	assert.NoError(t, os.Chdir(tmpDir))
	defer func() {
		assert.NoError(t, os.Chdir(currDir))
	}()

	toolDir := t.TempDir()
	regeneratedLock := `{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"13.0.1"}}}}`
	writeFakeDotnetRestore(t, toolDir, 0, regeneratedLock, false)
	t.Setenv("PATH", toolDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	fixDetails := &FixDetails{
		SuggestedFixedVersion:  "13.0.1",
		IsDirectDependency:     true,
		Technology:             techutils.Nuget,
		ImpactedDependencyName: "Newtonsoft.Json",
		Components:             []formats.ComponentRow{{Evidences: []formats.Location{{File: filepath.Join("WithLockFile", "WithLockFile.csproj")}}}},
	}

	updater := &NugetPackageUpdater{}
	err = updater.UpdateDependency(fixDetails)
	assert.NoError(t, err)

	fixedCsproj, err := os.ReadFile(filepath.Join("WithLockFile", "WithLockFile.csproj"))
	assert.NoError(t, err)
	assert.Contains(t, string(fixedCsproj), `Include="Newtonsoft.Json" Version="13.0.1"`)

	lockFile, err := os.ReadFile(filepath.Join("WithLockFile", "packages.lock.json"))
	assert.NoError(t, err)
	assert.Contains(t, string(lockFile), `"resolved":"13.0.1"`)
}

func TestNugetUpdateDependencyRollsBackOnRestoreFailure(t *testing.T) {
	integration.InitUnitTest(t)
	testProjectPath := filepath.Join("..", "..", "..", "tests", "testdata", "projects", "package-managers", "nuget", "remediation-packageupdaters")
	currDir, err := os.Getwd()
	assert.NoError(t, err)

	tmpDir, err := os.MkdirTemp("", "nuget-test-*")
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()
	assert.NoError(t, biutils.CopyDir(testProjectPath, tmpDir, true, nil))
	assert.NoError(t, os.Chdir(tmpDir))
	defer func() {
		assert.NoError(t, os.Chdir(currDir))
	}()

	originalLockFile, err := os.ReadFile(filepath.Join("WithLockFile", "packages.lock.json"))
	assert.NoError(t, err)
	originalCsproj, err := os.ReadFile(filepath.Join("WithLockFile", "WithLockFile.csproj"))
	assert.NoError(t, err)

	toolDir := t.TempDir()
	writeFakeDotnetRestore(t, toolDir, 1, `{"corrupted": true}`, false)
	t.Setenv("PATH", toolDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	fixDetails := &FixDetails{
		SuggestedFixedVersion:  "13.0.1",
		IsDirectDependency:     true,
		Technology:             techutils.Nuget,
		ImpactedDependencyName: "Newtonsoft.Json",
		Components:             []formats.ComponentRow{{Evidences: []formats.Location{{File: filepath.Join("WithLockFile", "WithLockFile.csproj")}}}},
	}

	updater := &NugetPackageUpdater{}
	err = updater.UpdateDependency(fixDetails)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "dotnet restore failed")

	rolledBackCsproj, err := os.ReadFile(filepath.Join("WithLockFile", "WithLockFile.csproj"))
	assert.NoError(t, err)
	assert.Equal(t, originalCsproj, rolledBackCsproj)

	rolledBackLockFile, err := os.ReadFile(filepath.Join("WithLockFile", "packages.lock.json"))
	assert.NoError(t, err)
	assert.Equal(t, originalLockFile, rolledBackLockFile)
}

func TestNugetUpdateDependencyErrors(t *testing.T) {
	integration.InitUnitTest(t)
	testProjectPath := filepath.Join("..", "..", "..", "tests", "testdata", "projects", "package-managers", "nuget", "remediation-packageupdaters")
	currDir, err := os.Getwd()
	assert.NoError(t, err)

	testCases := []struct {
		name        string
		fixDetails  *FixDetails
		useTestData bool
		assertErr   func(t *testing.T, err error)
	}{
		{
			name: "DependencyNotFound",
			fixDetails: &FixDetails{
				SuggestedFixedVersion:  "1.0.0",
				IsDirectDependency:     true,
				Technology:             techutils.Nuget,
				ImpactedDependencyName: "NonExistent.Package",
				Components:             []formats.ComponentRow{{Evidences: []formats.Location{{File: "Project.csproj"}}}},
			},
			useTestData: true,
			assertErr: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "NonExistent.Package")
			},
		},
		{
			name: "NoInlineVersionNotSupported",
			fixDetails: &FixDetails{
				SuggestedFixedVersion:  "1.1.118",
				IsDirectDependency:     true,
				Technology:             techutils.Nuget,
				ImpactedDependencyName: "StyleCop.Analyzers",
				Components:             []formats.ComponentRow{{Evidences: []formats.Location{{File: "Project.csproj"}}}},
			},
			useTestData: true,
			assertErr: func(t *testing.T, err error) {
				assert.Error(t, err)
				var unsupportedErr *ErrUnsupportedFix
				assert.True(t, errors.As(err, &unsupportedErr))
				assert.Equal(t, NoInlineVersionFixNotSupported, unsupportedErr.ErrorType)
			},
		},
		{
			name: "IndirectDependencyNotSupported",
			fixDetails: &FixDetails{
				SuggestedFixedVersion:  "13.0.1",
				IsDirectDependency:     false,
				Technology:             techutils.Nuget,
				ImpactedDependencyName: "Newtonsoft.Json",
				Components:             []formats.ComponentRow{{Evidences: []formats.Location{{File: "Project.csproj"}}}},
			},
			useTestData: false,
			assertErr: func(t *testing.T, err error) {
				assert.Error(t, err)
				var unsupportedErr *ErrUnsupportedFix
				assert.True(t, errors.As(err, &unsupportedErr))
				assert.Equal(t, IndirectDependencyFixNotSupported, unsupportedErr.ErrorType)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.useTestData {
				tmpDir, err := os.MkdirTemp("", "nuget-test-*")
				assert.NoError(t, err)
				defer func() {
					assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
				}()
				assert.NoError(t, biutils.CopyDir(testProjectPath, tmpDir, true, nil))
				assert.NoError(t, os.Chdir(tmpDir))
				defer func() {
					assert.NoError(t, os.Chdir(currDir))
				}()
			}
			updater := &NugetPackageUpdater{}
			err = updater.UpdateDependency(tc.fixDetails)
			tc.assertErr(t, err)
		})
	}
}

func TestHasNugetProjectFileSuffix(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"Project.csproj", true},
		{"Project.CSProj", true},
		{"Project.CSPROJ", true},
		{"Project.fsproj", true},
		{"Project.FSPROJ", true},
		{"Project.vbproj", true},
		{"Project.VBPROJ", true},
		{filepath.Join("src", "Project.csproj"), true},
		{"Directory.Packages.props", false},
		{"packages.config", false},
		{"Project.sln", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, hasNugetProjectFileSuffix(tt.path))
		})
	}
}

// TestNugetUpdateDependencyRestoreScopedFlags documents the exact restore invocation: both
// --force-evaluate and --no-dependencies must always be passed. --no-dependencies is what keeps a
// fix scoped to the touched project's own lock file - and is also the source of a known
// limitation (a bumped package's transitives living in a referenced project can leave that
// project's own lock file stale), so this test doubles as a marker for that tradeoff.
func TestNugetUpdateDependencyRestoreScopedFlags(t *testing.T) {
	integration.InitUnitTest(t)
	testProjectPath := filepath.Join("..", "..", "..", "tests", "testdata", "projects", "package-managers", "nuget", "remediation-packageupdaters")
	currDir, err := os.Getwd()
	assert.NoError(t, err)

	tmpDir, err := os.MkdirTemp("", "nuget-test-*")
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()
	assert.NoError(t, biutils.CopyDir(testProjectPath, tmpDir, true, nil))
	assert.NoError(t, os.Chdir(tmpDir))
	defer func() {
		assert.NoError(t, os.Chdir(currDir))
	}()

	toolDir := t.TempDir()
	writeFakeDotnetRestore(t, toolDir, 0, `{}`, false)
	t.Setenv("PATH", toolDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	fixDetails := &FixDetails{
		SuggestedFixedVersion:  "13.0.1",
		IsDirectDependency:     true,
		Technology:             techutils.Nuget,
		ImpactedDependencyName: "Newtonsoft.Json",
		Components:             []formats.ComponentRow{{Evidences: []formats.Location{{File: filepath.Join("WithLockFile", "WithLockFile.csproj")}}}},
	}

	updater := &NugetPackageUpdater{}
	err = updater.UpdateDependency(fixDetails)
	assert.NoError(t, err)

	argsLog, err := os.ReadFile(filepath.Join(toolDir, "args.log"))
	assert.NoError(t, err)
	assert.Contains(t, string(argsLog), "--force-evaluate")
	assert.Contains(t, string(argsLog), "--no-dependencies")
}

// TestNugetUpdateDependencyCleansUpGeneratedObjDir verifies that an obj/ directory created by
// restore (dotnet writes project.assets.json and other build artifacts there) is removed
// afterward, so a fix PR doesn't pick up unrelated build output alongside the intended
// descriptor/lock file changes.
func TestNugetUpdateDependencyCleansUpGeneratedObjDir(t *testing.T) {
	integration.InitUnitTest(t)
	testProjectPath := filepath.Join("..", "..", "..", "tests", "testdata", "projects", "package-managers", "nuget", "remediation-packageupdaters")
	currDir, err := os.Getwd()
	assert.NoError(t, err)

	tmpDir, err := os.MkdirTemp("", "nuget-test-*")
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()
	assert.NoError(t, biutils.CopyDir(testProjectPath, tmpDir, true, nil))
	assert.NoError(t, os.Chdir(tmpDir))
	defer func() {
		assert.NoError(t, os.Chdir(currDir))
	}()

	objDir := filepath.Join("WithLockFile", "obj")
	_, statErr := os.Stat(objDir)
	assert.True(t, os.IsNotExist(statErr), "obj/ should not exist before the fix")

	toolDir := t.TempDir()
	writeFakeDotnetRestore(t, toolDir, 0, `{}`, true)
	t.Setenv("PATH", toolDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	fixDetails := &FixDetails{
		SuggestedFixedVersion:  "13.0.1",
		IsDirectDependency:     true,
		Technology:             techutils.Nuget,
		ImpactedDependencyName: "Newtonsoft.Json",
		Components:             []formats.ComponentRow{{Evidences: []formats.Location{{File: filepath.Join("WithLockFile", "WithLockFile.csproj")}}}},
	}

	updater := &NugetPackageUpdater{}
	err = updater.UpdateDependency(fixDetails)
	assert.NoError(t, err)

	_, statErr = os.Stat(objDir)
	assert.True(t, os.IsNotExist(statErr), "obj/ created by restore should be cleaned up afterward")
}

// TestNugetUpdateDependencyPreservesPreexistingObjDir verifies that an obj/ directory that
// already existed before the fix (e.g. from a prior local build) is left alone, even though
// restore also touches it.
func TestNugetUpdateDependencyPreservesPreexistingObjDir(t *testing.T) {
	integration.InitUnitTest(t)
	testProjectPath := filepath.Join("..", "..", "..", "tests", "testdata", "projects", "package-managers", "nuget", "remediation-packageupdaters")
	currDir, err := os.Getwd()
	assert.NoError(t, err)

	tmpDir, err := os.MkdirTemp("", "nuget-test-*")
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()
	assert.NoError(t, biutils.CopyDir(testProjectPath, tmpDir, true, nil))
	assert.NoError(t, os.Chdir(tmpDir))
	defer func() {
		assert.NoError(t, os.Chdir(currDir))
	}()

	objDir := filepath.Join("WithLockFile", "obj")
	assert.NoError(t, os.MkdirAll(objDir, 0755))
	sentinelPath := filepath.Join(objDir, "sentinel.txt")
	assert.NoError(t, os.WriteFile(sentinelPath, []byte("keep-me"), 0644))

	toolDir := t.TempDir()
	writeFakeDotnetRestore(t, toolDir, 0, `{}`, true)
	t.Setenv("PATH", toolDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	fixDetails := &FixDetails{
		SuggestedFixedVersion:  "13.0.1",
		IsDirectDependency:     true,
		Technology:             techutils.Nuget,
		ImpactedDependencyName: "Newtonsoft.Json",
		Components:             []formats.ComponentRow{{Evidences: []formats.Location{{File: filepath.Join("WithLockFile", "WithLockFile.csproj")}}}},
	}

	updater := &NugetPackageUpdater{}
	err = updater.UpdateDependency(fixDetails)
	assert.NoError(t, err)

	sentinel, err := os.ReadFile(sentinelPath)
	assert.NoError(t, err)
	assert.Equal(t, "keep-me", string(sentinel))
}
