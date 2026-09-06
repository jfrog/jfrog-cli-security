package packageupdaters

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

func writeFakeDotnetRestore(t *testing.T, dir string, exitCode int, lockFileContent string) {
	if runtime.GOOS == "windows" {
		t.Skip("fake tool executable is a POSIX shell script")
	}
	script := fmt.Sprintf(`#!/bin/sh
projdir=$(dirname "$2")
cat > "$projdir/packages.lock.json" <<'EOF'
%s
EOF
exit %d
`, lockFileContent, exitCode)
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
	assert.Error(t, err)
	var unsupportedErr *ErrUnsupportedFix
	assert.True(t, errors.As(err, &unsupportedErr))
	assert.Equal(t, CentralPackageManagementFixNotSupported, unsupportedErr.ErrorType)

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
	writeFakeDotnetRestore(t, toolDir, 0, regeneratedLock)
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
	writeFakeDotnetRestore(t, toolDir, 1, `{"corrupted": true}`)
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
			name: "CentrallyManagedVersionNotSupported",
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
				assert.Equal(t, CentralPackageManagementFixNotSupported, unsupportedErr.ErrorType)
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
