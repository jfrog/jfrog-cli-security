package nuget

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Fixtures: verbatim `dotnet restore` outputs captured from real SDK versions.

// Original bug report; SDK .NET 10.0.101.
const dotnet10_NU1010_BugReport = `  Determining projects to restore...
/private/var/folders/y7/7szwlg1171b0qdh6zvp1b15m0000gn/T/jfrog.cli.temp.-1777997622-3704502098/tests/Sdlc.Vantage.Dotnet.Service.IntegrationTests/Sdlc.Vantage.Dotnet.Service.IntegrationTests.csproj : error NU1010: The following PackageReference items do not define a corresponding PackageVersion item: Microsoft.ApplicationInsights. Projects using Central Package Management must declare PackageReference and PackageVersion items with matching names. For more information, visit https://aka.ms/nuget/cpm/gettingstarted [/private/var/folders/y7/7szwlg1171b0qdh6zvp1b15m0000gn/T/jfrog.cli.temp.-1777997622-3704502098/Sdlc.Vantage.Dotnet.Service.sln]
/private/var/folders/y7/7szwlg1171b0qdh6zvp1b15m0000gn/T/jfrog.cli.temp.-1777997622-3704502098/tests/Sdlc.Vantage.Dotnet.Service.Tests/Sdlc.Vantage.Dotnet.Service.Tests.csproj : error NU1010: The following PackageReference items do not define a corresponding PackageVersion item: Microsoft.ApplicationInsights. Projects using Central Package Management must declare PackageReference and PackageVersion items with matching names. For more information, visit https://aka.ms/nuget/cpm/gettingstarted [/private/var/folders/y7/7szwlg1171b0qdh6zvp1b15m0000gn/T/jfrog.cli.temp.-1777997622-3704502098/Sdlc.Vantage.Dotnet.Service.sln]
/usr/local/share/dotnet/sdk/10.0.101/NuGet.targets(196,5): error : Object reference not set to an instance of an object. [/private/var/folders/y7/7szwlg1171b0qdh6zvp1b15m0000gn/T/jfrog.cli.temp.-1777997622-3704502098/Sdlc.Vantage.Dotnet.Service.sln]`

// SDK .NET 8.0.421, one PackageReference missing while at least one other has a version.
const dotnet8_NU1010_Single = `  Determining projects to restore...
/private/tmp/dotnet-cpm-test/cpm-repro/LibB/LibB.csproj : error NU1010: The PackageReference items Microsoft.ApplicationInsights do not have corresponding PackageVersion. [/private/tmp/dotnet-cpm-test/cpm-repro/cpm-repro.sln]
/private/tmp/dotnet-cpm-test/cpm-repro/LibA/LibA.csproj : error NU1010: The PackageReference items Microsoft.ApplicationInsights do not have corresponding PackageVersion. [/private/tmp/dotnet-cpm-test/cpm-repro/cpm-repro.sln]
  Failed to restore /private/tmp/dotnet-cpm-test/cpm-repro/LibA/LibA.csproj (in 38 ms).
  Failed to restore /private/tmp/dotnet-cpm-test/cpm-repro/LibB/LibB.csproj (in 38 ms).`

// SDK .NET 8.0.421, multiple missing names emitted semicolon-separated.
const dotnet8_NU1010_Multi = `  Determining projects to restore...
/private/tmp/dotnet-cpm-test/cpm-repro/LibA/LibA.csproj : error NU1010: The PackageReference items Microsoft.ApplicationInsights;Serilog do not have corresponding PackageVersion. [/private/tmp/dotnet-cpm-test/cpm-repro/cpm-repro.sln]
/private/tmp/dotnet-cpm-test/cpm-repro/LibB/LibB.csproj : error NU1010: The PackageReference items Microsoft.ApplicationInsights;Serilog do not have corresponding PackageVersion. [/private/tmp/dotnet-cpm-test/cpm-repro/cpm-repro.sln]
  Failed to restore /private/tmp/dotnet-cpm-test/cpm-repro/LibB/LibB.csproj (in 38 ms).
  Failed to restore /private/tmp/dotnet-cpm-test/cpm-repro/LibA/LibA.csproj (in 38 ms).`

// SDK .NET 8.0.421, every reference missing — NuGet switches to NU1008.
const dotnet8_NU1008 = `  Determining projects to restore...
/private/tmp/dotnet-cpm-test/cpm-repro/LibA/LibA.csproj : error NU1008: Projects that use central package version management should not define the version on the PackageReference items but on the PackageVersion items: Microsoft.ApplicationInsights;Newtonsoft.Json. [/private/tmp/dotnet-cpm-test/cpm-repro/cpm-repro.sln]
/private/tmp/dotnet-cpm-test/cpm-repro/LibB/LibB.csproj : error NU1008: Projects that use central package version management should not define the version on the PackageReference items but on the PackageVersion items: Microsoft.ApplicationInsights;Newtonsoft.Json. [/private/tmp/dotnet-cpm-test/cpm-repro/cpm-repro.sln]
  Failed to restore /private/tmp/dotnet-cpm-test/cpm-repro/LibA/LibA.csproj (in 41 ms).
  Failed to restore /private/tmp/dotnet-cpm-test/cpm-repro/LibB/LibB.csproj (in 41 ms).`

// SDK .NET 9.0.314: NuGet 6.12 emits NU1008 even when only one reference is missing.
const dotnet9_NU1008_Single = `  Determining projects to restore...
/private/tmp/dotnet-cpm-test/cpm-sdk9-A_single/LibB/LibB.csproj : error NU1008: Projects that use central package version management should not define the version on the PackageReference items but on the PackageVersion items: Microsoft.ApplicationInsights. [/private/tmp/dotnet-cpm-test/cpm-sdk9-A_single/cpm-sdk9-A_single.sln]
/private/tmp/dotnet-cpm-test/cpm-sdk9-A_single/LibA/LibA.csproj : error NU1008: Projects that use central package version management should not define the version on the PackageReference items but on the PackageVersion items: Microsoft.ApplicationInsights. [/private/tmp/dotnet-cpm-test/cpm-sdk9-A_single/cpm-sdk9-A_single.sln]
  Failed to restore /private/tmp/dotnet-cpm-test/cpm-sdk9-A_single/LibB/LibB.csproj (in 35 ms).
  Failed to restore /private/tmp/dotnet-cpm-test/cpm-sdk9-A_single/LibA/LibA.csproj (in 35 ms).`

// SDK .NET 9.0.314, partial-mismatch case.
const dotnet9_NU1008_Multi = `  Determining projects to restore...
/private/tmp/dotnet-cpm-test/cpm-sdk9-B_multi_partial/LibA/LibA.csproj : error NU1008: Projects that use central package version management should not define the version on the PackageReference items but on the PackageVersion items: Microsoft.ApplicationInsights;Serilog. [/private/tmp/dotnet-cpm-test/cpm-sdk9-B_multi_partial/cpm-sdk9-B_multi_partial.sln]
/private/tmp/dotnet-cpm-test/cpm-sdk9-B_multi_partial/LibB/LibB.csproj : error NU1008: Projects that use central package version management should not define the version on the PackageReference items but on the PackageVersion items: Microsoft.ApplicationInsights;Serilog. [/private/tmp/dotnet-cpm-test/cpm-sdk9-B_multi_partial/cpm-sdk9-B_multi_partial.sln]
  Failed to restore /private/tmp/dotnet-cpm-test/cpm-sdk9-B_multi_partial/LibA/LibA.csproj (in 36 ms).
  Failed to restore /private/tmp/dotnet-cpm-test/cpm-sdk9-B_multi_partial/LibB/LibB.csproj (in 36 ms).`

func TestParseNugetErrors_Dotnet10_BugReport(t *testing.T) {
	entries := parseNugetErrors(dotnet10_NU1010_BugReport)
	if assert.Len(t, entries, 2, "trailing NuGet.targets line must be ignored") {
		for _, e := range entries {
			assert.Equal(t, "NU1010", e.code)
			assert.True(t, strings.HasSuffix(e.csproj, ".csproj"), "csproj path: %s", e.csproj)
		}
	}
}

func TestParseNugetErrors_Dotnet8_NU1010_Single(t *testing.T) {
	entries := parseNugetErrors(dotnet8_NU1010_Single)
	if assert.Len(t, entries, 2) {
		for _, e := range entries {
			assert.Equal(t, "NU1010", e.code)
			assert.Contains(t, e.message, "Microsoft.ApplicationInsights")
		}
	}
}

func TestParseNugetErrors_Dotnet8_NU1008(t *testing.T) {
	entries := parseNugetErrors(dotnet8_NU1008)
	if assert.Len(t, entries, 2) {
		for _, e := range entries {
			assert.Equal(t, "NU1008", e.code)
		}
	}
}

func TestParseNugetErrors_IgnoresUnstructuredLines(t *testing.T) {
	// NuGet.targets line has `error :` without an NU code; must not be parsed.
	for _, e := range parseNugetErrors(dotnet10_NU1010_BugReport) {
		assert.NotContains(t, e.csproj, "NuGet.targets")
	}
}

func TestParseNugetErrors_FsprojAndVbproj(t *testing.T) {
	out := `/x/My.fsproj : error NU1010: The PackageReference items Foo do not have corresponding PackageVersion.
/y/My.vbproj : error NU1010: The PackageReference items Bar do not have corresponding PackageVersion.`
	assert.Len(t, parseNugetErrors(out), 2)
}

func TestParseNugetErrors_EmptyAndNoMatches(t *testing.T) {
	assert.Empty(t, parseNugetErrors(""))
	assert.Empty(t, parseNugetErrors("nothing structured here\njust regular text\n"))
}

func TestExtractCPMMismatchPackages_Dotnet10_NU1010_Single(t *testing.T) {
	msg := "The following PackageReference items do not define a corresponding PackageVersion item: Microsoft.ApplicationInsights. Projects using Central Package Management must declare PackageReference and PackageVersion items with matching names."
	assert.Equal(t, []string{"Microsoft.ApplicationInsights"}, extractCPMMismatchPackages(msg))
}

func TestExtractCPMMismatchPackages_Dotnet10_NU1010_Multi(t *testing.T) {
	msg := "The following PackageReference items do not define a corresponding PackageVersion item: Pkg.A, Pkg.B, Pkg.C. Projects using Central Package Management..."
	assert.Equal(t, []string{"Pkg.A", "Pkg.B", "Pkg.C"}, extractCPMMismatchPackages(msg))
}

func TestExtractCPMMismatchPackages_Dotnet8_NU1010_Single(t *testing.T) {
	msg := "The PackageReference items Microsoft.ApplicationInsights do not have corresponding PackageVersion."
	assert.Equal(t, []string{"Microsoft.ApplicationInsights"}, extractCPMMismatchPackages(msg))
}

func TestExtractCPMMismatchPackages_Dotnet8_NU1010_Multi(t *testing.T) {
	msg := "The PackageReference items Microsoft.ApplicationInsights;Serilog do not have corresponding PackageVersion."
	assert.Equal(t, []string{"Microsoft.ApplicationInsights", "Serilog"}, extractCPMMismatchPackages(msg))
}

func TestExtractCPMMismatchPackages_Dotnet8_NU1008(t *testing.T) {
	msg := "Projects that use central package version management should not define the version on the PackageReference items but on the PackageVersion items: Microsoft.ApplicationInsights;Newtonsoft.Json."
	assert.Equal(t, []string{"Microsoft.ApplicationInsights", "Newtonsoft.Json"}, extractCPMMismatchPackages(msg))
}

func TestExtractCPMMismatchPackages_MarkerMissing(t *testing.T) {
	assert.Nil(t, extractCPMMismatchPackages("Some unrelated error text"))
	assert.Nil(t, extractCPMMismatchPackages(""))
}

func TestFormatCPMMismatchError_SinglePackage(t *testing.T) {
	err := formatCPMMismatchError([]string{"Microsoft.ApplicationInsights"})
	if !assert.Error(t, err) {
		return
	}
	msg := err.Error()
	assert.Contains(t, msg, "Central Package Management mismatch:")
	assert.Contains(t, msg,
		"PackageReference 'Microsoft.ApplicationInsights' does not have a corresponding PackageVersion entry.")
	assert.Contains(t, msg,
		"Ensure 'Microsoft.ApplicationInsights' is defined in Directory.Packages.props, then try again.")
}

func TestFormatCPMMismatchError_MultiplePackagesSortedAndPluralised(t *testing.T) {
	// Input order reversed to exercise sorting.
	err := formatCPMMismatchError([]string{"Pkg.B", "Pkg.A"})
	if !assert.Error(t, err) {
		return
	}
	msg := err.Error()
	assert.Contains(t, msg, "Central Package Management mismatch:")
	assert.Contains(t, msg,
		"PackageReferences 'Pkg.A', 'Pkg.B' do not have corresponding PackageVersion entries.")
	assert.Contains(t, msg,
		"Ensure they are defined in Directory.Packages.props, then try again.")
	assert.NotContains(t, msg, "does not have a corresponding")
}

func TestTranslateRestoreError_Dotnet10_BugReportReproduction(t *testing.T) {
	err := translateRestoreError([]byte(dotnet10_NU1010_BugReport), errors.New("exit status 1"), "")
	if !assert.Error(t, err) {
		return
	}
	msg := err.Error()
	assert.Contains(t, msg, "Central Package Management mismatch:")
	assert.Contains(t, msg, "Microsoft.ApplicationInsights")
	assert.Contains(t, msg, "Directory.Packages.props")
	assert.Contains(t, msg, "try again")
	assert.NotContains(t, msg, "jfrog.cli.temp.")
	assert.NotContains(t, msg, "exit status 1")
	assert.NotContains(t, msg, "'dotnet restore' command failed")
}

func TestTranslateRestoreError_Dotnet8_NU1010_Single(t *testing.T) {
	err := translateRestoreError([]byte(dotnet8_NU1010_Single), errors.New("exit status 1"), "")
	if !assert.Error(t, err) {
		return
	}
	msg := err.Error()
	assert.Contains(t, msg, "Central Package Management mismatch:")
	assert.Contains(t, msg,
		"PackageReference 'Microsoft.ApplicationInsights' does not have a corresponding PackageVersion entry.")
	assert.NotContains(t, msg, "exit status 1")
}

func TestTranslateRestoreError_Dotnet8_NU1010_Multi(t *testing.T) {
	err := translateRestoreError([]byte(dotnet8_NU1010_Multi), errors.New("exit status 1"), "")
	if !assert.Error(t, err) {
		return
	}
	msg := err.Error()
	assert.Contains(t, msg, "Central Package Management mismatch:")
	// Output is alphabetical, comma-separated regardless of source separator.
	assert.Contains(t, msg,
		"PackageReferences 'Microsoft.ApplicationInsights', 'Serilog' do not have corresponding PackageVersion entries.")
}

func TestTranslateRestoreError_Dotnet8_NU1008(t *testing.T) {
	err := translateRestoreError([]byte(dotnet8_NU1008), errors.New("exit status 1"), "")
	if !assert.Error(t, err) {
		return
	}
	msg := err.Error()
	assert.Contains(t, msg, "Central Package Management mismatch:")
	assert.Contains(t, msg,
		"PackageReferences 'Microsoft.ApplicationInsights', 'Newtonsoft.Json' do not have corresponding PackageVersion entries.")
}

func TestTranslateRestoreError_UnrecognizedCode_FallbackPreserved(t *testing.T) {
	// NU1101 isn't a CPM problem; raw output must come through unchanged.
	raw := `  Determining projects to restore...
/x/Foo.csproj : error NU1101: Unable to find package Definitely.Not.A.Real.Package.`
	err := translateRestoreError([]byte(raw), errors.New("exit status 1"), "")
	if !assert.Error(t, err) {
		return
	}
	msg := err.Error()
	assert.Contains(t, msg, "'dotnet restore' command failed")
	assert.Contains(t, msg, "exit status 1")
	assert.Contains(t, msg, "NU1101")
	assert.NotContains(t, msg, "Central Package Management")
}

func TestTranslateRestoreError_EmptyOutput_FallbackPreserved(t *testing.T) {
	err := translateRestoreError(nil, errors.New("exit status 1"), "")
	if !assert.Error(t, err) {
		return
	}
	assert.Contains(t, err.Error(), "'dotnet restore' command failed")
	assert.Contains(t, err.Error(), "exit status 1")
}

func TestTranslateRestoreError_Dotnet9_NU1008_Single(t *testing.T) {
	err := translateRestoreError([]byte(dotnet9_NU1008_Single), errors.New("exit status 1"), "")
	if !assert.Error(t, err) {
		return
	}
	msg := err.Error()
	assert.Contains(t, msg, "Central Package Management mismatch:")
	assert.Contains(t, msg,
		"PackageReference 'Microsoft.ApplicationInsights' does not have a corresponding PackageVersion entry.")
	assert.NotContains(t, msg, "exit status 1")
}

func TestTranslateRestoreError_Dotnet9_NU1008_Multi(t *testing.T) {
	err := translateRestoreError([]byte(dotnet9_NU1008_Multi), errors.New("exit status 1"), "")
	if !assert.Error(t, err) {
		return
	}
	msg := err.Error()
	assert.Contains(t, msg, "Central Package Management mismatch:")
	assert.Contains(t, msg,
		"PackageReferences 'Microsoft.ApplicationInsights', 'Serilog' do not have corresponding PackageVersion entries.")
}

// Safety-net: CPM code recognised but wording unknown — must still produce a
// friendly CPM message, never the raw `exit status 1` blob.

func TestTranslateRestoreError_CPMCode_UnknownWording_EmitsGenericMessage(t *testing.T) {
	raw := `  Determining projects to restore...
/x/Foo.csproj : error NU1010: PackageReferences are missing matching central versions, please review your packages file.
/y/Bar.csproj : error NU1010: PackageReferences are missing matching central versions, please review your packages file.`
	err := translateRestoreError([]byte(raw), errors.New("exit status 1"), "")
	if !assert.Error(t, err) {
		return
	}
	msg := err.Error()
	assert.Contains(t, msg, "Central Package Management mismatch:")
	assert.Contains(t, msg, "Directory.Packages.props")
	assert.Contains(t, msg, "try again")
	assert.NotContains(t, msg, "exit status 1")
	assert.NotContains(t, msg, "'dotnet restore' command failed")
	assert.NotContains(t, msg, "PackageReference 'PackageReferences")
}

func TestTranslateRestoreError_CPMCode_LocalisedOutput_EmitsGenericMessage(t *testing.T) {
	// French locale: code stays NU1010, prose is translated; anchors won't match.
	raw := `/x/Mon.csproj : error NU1010: Les éléments PackageReference ne correspondent à aucune entrée PackageVersion centrale.`
	err := translateRestoreError([]byte(raw), errors.New("exit status 1"), "")
	if !assert.Error(t, err) {
		return
	}
	msg := err.Error()
	assert.Contains(t, msg, "Central Package Management mismatch:")
	assert.Contains(t, msg, "Directory.Packages.props")
	assert.NotContains(t, msg, "exit status 1")
}

func TestTranslateRestoreError_NU1008_UnknownWording_EmitsGenericMessage(t *testing.T) {
	// Confirms the safety net is keyed on the code map, not on a single code.
	raw := `/x/Foo.csproj : error NU1008: Mismatch detected in central package version management configuration.`
	err := translateRestoreError([]byte(raw), errors.New("exit status 1"), "")
	if !assert.Error(t, err) {
		return
	}
	msg := err.Error()
	assert.Contains(t, msg, "Central Package Management mismatch:")
	assert.Contains(t, msg, "Directory.Packages.props")
	assert.NotContains(t, msg, "exit status 1")
}

func TestFormatGenericCPMMismatchError_ShapeAndContent(t *testing.T) {
	err := formatGenericCPMMismatchError()
	if !assert.Error(t, err) {
		return
	}
	msg := err.Error()
	assert.Contains(t, msg, "Central Package Management mismatch:")
	assert.Contains(t, msg, "Directory.Packages.props")
	assert.Contains(t, msg, "try again")
	// Generic message omits per-package detail; no single-quoted names.
	assert.NotContains(t, msg, "PackageReference '")
	assert.NotContains(t, msg, "PackageReferences '")
}
