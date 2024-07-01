package sarifparser

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
)

func TestGetComponentSarifLocation(t *testing.T) {
	testCases := []struct {
		name           string
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedOutput, getComponentSarifLocation(tc.component))
		})
	}
}

func TestGetVulnerabilityOrViolationSarifHeadline(t *testing.T) {
	assert.Equal(t, "[CVE-2022-1234] loadsh 1.4.1", getScaIssueSarifHeadline("loadsh", "1.4.1", "CVE-2022-1234"))
	assert.NotEqual(t, "[CVE-2022-1234] comp 1.4.1", getScaIssueSarifHeadline("comp", "1.2.1", "CVE-2022-1234"))
}

func TestgetXrayLicenseSarifHeadline(t *testing.T) {
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
			expectedDescription: "| Severity Score | Contextual Analysis | Direct Dependencies | Fixed Versions     |\n|  :---:  |  :---:  |  :---:  |  :---:  |\n| 3.0      | Not covered       | `example-package 3.0.0`       | 3.0.1   |",
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
