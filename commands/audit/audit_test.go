package audit

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/stretchr/testify/assert"
)

func TestDetectScansToPreform(t *testing.T) {

	dir, cleanUp := createTestDir(t)

	tests := []struct {
		name     string
		wd       string
		params   func() *AuditParams
		expected []*results.TargetResults
	}{
		{
			name: "Test specific technologies",
			wd:   dir,
			params: func() *AuditParams {
				param := NewAuditParams().SetWorkingDirs([]string{dir})
				param.SetTechnologies([]string{"maven", "npm", "go"}).SetIsRecursiveScan(true)
				return param
			},
			expected: []*results.TargetResults{
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Maven,
						Target:     filepath.Join(dir, "dir", "maven"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{
							filepath.Join(dir, "dir", "maven", "pom.xml"),
							filepath.Join(dir, "dir", "maven", "maven-sub", "pom.xml"),
							filepath.Join(dir, "dir", "maven", "maven-sub2", "pom.xml"),
						},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Npm,
						Target:     filepath.Join(dir, "dir", "npm"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "dir", "npm", "package.json")},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Go,
						Target:     filepath.Join(dir, "dir", "go"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "dir", "go", "go.mod")},
					},
				},
			},
		},
		{
			name: "Test all",
			wd:   dir,
			params: func() *AuditParams {
				param := NewAuditParams().SetWorkingDirs([]string{dir})
				param.SetIsRecursiveScan(true)
				return param
			},
			expected: []*results.TargetResults{
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Maven,
						Target:     filepath.Join(dir, "dir", "maven"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{
							filepath.Join(dir, "dir", "maven", "pom.xml"),
							filepath.Join(dir, "dir", "maven", "maven-sub", "pom.xml"),
							filepath.Join(dir, "dir", "maven", "maven-sub2", "pom.xml"),
						},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Npm,
						Target:     filepath.Join(dir, "dir", "npm"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "dir", "npm", "package.json")},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Go,
						Target:     filepath.Join(dir, "dir", "go"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "dir", "go", "go.mod")},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Yarn,
						Target:     filepath.Join(dir, "yarn"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "yarn", "package.json")},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Pip,
						Target:     filepath.Join(dir, "yarn", "Pip"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "yarn", "Pip", "requirements.txt")},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Pipenv,
						Target:     filepath.Join(dir, "yarn", "Pipenv"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "yarn", "Pipenv", "Pipfile")},
					},
				},
				{
					ScanTarget: results.ScanTarget{
						Technology: techutils.Nuget,
						Target:     filepath.Join(dir, "Nuget"),
					},
					JasResults: &results.JasScansResults{},
					ScaResults: &results.ScaScanResults{
						Descriptors: []string{filepath.Join(dir, "Nuget", "project.sln"), filepath.Join(dir, "Nuget", "Nuget-sub", "project.csproj")},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := results.NewCommandResults("", true)
			detectScanTargets(results, test.params())
			if assert.Len(t, results.Targets, len(test.expected)) {
				for i := range results.Targets {
					if results.Targets[i].ScaResults != nil {
						sort.Strings(results.Targets[i].ScaResults.Descriptors)
					}
					if test.expected[i].ScaResults != nil {
						sort.Strings(test.expected[i].ScaResults.Descriptors)
					}
				}
			}
			assert.ElementsMatch(t, test.expected, results.Targets)
		})
	}

	cleanUp()
}
