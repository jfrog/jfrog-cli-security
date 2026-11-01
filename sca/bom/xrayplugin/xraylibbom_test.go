package xrayplugin

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/sca/bom/xrayplugin/plugin"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/stretchr/testify/assert"
)

type scannerStub struct {
	config plugin.Config
}

func (s *scannerStub) Scan(_ string, config plugin.Config) (*cyclonedx.BOM, error) {
	s.config = config
	return nil, nil
}

func TestIgnorePatternsForTarget(t *testing.T) {
	profileModule := services.Module{
		ExcludePatterns: []string{`.\vendor`, "./generated"},
		ScanConfig: services.ScanConfig{
			ScaScannerConfig: services.ScaScannerConfig{ExcludePatterns: []string{"*dist*"}},
		},
	}
	tests := []struct {
		name     string
		target   results.ScanTarget
		expected []string
	}{
		{
			name:     "no profile uses the flag patterns",
			target:   results.ScanTarget{Exclude: []string{"tools/teleport/examples/*"}},
			expected: []string{"tools/teleport/examples/*"},
		},
		{
			name:     "no profile and no flag uses the defaults",
			target:   results.ScanTarget{},
			expected: utils.DefaultScaExcludePatterns,
		},
		{
			name:     "leading dot slash and backslashes are normalized",
			target:   results.ScanTarget{Exclude: []string{`.\tools\teleport`, "./examples/*"}},
			expected: []string{"tools/teleport", "examples/*"},
		},
		{
			name:     "explicit empty flag stays empty",
			target:   results.ScanTarget{Exclude: []string{""}},
			expected: []string{},
		},
		{
			name:     "dot slash alone stays empty",
			target:   results.ScanTarget{Exclude: []string{"./"}},
			expected: []string{},
		},
		{
			name:     "escaped glob characters are preserved",
			target:   results.ScanTarget{Exclude: []string{`directory\*`, `directory\?`}},
			expected: []string{`directory\*`, `directory\?`},
		},
		{
			name:     "globstar and trailing slash patterns are preserved",
			target:   results.ScanTarget{Exclude: []string{"**/directory", "directory/"}},
			expected: []string{"**/directory", "directory/"},
		},
		{
			name:     "flag style is not rewritten to doublestar",
			target:   results.ScanTarget{Exclude: []string{"*node_modules*"}},
			expected: []string{"*node_modules*"},
		},
		{
			name: "profile patterns replace the flag",
			target: results.ScanTarget{
				Exclude:              []string{"tools/teleport/examples/*"},
				CentralConfigModules: []services.Module{profileModule},
			},
			expected: []string{"vendor", "generated", "*dist*"},
		},
		{
			name: "empty profile exclusions are not replaced by the flag or the defaults",
			target: results.ScanTarget{
				Exclude:              utils.DefaultScaExcludePatterns,
				CentralConfigModules: []services.Module{{}},
			},
			expected: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ElementsMatch(t, tt.expected, ignorePatternsForTarget(tt.target))
		})
	}
}

func TestExecuteScannerPassesNormalizedIgnorePatterns(t *testing.T) {
	scanner := &scannerStub{}
	target := results.ScanTarget{
		Target:  "test-project",
		Exclude: []string{`.\vendor`, "./generated"},
	}

	_, err := NewXrayLibBomGenerator().executeScanner(scanner, target)

	assert.NoError(t, err)
	assert.Equal(t, []string{"vendor", "generated"}, scanner.config.IgnorePatterns)
}
