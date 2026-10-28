package xrayplugin

import (
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/stretchr/testify/assert"
)

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
