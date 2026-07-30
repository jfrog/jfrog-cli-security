package results

import (
	"testing"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	xscServices "github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/stretchr/testify/assert"
)

func TestScanTarget_String(t *testing.T) {
	tests := []struct {
		name     string
		target   ScanTarget
		expected string
	}{
		{
			name:     "Target only, no tech",
			target:   ScanTarget{Target: "/path/to/project"},
			expected: "/path/to/project [unknown]",
		},
		{
			name:     "Target with technology",
			target:   ScanTarget{Target: "/path/to/project", Technologies: []techutils.Technology{techutils.Npm}},
			expected: "/path/to/project [npm]",
		},
		{
			name:     "Target with name overrides path",
			target:   ScanTarget{Target: "/path/to/project", Name: "my-project", Technologies: []techutils.Technology{techutils.Go}},
			expected: "my-project [Go]",
		},
		{
			name: "Target with include dirs",
			target: ScanTarget{
				Target:       "/root",
				Include:      []string{"/root/sub1", "/root/sub2"},
				Technologies: []techutils.Technology{techutils.Maven},
			},
			expected: "/root {sub1, sub2} [Maven]",
		},
		{
			name: "Target with include dirs and name - name wins",
			target: ScanTarget{
				Target:       "/root",
				Include:      []string{"/root/sub1"},
				Name:         "override-name",
				Technologies: []techutils.Technology{techutils.Pip},
			},
			expected: "override-name [Pip]",
		},
		{
			name: "Target with multiple technologies",
			target: ScanTarget{
				Target:       "/path/to/project",
				Technologies: []techutils.Technology{techutils.Npm, techutils.Go},
			},
			expected: "/path/to/project [npm, Go]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.target.String())
		})
	}
}

func TestScanTarget_IsScanRequestedByCentralConfig(t *testing.T) {
	enabledModule := xscServices.Module{
		ScanConfig: xscServices.ScanConfig{
			ScaScannerConfig:                xscServices.ScaScannerConfig{EnableScaScan: true},
			ContextualAnalysisScannerConfig: xscServices.CaScannerConfig{EnableCaScan: true},
			IacScannerConfig:                xscServices.IacScannerConfig{EnableIacScan: true},
			SecretsScannerConfig:            xscServices.SecretsScannerConfig{EnableSecretsScan: true},
			SastScannerConfig:               xscServices.SastScannerConfig{EnableSastScan: true},
		},
	}

	tests := []struct {
		name     string
		target   ScanTarget
		scanType utils.SubScanType
		expected *bool
	}{
		{
			name:     "No modules - returns nil",
			target:   ScanTarget{},
			scanType: utils.ScaScan,
			expected: nil,
		},
		{
			name:     "SCA enabled",
			target:   ScanTarget{CentralConfigModules: []xscServices.Module{enabledModule}},
			scanType: utils.ScaScan,
			expected: utils.NewBoolPtr(true),
		},
		{
			name:     "IaC enabled",
			target:   ScanTarget{CentralConfigModules: []xscServices.Module{enabledModule}},
			scanType: utils.IacScan,
			expected: utils.NewBoolPtr(true),
		},
		{
			name:     "Secrets enabled",
			target:   ScanTarget{CentralConfigModules: []xscServices.Module{enabledModule}},
			scanType: utils.SecretsScan,
			expected: utils.NewBoolPtr(true),
		},
		{
			name:     "SAST enabled",
			target:   ScanTarget{CentralConfigModules: []xscServices.Module{enabledModule}},
			scanType: utils.SastScan,
			expected: utils.NewBoolPtr(true),
		},
		{
			name: "Applicability requires both CA and SCA enabled",
			target: ScanTarget{CentralConfigModules: []xscServices.Module{{
				ScanConfig: xscServices.ScanConfig{
					ContextualAnalysisScannerConfig: xscServices.CaScannerConfig{EnableCaScan: true},
					ScaScannerConfig:                xscServices.ScaScannerConfig{EnableScaScan: false},
				},
			}}},
			scanType: utils.ContextualAnalysisScan,
			expected: utils.NewBoolPtr(false),
		},
		{
			name:     "Applicability with both CA and SCA enabled",
			target:   ScanTarget{CentralConfigModules: []xscServices.Module{enabledModule}},
			scanType: utils.ContextualAnalysisScan,
			expected: utils.NewBoolPtr(true),
		},
		{
			name: "SCA disabled",
			target: ScanTarget{CentralConfigModules: []xscServices.Module{{
				ScanConfig: xscServices.ScanConfig{
					ScaScannerConfig: xscServices.ScaScannerConfig{EnableScaScan: false},
				},
			}}},
			scanType: utils.ScaScan,
			expected: utils.NewBoolPtr(false),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.target.IsScanRequestedByCentralConfig(tt.scanType))
		})
	}
}

func TestScanTarget_ShouldValidateSecrets(t *testing.T) {
	moduleWithValidation := xscServices.Module{
		ScanConfig: xscServices.ScanConfig{
			SecretsScannerConfig: xscServices.SecretsScannerConfig{
				EnableSecretsScan: true,
				ValidateSecrets:   true,
			},
		},
	}
	moduleWithoutValidation := xscServices.Module{
		ScanConfig: xscServices.ScanConfig{
			SecretsScannerConfig: xscServices.SecretsScannerConfig{
				EnableSecretsScan: true,
				ValidateSecrets:   false,
			},
		},
	}
	moduleValidationDisabledSecrets := xscServices.Module{
		ScanConfig: xscServices.ScanConfig{
			SecretsScannerConfig: xscServices.SecretsScannerConfig{
				EnableSecretsScan: false,
				ValidateSecrets:   true,
			},
		},
	}

	tests := []struct {
		name         string
		target       ScanTarget
		cliRequested bool
		expected     bool
	}{
		{
			name:         "No modules - CLI requested",
			target:       ScanTarget{},
			cliRequested: true,
			expected:     true,
		},
		{
			name:         "No modules - CLI not requested",
			target:       ScanTarget{},
			cliRequested: false,
			expected:     false,
		},
		{
			name:         "Module with validate_secrets enabled",
			target:       ScanTarget{CentralConfigModules: []xscServices.Module{moduleWithValidation}},
			cliRequested: false,
			expected:     true,
		},
		{
			name:         "Module with validate_secrets disabled - CLI ignored",
			target:       ScanTarget{CentralConfigModules: []xscServices.Module{moduleWithoutValidation}},
			cliRequested: true,
			expected:     false,
		},
		{
			name:         "ValidateSecrets without EnableSecretsScan - false",
			target:       ScanTarget{CentralConfigModules: []xscServices.Module{moduleValidationDisabledSecrets}},
			cliRequested: true,
			expected:     false,
		},
		{
			name: "Any module with validation enabled",
			target: ScanTarget{CentralConfigModules: []xscServices.Module{
				moduleWithoutValidation,
				moduleWithValidation,
			}},
			cliRequested: false,
			expected:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.target.ShouldValidateSecrets(tt.cliRequested))
		})
	}
}

func TestSecurityCommandResults_IsSecretValidationActive(t *testing.T) {
	moduleWithValidation := xscServices.Module{
		ScanConfig: xscServices.ScanConfig{
			SecretsScannerConfig: xscServices.SecretsScannerConfig{
				EnableSecretsScan: true,
				ValidateSecrets:   true,
			},
		},
	}
	cmdResults := NewCommandResults(utils.SourceCode).SetSecretValidation(true)
	cmdResults.NewScanResults(ScanTarget{CentralConfigModules: []xscServices.Module{moduleWithValidation}})

	assert.True(t, cmdResults.IsSecretValidationActive(false))
	assert.False(t, NewCommandResults(utils.SourceCode).SetSecretValidation(false).IsSecretValidationActive(true))
}

func TestScanTarget_GetCentralConfigExclusions(t *testing.T) {
	tests := []struct {
		name     string
		target   ScanTarget
		scanType utils.SubScanType
		expected []string
	}{
		{
			name:     "No modules - empty",
			target:   ScanTarget{},
			scanType: utils.ScaScan,
			expected: []string{},
		},
		{
			name: "SCA exclusions",
			target: ScanTarget{CentralConfigModules: []xscServices.Module{{
				ScanConfig: xscServices.ScanConfig{
					ScaScannerConfig: xscServices.ScaScannerConfig{ExcludePatterns: []string{"**/vendor/**"}},
				},
			}}},
			scanType: utils.ScaScan,
			expected: []string{"**/vendor/**"},
		},
		{
			name: "Secrets exclusions",
			target: ScanTarget{CentralConfigModules: []xscServices.Module{{
				ScanConfig: xscServices.ScanConfig{
					SecretsScannerConfig: xscServices.SecretsScannerConfig{ExcludePatterns: []string{"**/*.key"}},
				},
			}}},
			scanType: utils.SecretsScan,
			expected: []string{"**/*.key"},
		},
		{
			name: "IaC exclusions",
			target: ScanTarget{CentralConfigModules: []xscServices.Module{{
				ScanConfig: xscServices.ScanConfig{
					IacScannerConfig: xscServices.IacScannerConfig{ExcludePatterns: []string{"**/test-infra/**"}},
				},
			}}},
			scanType: utils.IacScan,
			expected: []string{"**/test-infra/**"},
		},
		{
			name: "SAST exclusions",
			target: ScanTarget{CentralConfigModules: []xscServices.Module{{
				ScanConfig: xscServices.ScanConfig{
					SastScannerConfig: xscServices.SastScannerConfig{ExcludePatterns: []string{"**/generated/**"}},
				},
			}}},
			scanType: utils.SastScan,
			expected: []string{"**/generated/**"},
		},
		{
			name: "Contextual analysis exclusions",
			target: ScanTarget{CentralConfigModules: []xscServices.Module{{
				ScanConfig: xscServices.ScanConfig{
					ContextualAnalysisScannerConfig: xscServices.CaScannerConfig{ExcludePatterns: []string{"**/mock/**"}},
				},
			}}},
			scanType: utils.ContextualAnalysisScan,
			expected: []string{"**/mock/**"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ElementsMatch(t, tt.expected, tt.target.GetCentralConfigExclusions(tt.scanType))
		})
	}
}

func TestScanTarget_GetDeprecatedAppsConfigModuleExclusions(t *testing.T) {
	tests := []struct {
		name     string
		target   ScanTarget
		scanType jasutils.JasScanType
		expected []string
	}{
		{
			name:     "Nil module - returns nil",
			target:   ScanTarget{},
			scanType: jasutils.Secrets,
			expected: nil,
		},
		{
			name: "Module with base exclusions only",
			target: ScanTarget{DeprecatedAppsConfigModule: &jfrogappsconfig.Module{
				ExcludePatterns: []string{"**/dist/**"},
			}},
			scanType: jasutils.IaC,
			expected: []string{"**/dist/**"},
		},
		{
			name: "Module with secrets scanner exclusions",
			target: ScanTarget{DeprecatedAppsConfigModule: &jfrogappsconfig.Module{
				ExcludePatterns: []string{"**/dist/**"},
				Scanners: jfrogappsconfig.Scanners{
					Secrets: &jfrogappsconfig.Scanner{ExcludePatterns: []string{"**/*.pem"}},
				},
			}},
			scanType: jasutils.Secrets,
			expected: []string{"**/dist/**", "**/*.pem"},
		},
		{
			name: "Module with SAST scanner exclusions",
			target: ScanTarget{DeprecatedAppsConfigModule: &jfrogappsconfig.Module{
				Scanners: jfrogappsconfig.Scanners{
					Sast: &jfrogappsconfig.SastScanner{Scanner: jfrogappsconfig.Scanner{ExcludePatterns: []string{"**/test/**"}}},
				},
			}},
			scanType: jasutils.Sast,
			expected: []string{"**/test/**"},
		},
		{
			name: "Module with IaC scanner exclusions",
			target: ScanTarget{DeprecatedAppsConfigModule: &jfrogappsconfig.Module{
				Scanners: jfrogappsconfig.Scanners{
					Iac: &jfrogappsconfig.Scanner{ExcludePatterns: []string{"**/sandbox/**"}},
				},
			}},
			scanType: jasutils.IaC,
			expected: []string{"**/sandbox/**"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ElementsMatch(t, tt.expected, tt.target.GetDeprecatedAppsConfigModuleExclusions(tt.scanType))
		})
	}
}
