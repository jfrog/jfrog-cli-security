package configs

import (
	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
)

// User input (flags, args, env) to configure security scans
type DetectScanConfigParams struct {
	// Control scan params
	RequestedSubScans           []utils.SubScanType
	ThirdPartyApplicabilityScan bool
	ScanPolicyContext
	// General scan params
	ScanOutput
}

// Configuration for audit command
type AppsSecurityConfig struct {
	// Platform information
	XrayVersion    string `json:"xray_version,omitempty"`
	XscVersion     string `json:"xsc_version,omitempty"`
	EntitledForJas bool   `json:"entitled_for_jas,omitempty"`
	// Scan targets
	MultiScanId string             `json:"multi_scan_id,omitempty"`
	Targets     []ScanTargetConfig `json:"targets,omitempty"`
	// General scan configurations
	ScanPolicyContext
	ScanOutput
}

// Configuration for scan policy context
type ScanPolicyContext struct {
	Watches                []string `json:"watches,omitempty"`
	ProjectKey             string   `json:"project_key,omitempty"`
	RepoPath               string   `json:"repo_path,omitempty"`
	IncludeVulnerabilities bool     `json:"include_vulnerabilities,omitempty"`
}

// Configuration for scan output
type ScanOutput struct {
	MinSeverity  severityutils.Severity `json:"min_severity,omitempty"`
	FixableOnly  bool                   `json:"fixable_only,omitempty"`
	OutputFormat format.OutputFormat    `json:"output_format,omitempty"`
	ExtendedTable bool                  `json:"extended_table,omitempty"`
}

// Configuration for Jas scans on target
type JasScannersConfig struct {
	Applicability *ScannerConfig     `json:"applicability,omitempty"`
	Secrets       *ScannerConfig     `json:"secrets,omitempty"`
	Iac           *ScannerConfig     `json:"iac,omitempty"`
	Sast          *SastScannerConfig `json:"sast,omitempty"`
}

// If scanner config == nil: will not preform the scan
func (sc *JasScannersConfig) ShouldPreformScan(scan utils.SubScanType) bool {
	switch scan {
	case utils.ContextualAnalysisScan:
		return sc.Applicability != nil
	case utils.SecretsScan:
		return sc.Secrets != nil
	case utils.IacScan:
		return sc.Iac != nil
	case utils.SastScan:
		return sc.Sast != nil
	default:
		return false
	}
}

type ScannerConfig struct {
	WorkingDirs     []string `json:"working_dirs,omitempty"`
	ExcludePatterns []string `json:"exclude_patterns,omitempty"`
}

type SastScannerConfig struct {
	ScannerConfig `json:",inline"`
	Language      string   `json:"language,omitempty"`
	ExcludedRules []string `json:"excluded_rules,omitempty"`
}
