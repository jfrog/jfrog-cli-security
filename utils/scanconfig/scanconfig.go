package scanconfig

import (
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

type AppsSecurityConfig struct {
	XrayVersion    string             `json:"xray_version,omitempty"`
	EntitledForJas bool               `json:"entitled_for_jas,omitempty"`
	Targets        []ScanTargetConfig `json:"targets,omitempty"`
}

type ScanTarget struct {
	// Physical location of the target: Working directory (audit) / binary to scan (scan / docker scan)
	Target string `json:"target,omitempty"`
	// Logical name of the target (build name / module name / docker image name...)
	Name string `json:"name,omitempty"`
	// Optional field (not used only in build scan) to provide the technology of the scan
	Technology techutils.Technology `json:"technology,omitempty"`
}

type ScanTargetConfig struct {
	ScanTarget
	// Optional field (used in audit) to provide an exclusion list for the target
	ExcludePatterns []string `json:"exclude_patterns,omitempty"`

	ScaScanConfig *ScaConfig `json:"sca_scans,omitempty"`
	// All the JAS scanners that should be executed on the target with their configurations
	JasScanConfigs *ScannersConfig `json:"jas_scans,omitempty"`
}

type ScaConfig struct {
	// Optional field (used in audit) to provide the descriptor path that provided the dependencies for the scan
	// If not exists (binary / docker scan) the field should be empty and the data is in `Target`
	Descriptors           []string `json:"descriptors,omitempty"`
	RunApplicableScanners bool     `json:"run_applicable_scanners,omitempty"`
}

type ScannersConfig struct {
	Applicability *ScannerConfig     `json:"applicability,omitempty"`
	Secrets       *ScannerConfig     `json:"secrets,omitempty"`
	Iac           *ScannerConfig     `json:"iac,omitempty"`
	Sast          *SastScannerConfig `json:"sast,omitempty"`
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
