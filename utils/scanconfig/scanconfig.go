package scanconfig

import (
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

type AppsSecurityConfig struct {
	XrayVersion    string             `json:"xray_version,omitempty"`
	EntitledForJas bool               `json:"entitled_for_jas,omitempty"`
	Targets        []ScanTargetConfig `json:"targets,omitempty"`
}

func (c *AppsSecurityConfig) GetScanTarget(target string) *ScanTargetConfig {
	for _, t := range c.Targets {
		if t.Target == target {
			return &t
		}
	}
	return nil
}

func (c *AppsSecurityConfig) GetScanTargets() []string {
	var targets []string
	for _, target := range c.Targets {
		targets = append(targets, target.Target)
	}
	return targets
}

type ScanTarget struct {
	// Physical location of the target: Working directory (audit) / binary to scan (scan / docker scan)
	Target string `json:"target,omitempty"`
	// Logical name of the target (build name / module name / docker image name...)
	Name string `json:"name,omitempty"`
	// Optional field (not used only in build scan) to provide the technology of the scan
	Technology techutils.Technology `json:"technology,omitempty"`
}

func (t *ScanTarget) String() string {
	str := t.Target
	if t.Name != "" {
		str += " (" + t.Name + ")"
	}
	if t.Technology != "" {
		str += " [" + t.Technology.ToFormal() + "]"
	}
	return str
}

type ScanTargetConfig struct {
	ScanTarget
	// Optional field (used in audit) to provide an exclusion list for the target
	// ExcludePatterns []string `json:"exclude_patterns,omitempty"`

	// If nil - scanner will not be executed
	ScaScanConfig *ScaConfig `json:"sca_scans,omitempty"`
	// All the JAS scanners that should be executed on the target with their configurations
	JasScanConfigs *ScannersConfig `json:"jas_scans,omitempty"`
}

type ScaConfig struct {
	// Optional field (used in audit) to provide the descriptor path that provided the dependencies for the scan
	// If not exists (binary / docker scan) the field should be empty and the data is in `Target`
	Descriptors           []string `json:"descriptors,omitempty"`
	InstallCommand 		  string   `json:"install_command,omitempty"`
}

type ScannersConfig struct {
	// If nil - scanner will not be executed
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
