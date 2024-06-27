package configs

import (
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

// User input (flags, args, env) to configure targets and their technologies
type DetectTargetsParams struct {
	// File system information
	WorkingDirs []string
	Exclusions  []string
}

// Configuration for scan target
type ScanTarget struct {
	// Physical location of the target: Working directory (audit) / binary to scan (scan / docker scan)
	Target string `json:"target,omitempty"`
	// Logical name of the target (build name / module name / docker image name...)
	Name string `json:"name,omitempty"`
	// Optional field (not used only in build scan) to provide the technology of the target
	Technology techutils.Technology `json:"technology,omitempty"`
}

type ScanTargetConfig struct {
	ScanTarget
	ScaScanTarget
	// Optional field (used in audit) to provide an exclusion list for the target
	// ExcludePatterns []string `json:"exclude_patterns,omitempty"`

	// If nil - scanner will not be executed
	// ScaScanConfig *TechConfig `json:"sca_scans,omitempty"`
	// Optional field (used in source code scans) to provide custom configuration for the target technology
	ScaScanConfig *TargetTechConfig `json:"tech_config,omitempty"`
	// All the JAS scanners that should be executed on the target with their configurations
	JasScanConfigs *JasScannersConfig `json:"jas_scans,omitempty"`
}

// Configuration for sca scan target
type ScaScanTarget struct {
	
	
}

func (c *AppsSecurityConfig) GetScanTarget(target string) *ScanTargetConfig {
	for _, t := range c.Targets {
		if t.Target == target {
			return &t
		}
	}
	return nil
}

func (c *AppsSecurityConfig) GetScanTargetByTechnology() map[techutils.Technology][]*ScanTargetConfig {
	targets := make(map[techutils.Technology][]*ScanTargetConfig)
	for _, target := range c.Targets {
		if target.Technology != "" {
			targets[techutils.Unknown] = append(targets[techutils.Unknown], &target)
		}
		targets[target.Technology] = append(targets[target.Technology], &target)
	}
	return targets
}

func (c *AppsSecurityConfig) GetScanTargets() []string {
	var targets []string
	for _, target := range c.Targets {
		targets = append(targets, target.Target)
	}
	return targets
}

func (t *ScanTarget) String() string {
	str := ""
	if t.Name != "" {
		str += " (" + t.Name + ")"
	}
	if t.Technology != "" {
		str += " [" + t.Technology.ToFormal() + "]"
	}
	return str + t.Target
}
