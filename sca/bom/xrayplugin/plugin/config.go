package plugin

import (
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

// Config holds the configuration for Xray plugin library options.
type Config struct {
	// The BOMRef of the scanned target, will be used at the Metadata and considered the Root.
	BomRef string `json:"bom-ref,omitempty" yaml:"bom-ref,omitempty"`
	// The component type of the target ("application" / "library" / "file"...), will be used at the Metadata component.
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	// The name of the target, will be used at the Metadata component.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// [Optional] The logging level for the scan process. if not set will get from environment variable or default to "info".
	LogLevel string `json:"logLevel,omitempty" yaml:"logLevel,omitempty"`
	// [Optional] The version of the target, will be used at the Metadata component.
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
	// [Optional] Patterns (git ignore like) to ignore when scanning the target.
	IgnorePatterns []string `json:"ignorePatterns,omitempty" yaml:"ignorePatterns,omitempty"`
	// [Optional] Ecosystems to scan.
	Ecosystems []techutils.Technology `json:"ecosystems,omitempty" yaml:"ecosystems,omitempty"`
}
