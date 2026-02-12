package plugin

// Config holds the configuration for Xray plugin library options.
type Config struct {
	// The BOMRef of the scanned target, will be used at the Metadata and considered the Root.
	BomRef string `json:"bom-ref,omitempty"`
	// The component type of the target ("application" / "library" / "file"...), will be used at the Metadata component.
	Type string `json:"type,omitempty"`
	// The name of the target, will be used at the Metadata component.
	Name string `json:"name,omitempty"`
	// [Optional] The version of the target, will be used at the Metadata component.
	Version string `json:"version,omitempty"`
	// [Optional] Patterns (git ignore like) to ignore when scanning the target.
	IgnorePatterns []string `json:"ignorePatterns,omitempty"`
	// [Optional] Specific directories to scan.
	IncludeDirs []string `json:"includeDirs,omitempty"`
}
