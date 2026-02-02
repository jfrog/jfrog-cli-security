package plugin

import (
	"github.com/jfrog/gofrog/datastructures"
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
	// [Optional] Scan passes to customize the scanning process.
	ScanPasses []ScanPass `json:"passes,omitempty" yaml:"passes,omitempty"`
	// [Optional] JFrog connection parameters for enhanced scanning capabilities.
	JfrogConnection *JfrogConnectionParams `json:"jfrogConnection,omitempty" yaml:"jfrogConnection,omitempty"`
}

// ScanPass defines a single scan pass with specific engines
type ScanPass struct {
	Name        string   `json:"name" yaml:"name"`
	Extractors  []string `json:"extractors,omitempty" yaml:"extractors,omitempty"`
	Lookups     []string `json:"lookups,omitempty" yaml:"lookups,omitempty"`
	Aggregators []string `json:"aggregators,omitempty" yaml:"aggregators,omitempty"`
}

type JfrogConnectionParams struct {
	Url         string `json:"url" yaml:"url"`
	AccessToken string `json:"token,omitempty" yaml:"token,omitempty"`
}

// TechEngines defines the extractors and aggregators for each technology
type TechEngines struct {
	Extractors  []string
	Aggregators []string
}

// techToEnginesMap maps Technology to its corresponding extractors and aggregators
var techToEnginesMap = map[techutils.Technology]TechEngines{
	techutils.Maven: {
		Extractors:  []string{"maven"},
		Aggregators: []string{"maven"},
	},
	techutils.Gradle: {
		Extractors:  []string{"gradle", "gradle-lockfile"},
		Aggregators: []string{"maven"},
	},
	techutils.Npm: {
		Extractors:  []string{"npm"},
		Aggregators: []string{"npm"},
	},
	techutils.Yarn: {
		Extractors:  []string{"yarn"},
		Aggregators: []string{"npm"},
	},
	techutils.Pnpm: {
		Extractors:  []string{"pnpm"},
		Aggregators: []string{"npm"},
	},
	techutils.Go: {
		Extractors:  []string{"golang"},
		Aggregators: []string{"golang"},
	},
	techutils.Pip: {
		Extractors:  []string{"pypi", "python-root"},
		Aggregators: []string{"pypi"},
	},
	techutils.Pipenv: {
		Extractors:  []string{"pypi", "python-root"},
		Aggregators: []string{"pypi"},
	},
	techutils.Poetry: {
		Extractors:  []string{"pyproject-toml", "python-root"},
		Aggregators: []string{"pypi"},
	},
	techutils.Nuget: {
		Extractors:  []string{"nuget"},
		Aggregators: []string{"nuget"},
	},
	techutils.Dotnet: {
		Extractors:  []string{"nuget"},
		Aggregators: []string{"nuget"},
	},
	techutils.Conan: {
		Extractors:  []string{"conan"},
		Aggregators: []string{"conan"},
	},
	techutils.Gem: {
		Extractors:  []string{"gems"},
		Aggregators: []string{"gem"},
	},
}

// TechToPasses generates a single scan pass with extractors and aggregators for the given technologies
func TechToPasses(technologies []techutils.Technology) []ScanPass {
	if len(technologies) == 0 {

		return nil
	}
	extractorSet := datastructures.MakeSet[string]()
	aggregatorSet := datastructures.MakeSet[string]()
	for _, tech := range technologies {
		if engines, ok := techToEnginesMap[tech]; ok {
			for _, extractor := range engines.Extractors {
				extractorSet.Add(extractor)
			}
			for _, aggregator := range engines.Aggregators {
				aggregatorSet.Add(aggregator)
			}
		}
	}
	// If no engines were found for the provided technologies, return nil
	if extractorSet.Size() == 0 && aggregatorSet.Size() == 0 {
		return nil
	}
	return []ScanPass{
		{
			Name:        "Tech Specific Pass",
			Extractors:  extractorSet.ToSlice(),
			Aggregators: aggregatorSet.ToSlice(),
		},
	}
}
