package upload

import "github.com/jfrog/jfrog-cli-core/v2/plugins/components"

func GetDescription() string {
	return "Upload a CycloneDX SBOM file to a JFrog repository."
}

func GetArguments() []components.Argument {
	return []components.Argument{{Name: "cycloneDx file path", Description: "Path to the JSON CycloneDX file to upload. (must be a '.cdx.json' extension)"}}
}
