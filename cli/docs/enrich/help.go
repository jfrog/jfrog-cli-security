package enrich

import (
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
)

func GetDescription() string {
	return "Enrich sbom format JSON located on the local file-system with Xray."
}

func GetArguments() []components.Argument {
	return []components.Argument{{Name: "File path", Description: `Specifies the local file system path of the JSON to be scanned.`}}
}
