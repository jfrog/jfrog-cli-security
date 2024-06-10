package enrich

import (
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
)

func GetDescription() string {
	return "Enrich CycloneDX format JSON located on the local file-system with Xray."
}

func GetArguments() []components.Argument {
	return []components.Argument{{Name: "source pattern", Description: `Specifies the local file system path of the JSON to be scanned.`}}
}
