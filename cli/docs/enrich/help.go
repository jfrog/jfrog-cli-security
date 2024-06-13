package enrich

import (
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	"github.com/jfrog/jfrog-cli-security/cli/docs"
)

func GetDescription() string {
	return "Enrich CycloneDX format JSON located on the local file-system with Xray."
}

func GetArguments() []components.Argument {
	return []components.Argument{{Name: "source pattern", ReplaceWithFlag: docs.SpecFlag, Description: `Specifies the local file system path of the JSON to be scanned.`}}
}
