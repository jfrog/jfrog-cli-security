package source_mcp

import (
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
)

func GetDescription() string {
	return "Runs a local source code analysis as a local MCP server, allowing access to tools which reflect source code analysis"
}

func GetArguments() []components.Argument {
	return []components.Argument{{Name: "Source path", Description: `Specifies the local file system path of source code to analyze.`}}
}
