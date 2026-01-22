package sast_server

import (
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
)

func GetDescription() string {
	return "Runs a local source code analysis as a local SAST server, allowing access to tools which reflect source code analysis"
}

func GetArguments() []components.Argument {
	return []components.Argument{}
}

func GetFlags() []components.Flag {
	return []components.Flag{
		components.NewStringFlag("port", "Specifies the port to run the SAST server on."),
	}
}
