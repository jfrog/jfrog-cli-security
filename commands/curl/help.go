package curl

import "github.com/jfrog/jfrog-cli-core/v2/plugins/components"

// var Usage = []string{"xr curl [command options] <curl command>"}

func GetDescription() string {
	return "Execute a cUrl command, using the configured Xray details."
}

func GetArguments() []components.Argument {
	return []components.Argument{{Name: "curl command", Description: "cUrl command to run."}}
}