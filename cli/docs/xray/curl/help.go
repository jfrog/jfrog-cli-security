package curl

import "github.com/jfrog/jfrog-cli-core/v2/plugins/components"

func GetDescription() string {
	return "Execute a cURL command, using the configured Xray details."
}

func GetArguments() []components.Argument {
	return []components.Argument{{Name: "curl command", Description: "cURL command to run."}}
}
