package dockerscan

import "github.com/jfrog/jfrog-cli-core/v2/plugins/components"

func GetDescription() string {
	return "Scan local docker image using the docker client and Xray."
}

func GetArguments() []components.Argument {
	return []components.Argument{
		{
			Name:        "image tag",
			Description: "The docker image tag to scan.",
		},
	}
}
