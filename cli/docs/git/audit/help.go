package audit

import "github.com/jfrog/jfrog-cli-core/v2/plugins/components"

func GetDescription() string {
	return "Audit a git repository. This command will compare the sourceCommit against the targetCommit and return the security vulnerabilities added by the sourceCommit against the targetCommit."
}

func GetArguments() []components.Argument {
	return []components.Argument{
		{Name: "sourceCommit", Description: "sourceCommit to compare against."},
		{Name: "targetCommit", Description: "targetCommit to compare against."},
	}
}