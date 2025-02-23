package audit

import (
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
)

func GetDescription() string {
	return "Audit your local git repository project for security issues."
}

func GetArguments() []components.Argument {
	return []components.Argument{{Name: "target", Description: `Diff mode, run git diff between the cwd commit to the given target commit and audit the differences.
	You can specify a commit hash, a branch name a tag name or a reference like HEAD~1.`}}
}
