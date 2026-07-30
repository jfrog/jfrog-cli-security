package auditspecific

import "fmt"

// TODO: Deprecated commands (remove at next CLI major version)

const descFormat = "Execute an audit %s command, using the configured Xray details."

const aiDescFormat = `Run a tech-restricted audit limited to %s dependencies. Deprecated: prefer ` + "`jf audit --%s`" + ` over this dedicated subcommand. Use only when integrating with legacy scripts that still call the per-technology audit command.

When to use:
- Maintaining older CI scripts that have not yet migrated to the unified jf audit interface.

Prerequisites:
- Configured JFrog Platform server (jf c add) with Xray entitlement.
- The %s toolchain installed and reachable on PATH.

Common patterns:
  $ jf audit --%s

Gotchas:
- This command emits a deprecation warning at runtime and will be removed in the next CLI major version.

Related: jf audit`

func GetGoDescription() string {
	return fmt.Sprintf(descFormat, "Go")
}

func GetGoAIDescription() string {
	return fmt.Sprintf(aiDescFormat, "Go", "go", "Go", "go")
}

func GetGradleDescription() string {
	return fmt.Sprintf(descFormat, "Gradle")
}

func GetGradleAIDescription() string {
	return fmt.Sprintf(aiDescFormat, "Gradle", "gradle", "Gradle", "gradle")
}

func GetMvnDescription() string {
	return fmt.Sprintf(descFormat, "Maven")
}

func GetMvnAIDescription() string {
	return fmt.Sprintf(aiDescFormat, "Maven", "mvn", "Maven", "mvn")
}

func GetNpmDescription() string {
	return fmt.Sprintf(descFormat, "Npm")
}

func GetNpmAIDescription() string {
	return fmt.Sprintf(aiDescFormat, "npm", "npm", "Node.js/npm", "npm")
}

func GetPipDescription() string {
	return fmt.Sprintf(descFormat, "Pip")
}

func GetPipAIDescription() string {
	return fmt.Sprintf(aiDescFormat, "Pip (Python)", "pip", "Python with pip", "pip")
}

func GetPipenvDescription() string {
	return fmt.Sprintf(descFormat, "Pipenv")
}

func GetPipenvAIDescription() string {
	return fmt.Sprintf(aiDescFormat, "Pipenv (Python)", "pipenv", "Python with Pipenv", "pipenv")
}
