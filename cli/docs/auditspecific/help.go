package auditspecific

import "fmt"

// TODO: Deprecated commands (remove at next CLI major version)

const descFormat = "Execute an audit %s command, using the configured Xray details."

func GetGoDescription() string {
	return fmt.Sprintf(descFormat, "Go")
}

func GetGradleDescription() string {
	return fmt.Sprintf(descFormat, "Gradle")
}

func GetMvnDescription() string {
	return fmt.Sprintf(descFormat, "Maven")
}

func GetNpmDescription() string {
	return fmt.Sprintf(descFormat, "Npm")
}

func GetPipDescription() string {
	return fmt.Sprintf(descFormat, "Pip")
}

func GetPipenvDescription() string {
	return fmt.Sprintf(descFormat, "Pipenv")
}
