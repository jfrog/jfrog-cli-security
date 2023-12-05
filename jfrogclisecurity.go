package jfrog_cli_security

import "fmt"

var agentName = "jfrog-cli-security"
var agentVersion = "1.0.0"

func GetVersion() string {
	return agentVersion
}

func GetName() string {
	return agentName
}

func GetUserAgent() string {
	return fmt.Sprintf("%s/%s", agentName, agentVersion)
}
