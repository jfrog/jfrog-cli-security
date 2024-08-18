package main

import (
	"github.com/jfrog/jfrog-cli-core/v2/plugins"
	"github.com/jfrog/jfrog-cli-security/cli"
)

func main() {
	app := cli.GetJfrogCliSecurityApp()
	// Add docker scan command
	app.Commands = append(app.Commands, cli.DockerScanMockCommand())
	plugins.PluginMain(app)
}
