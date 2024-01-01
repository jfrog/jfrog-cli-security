package cli

import (
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
)

func GetJfrogCliSecurityApp() components.App {
	app := components.CreateApp(
		"security",
		"v1.0.0",
		"Jfrog Security CLI embedded plugin",
		[]components.Command{},
	)
	return app
}
