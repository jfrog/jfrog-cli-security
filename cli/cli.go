package cli

import (
	"github.com/jfrog/jfrog-cli-core/v2/common/cliutils"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
)

func GetJfrogCliSecurityApp() components.App {
	app := components.CreateEmbeddedApp(
		"security",
		GetAuditAndScansCommands(),
	)
	app.Subcommands = append(app.Subcommands, components.Namespace{
		Name:        string(cliutils.Xr),
		Description: "Xray commands.",
		Commands:    GetXrayNameSpaceCommands(),
	})
	return app
}
