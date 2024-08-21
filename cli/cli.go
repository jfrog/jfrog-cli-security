package cli

import (
	"github.com/jfrog/jfrog-cli-core/v2/common/cliutils"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
)

const securityCategory = "Security"

func GetJfrogCliSecurityApp() components.App {
	app := components.CreateEmbeddedApp(
		"security",
		getAuditAndScansCommands(),
	)
	app.Subcommands = append(app.Subcommands, components.Namespace{
		Name:        string(cliutils.Xr),
		Description: "Xray commands.",
		Commands:    getXrayNameSpaceCommands(),
		Category:    "Command Namespaces",
	})
	app.Subcommands = append(app.Subcommands, components.Namespace{
		Name:        "git",
		Description: "Git commands.",
		Hidden:      true,
		Commands:    getGitNameSpaceCommands(),
		Category:    "Command Namespaces",
	})
	return app
}
