package cli

import (
	"github.com/jfrog/jfrog-cli-core/v2/common/cliutils"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
)

const (
	securityCategory = "Security"
	cmdNamespace = "Command Namespaces"
)

func GetJfrogCliSecurityApp() components.App {
	app := components.CreateEmbeddedApp(
		"security",
		getAuditAndScansCommands(),
	)
	app.Subcommands = append(app.Subcommands, 
		components.Namespace{
			Name:        string(cliutils.Xr),
			Description: "Xray commands.",
			Commands:    getXrayNameSpaceCommands(),
			Category:    cmdNamespace,
		},
		components.Namespace{
			Name:        "app",
			Description: "Application commands detect information about the user application.",
			Hidden:      true,
			Commands:    getAppsCommands(),
			Category:    cmdNamespace,
		},
		components.Namespace{
			Name:        "git",
			Description: "Git commands.",
			Hidden:      true,
			Commands:    getGitNameSpaceCommands(),
			Category:    cmdNamespace,
		},
	)
	return app
}
