package cli

import (
	commandsCommon "github.com/jfrog/jfrog-cli-core/v2/common/commands"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	"github.com/jfrog/jfrog-cli-security/commands/app/detect"

	flags "github.com/jfrog/jfrog-cli-security/cli/docs"
)

func getAppsCommands() []components.Command {
	return []components.Command{
		{
			Name:        "detect",
			Flags:       flags.GetCommandFlags(flags.Detect),
			Description: "Detect the application security scan profile.",
			Hidden:      true,
			Action:      DetectCmd,
		},
		{
			Name:        "dependencies",
			Flags:       flags.GetCommandFlags(flags.Dependencies),
			Description: "Get the application dependencies.",
			Hidden:      true,
			Action:      DependenciesCmd,
		},
		// {
		// 	Name: "install",
		// 	Flags: flags.GetCommandFlags(flags.Install),
		// 	Description: "Install the application with supported package managers, apply curation if needed.",
		// 	Hidden: true,
		// 	Action: InstallCmd,
		// },
	}
}

func DetectCmd(c *components.Context) error {

	serverDetails, err := createServerDetailsWithConfigOffer(c)
	if err != nil {
		return err
	}
	getScanProfileCmd := detect.NewDetectAppsCommand(serverDetails)

	return commandsCommon.Exec(getScanProfileCmd)
}
