package cli

import (
	commandsCommon "github.com/jfrog/jfrog-cli-core/v2/common/commands"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"

	"github.com/jfrog/jfrog-cli-security/cli/flags"
	"github.com/jfrog/jfrog-cli-security/commands/app/detect"
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
	}
}

func DetectCmd(c *components.Context) error {

	serverDetails, err := flags.ParsePlatformConnectionFlags(c)
	if err != nil {
		return err
	}
	getScanProfileCmd := detect.NewDetectAppsCommand(serverDetails)

	return commandsCommon.Exec(getScanProfileCmd)
}
