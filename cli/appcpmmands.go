package cli

import "github.com/jfrog/jfrog-cli-core/v2/plugins/components"

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

	serverDetails, err := createServerDetailsWithConfigOffer(c)
	if err != nil {
		return err
	}
	getScanProfileCmd := detect.NewDetectAppsCommand(serverDetails)

	return commandsCommon.Exec(getScanProfileCmd)
}