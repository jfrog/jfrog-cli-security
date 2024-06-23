package cli

import "github.com/jfrog/jfrog-cli-core/v2/plugins/components"

func getAppsCommands() []components.Command {
	return []components.Command{
		{
			Name:   "detect",
			Flags:  flags.GetCommandFlags(flags.ScanProfile),
			Description: "Detect the application security scan profile.",
			Hidden: true,
			Action: ScanProfileCmd,
		},
		{
			Name:   "dependencies",
			Flags:  flags.GetCommandFlags(flags.Dependencies),
			Description: "Get the application dependencies.",
			Hidden: true,
			Action: DependenciesCmd,
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