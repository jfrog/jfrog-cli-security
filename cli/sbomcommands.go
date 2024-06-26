package cli

import (
	"github.com/jfrog/jfrog-cli-core/v2/common/cliutils"
	commandsCommon "github.com/jfrog/jfrog-cli-core/v2/common/commands"
	"github.com/jfrog/jfrog-cli-core/v2/common/spec"
	pluginsCommon "github.com/jfrog/jfrog-cli-core/v2/plugins/common"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	coreConfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	flags "github.com/jfrog/jfrog-cli-security/cli/docs"
	enrichDocs "github.com/jfrog/jfrog-cli-security/cli/docs/enrich"
	"github.com/jfrog/jfrog-cli-security/commands/enrich"
)

func getSbomCommands() []components.Command {
	return []components.Command{
		{
			Name:        "enrich",
			Aliases:     []string{"se"},
			Flags:       flags.GetCommandFlags(flags.Enrich),
			Description: enrichDocs.GetDescription(),
			Arguments:   enrichDocs.GetArguments(),
			Action:      EnrichCmd,
		},
	}
}

func createServerDetails(c *components.Context) (*coreConfig.ServerDetails, error) {
	return pluginsCommon.CreateServerDetailsWithConfigOffer(c, true, cliutils.Sbom)
}

func EnrichCmd(c *components.Context) error {
	if len(c.Arguments) == 0 {
		return pluginsCommon.PrintHelpAndReturnError("providing a <source pattern> argument is mandatory", c)
	}
	serverDetails, err := createServerDetails(c)
	if err != nil {
		return err
	}
	if err = validateXrayContext(c, serverDetails); err != nil {
		return err
	}
	specFile := createDefaultScanSpec(c, addTrailingSlashToRepoPathIfNeeded(c))
	if err = spec.ValidateSpec(specFile.Files, false, false); err != nil {
		return err
	}
	threads, err := pluginsCommon.GetThreadsCount(c)
	if err != nil {
		return err
	}
	EnrichCmd := enrich.NewEnrichCommand().
		SetServerDetails(serverDetails).
		SetThreads(threads).
		SetSpec(specFile)
	return commandsCommon.Exec(EnrichCmd)
}
