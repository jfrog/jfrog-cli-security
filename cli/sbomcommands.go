package cli

import (
	commandsCommon "github.com/jfrog/jfrog-cli-core/v2/common/commands"
	"github.com/jfrog/jfrog-cli-core/v2/common/spec"
	pluginsCommon "github.com/jfrog/jfrog-cli-core/v2/plugins/common"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	flags "github.com/jfrog/jfrog-cli-security/cli/docs"
	enrichDocs "github.com/jfrog/jfrog-cli-security/cli/docs/scan/enrich"
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
			Category:    auditScanCategory,
			Action:      EnrichCmd,
		},
	}
}

func EnrichCmd(c *components.Context) error {
	if len(c.Arguments) == 0 && !c.IsFlagSet(flags.SpecFlag) {
		return pluginsCommon.PrintHelpAndReturnError("providing a <source pattern> argument is mandatory", c)
	}
	serverDetails, err := createServerDetailsWithConfigOffer(c)
	if err != nil {
		return err
	}
	err = validateXrayContext(c, serverDetails)
	if err != nil {
		return err
	}
	specFile := createDefaultScanSpec(c, addTrailingSlashToRepoPathIfNeeded(c))
	err = spec.ValidateSpec(specFile.Files, false, false)
	if err != nil {
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
