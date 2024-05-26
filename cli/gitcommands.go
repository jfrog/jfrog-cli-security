package cli

import (
	"github.com/jfrog/jfrog-cli-core/v2/common/progressbar"
	pluginsCommon "github.com/jfrog/jfrog-cli-core/v2/plugins/common"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	flags "github.com/jfrog/jfrog-cli-security/cli/docs"
	auditDocs "github.com/jfrog/jfrog-cli-security/cli/docs/git/audit"
	"github.com/jfrog/jfrog-cli-security/commands/auditgit"
	"github.com/jfrog/jfrog-cli-security/utils"
)

func getGitNameSpaceCommands() []components.Command {
	return []components.Command{
		{
			Name:        "audit",
			Aliases:     []string{"gita"},
			Flags:       flags.GetCommandFlags(flags.Audit),
			Description: auditDocs.GetDescription(),
			Arguments:  auditDocs.GetArguments(),
			Category:    auditScanCategory,
			Hidden: 	 true,
			Action:      GitAuditCmd,
		},
	}
}

func GitAuditCmd(c *components.Context) error {
	if len(c.Arguments) < 2 {
		return pluginsCommon.WrongNumberOfArgumentsHandler(c)
	}
	auditParams, err := createAuditParams(c)
	if err != nil {
		return err
	}
	cmd := auditgit.NewGitAuditCommand(auditParams)
	cmd.SetSource(c.Arguments[0]).SetTarget(c.Arguments[1])
	return utils.ReportErrorIfExists(progressbar.ExecWithProgress(cmd), cmd.ServerDetails)
}