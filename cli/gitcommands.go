package cli

import (
	"github.com/jfrog/jfrog-cli-core/v2/common/progressbar"
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
	auditParams, err := createAuditParams(c)
	if err != nil {
		return err
	}
	cmd := auditgit.NewGitAuditCommand(auditParams)
	return utils.ReportErrorIfExists(progressbar.ExecWithProgress(cmd), cmd.ServerDetails)
}