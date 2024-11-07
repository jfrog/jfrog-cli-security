package audit

import (
	sourceAudit "github.com/jfrog/jfrog-cli-security/commands/audit"
	"github.com/jfrog/jfrog-cli-security/utils/git"
	"github.com/jfrog/jfrog-cli-security/utils/results"
)

type GitAuditCommand struct {
	sourceAudit.AuditCommand
	gitManager *git.GitManager
}

func NewGitAuditCommand(auditCmd *sourceAudit.AuditCommand) *GitAuditCommand {
	return &GitAuditCommand{*auditCmd, &git.GitManager{}}
}

func (gaCmd *GitAuditCommand) CommandName() string {
	return "git_audit"
}

func (gaCmd *GitAuditCommand) Run() (err error) {
	return gaCmd.ProcessResultsAndOutput(RunGitAudit(gaCmd.CreateAuditParams()))
}

func RunGitAudit(params *sourceAudit.AuditParams) (cmdResults *results.SecurityCommandResults) {
	_, _, err := git.DetectGitInfo()
	if err != nil {
		return
	}

	return sourceAudit.RunAudit(params)
}
