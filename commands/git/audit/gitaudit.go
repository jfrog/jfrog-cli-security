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
	_, gitInfo, err := git.DetectGitInfo()
	if err != nil {
		return
	}
	return gaCmd.ProcessResultsAndOutput(RunGitAudit(NewGitAuditParams(gaCmd.CreateAuditParams(gitInfo))))
}

func RunGitAudit(params *GitAuditParams) (cmdResults *results.SecurityCommandResults) {
	return sourceAudit.RunAudit(&params.AuditParams)
}
