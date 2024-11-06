package audit

import (
	"fmt"

	sourceAudit "github.com/jfrog/jfrog-cli-security/commands/audit"
	"github.com/jfrog/jfrog-cli-security/utils/git"
	"github.com/jfrog/jfrog-client-go/xray/services"
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
	_, err = gaCmd.DetectGitInfo()
	if err != nil {
		return
	}
	return gaCmd.ProcessResultsAndOutput(sourceAudit.RunAudit(gaCmd.CreateAuditParams()))
}

func (gaCmd *GitAuditCommand) DetectGitInfo() (gitInfo *services.XscGitInfoContext, err error) {
	gaCmd.gitManager, err = git.NewGitManager(".")
	if err != nil {
		return nil, fmt.Errorf("Failed to found local git repository at the current directory: %v", err)
	}
	return git.GetGitContext(gaCmd.gitManager)
}
