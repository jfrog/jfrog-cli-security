package audit

import (
	sourceAudit "github.com/jfrog/jfrog-cli-security/commands/audit"
)

type GitAuditCommand struct {
	sourceAudit.AuditCommand
}

func NewGitAuditCommand(auditCmd sourceAudit.AuditCommand) *GitAuditCommand {
	return &GitAuditCommand{auditCmd}
}

func (gaCmd *GitAuditCommand) CommandName() string {
	return "git_audit"
}

func (gaCmd *GitAuditCommand) Run() (err error) {
	return
}
