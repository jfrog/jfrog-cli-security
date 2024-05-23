package auditgit

import "github.com/jfrog/jfrog-cli-security/commands/audit"

type GitAuditCommand struct {
	audit.AuditCommand
	audit.AuditParams
}

func NewGitAuditCommand(params *audit.AuditParams) *GitAuditCommand {
	if params == nil {
		params = audit.NewAuditParams()
	}
	return &GitAuditCommand{AuditParams: *params}
}

func (gaCmd *GitAuditCommand) Run() (err error) {
	// Calculate diff

	// Run audit
	// results, err := audit.RunAudit(&gaCmd.AuditParams)
	// if err != nil {
	// 	return
	// }
	// Filter results by added lines

	// Print results
	return
}