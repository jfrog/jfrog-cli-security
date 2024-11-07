package audit

import (
	sourceAudit "github.com/jfrog/jfrog-cli-security/commands/audit"
)

type GitAuditParams struct {
	sourceAudit.AuditParams
}

func NewGitAuditParams(params *sourceAudit.AuditParams) *GitAuditParams {
	return &GitAuditParams{*params}
}
