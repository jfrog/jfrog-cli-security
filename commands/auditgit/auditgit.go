package auditgit

import (
	"fmt"
	"os"

	"github.com/jfrog/jfrog-cli-security/commands/audit"
	clientutils "github.com/jfrog/jfrog-client-go/utils"

	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	initialCommitHash = "0000000000000000000000000000000000000000"
)

type GitAuditCommand struct {
	Source string
	Target string
	audit.AuditCommand
	audit.AuditParams
}

func NewGitAuditCommand(params *audit.AuditParams) *GitAuditCommand {
	if params == nil {
		params = audit.NewAuditParams()
	}
	return &GitAuditCommand{AuditParams: *params}
}

func (gaCmd *GitAuditCommand) SetSource(source string) *GitAuditCommand {
	gaCmd.Source = source
	return gaCmd
}

func (gaCmd *GitAuditCommand) SetTarget(target string) *GitAuditCommand {
	gaCmd.Target = target
	return gaCmd
}

func (gaCmd *GitAuditCommand) Run() (err error) {
	log.Info(fmt.Sprintf("Calculating diff between source commit `%s` and target commit `%s`", gaCmd.Source, gaCmd.Target))
	wd, err := os.Getwd()
	if err != nil {
		return
	}
	gitManager := clientutils.NewGitManager(wd)
	// Calculate diff
	filesChanged, err := GetFileDiff(gitManager, gaCmd.Source, gaCmd.Target)
	if err != nil {
		return
	}
	log.Info(fmt.Sprintf("Files changed: %v", filesChanged))
	// Run audit
	results, err := audit.RunAudit(&gaCmd.AuditParams)
	if err != nil {
		return
	}
	// Filter results by added lines

	// Print results
	return
}

// move to GitManager in client-go

// GetFileDiff returns the list of files changed between two commits.
// Source - can be a branch or a commit hash
// TODO: Target - can be a branch or a commit hash? (not sure) - need to check
func GetFileDiff(gitManager *clientutils.GitManager, source string, target string) (filesChanged []string, err error) {
	stdout, stderr, err := gitManager.ExecGit("diff", source, target)
	if err != nil {
		return
	}
	log.Debug(fmt.Sprintf("Diff output:\n%s", stdout))
	if stderr != "" {
		log.Warn(fmt.Sprintf("Git diff stderr:\n%s", stderr))
	}
	edits, err := ParseUnifiedDiffToEditOperations(stdout)
	if err != nil {
		return
	}
	return
}