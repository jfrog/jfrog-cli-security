package curation

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/commands/curation/githubactions"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/results/output"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

// workflowsSubdir is the standard location of a repo's workflow files, relative to its root.
const workflowsSubdir = ".github/workflows"

// CurationActionsCommand curates the GitHub Actions that actually resolved on this job's
// runner, using the runner's own action cache as the source of truth (not the workflow YAML
// alone - see githubactions.DiscoverActionCache).
type CurationActionsCommand struct {
	workingDir      string
	actionsCacheDir string
	workflowFile    string
	decider         githubactions.ActionCurationDecider
}

// NewCurationActionsCommand returns a command wired to the mock decider - no real
// Artifactory/Catalog decision service exists yet for GitHub Actions.
func NewCurationActionsCommand() *CurationActionsCommand {
	return &CurationActionsCommand{decider: githubactions.NewMockActionCurationDecider()}
}

// SetWorkingDir overrides the repo root; defaults to the process's working directory.
func (c *CurationActionsCommand) SetWorkingDir(dir string) *CurationActionsCommand {
	c.workingDir = dir
	return c
}

// SetActionsCacheDir overrides the runner's action cache directory; defaults to
// githubactions.DefaultActionsCacheDir() (derived from RUNNER_WORKSPACE). Mainly useful for
// local/test runs outside an actual GitHub Actions runner.
func (c *CurationActionsCommand) SetActionsCacheDir(dir string) *CurationActionsCommand {
	c.actionsCacheDir = dir
	return c
}

// SetWorkflowFile restricts workflow-YAML cross-referencing to a single file instead of
// scanning every file under .github/workflows.
func (c *CurationActionsCommand) SetWorkflowFile(path string) *CurationActionsCommand {
	c.workflowFile = path
	return c
}

// SetDecider overrides the curation decider; exposed for tests.
func (c *CurationActionsCommand) SetDecider(decider githubactions.ActionCurationDecider) *CurationActionsCommand {
	c.decider = decider
	return c
}

func (c *CurationActionsCommand) CommandName() string {
	return "curation_actions"
}

// Run discovers the actions resolved on this job's runner, cross-references them against the
// job's workflow YAML for Subpath/Parent metadata, decides a curation outcome per action,
// prints and records the report, and returns an error if any action was Rejected.
func (c *CurationActionsCommand) Run() (err error) {
	workingDir := c.workingDir
	if workingDir == "" {
		if workingDir, err = coreutils.GetWorkingDirectory(); err != nil {
			return err
		}
	}

	actionsCacheDir := c.actionsCacheDir
	if actionsCacheDir == "" {
		if actionsCacheDir, err = githubactions.DefaultActionsCacheDir(); err != nil {
			return err
		}
	}

	discovered, err := githubactions.DiscoverActionCache(actionsCacheDir)
	if err != nil {
		return err
	}
	if len(discovered) == 0 {
		log.Info("No GitHub Actions found in the runner's action cache - nothing to curate.")
		return nil
	}

	used, target, err := c.parseWorkflowUses(workingDir)
	if err != nil {
		return err
	}
	discovered = githubactions.CrossReference(discovered, used)

	rows := make([]githubactions.ActionReportRow, 0, len(discovered))
	var decideErrs error
	for _, ref := range discovered {
		result, decideErr := c.decider.Decide(ref)
		if decideErr != nil {
			decideErrs = errors.Join(decideErrs, fmt.Errorf("deciding curation status for %s/%s@%s: %w", ref.Owner, ref.Repo, ref.Ref, decideErr))
		}
		rows = append(rows, githubactions.NewActionReportRow(ref, result))
	}

	log.Info(fmt.Sprintf("GitHub Actions Curation Report:\n%s", githubactions.RenderMarkdownTable(rows)))

	if recordErr := c.recordSummary(rows, target); recordErr != nil {
		log.Warn(fmt.Sprintf("failed to record GitHub Actions curation summary: %v", recordErr))
	}

	if decideErrs != nil {
		return decideErrs
	}
	if githubactions.AnyRejected(rows) {
		return errors.New("one or more GitHub Actions were rejected by curation policy")
	}
	return nil
}

// parseWorkflowUses returns the uses: refs to cross-reference against, and a target label for
// the report (the specific workflow file, or the workflows directory when scanning all of them).
func (c *CurationActionsCommand) parseWorkflowUses(workingDir string) (used []githubactions.WorkflowUse, target string, err error) {
	if c.workflowFile != "" {
		used, err = githubactions.ParseWorkflowUses(c.workflowFile)
		return used, c.workflowFile, err
	}
	workflowsDir := filepath.Join(workingDir, workflowsSubdir)
	used, err = githubactions.ParseWorkflowsDir(workflowsDir)
	return used, workflowsDir, err
}

// recordSummary records the report through the same "security" job-summary manager
// curation-audit already uses (output.RecordSecurityCommandSummary), so it's picked up by the
// existing generate-summary-markdown pipeline with no changes needed outside this repo. This is
// a no-op when JFROG_CLI_COMMAND_SUMMARY_OUTPUT_DIR isn't set (e.g. a local/manual run) - the
// console log above is what carries the result in that case.
func (c *CurationActionsCommand) recordSummary(rows []githubactions.ActionReportRow, target string) error {
	actions := make([]formats.CuratedAction, 0, len(rows))
	for _, row := range rows {
		actions = append(actions, formats.CuratedAction{
			Action: row.Action,
			Ref:    row.Ref,
			Parent: row.Parent,
			Status: row.Status,
			Notes:  row.Notes,
		})
	}
	return output.RecordSecurityCommandSummary(output.NewCurationActionsSummary(actions, target))
}
