package curation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/jfrog-cli-security/commands/curation/githubactions"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/results/output"
)

const flagGithubRepo = "github-repo"

// CurationActionsCommand curates the GitHub Actions that actually resolved on this job's
// runner, using the runner's own action cache as the source of truth (not the workflow YAML
// alone - see githubactions.DiscoverActionCache).
type CurationActionsCommand struct {
	workingDir      string
	actionsCacheDir string
	workflowFile    string
	jobID           string
	githubRepo      string
	decider         githubactions.ActionCurationDecider
	vcsRepoResolver githubactions.ArtifactoryVcsRepoResolver
}

// NewCurationActionsCommand returns a command wired to the mock decider - no real
// Artifactory/Catalog decision service exists yet for GitHub Actions.
func NewCurationActionsCommand() *CurationActionsCommand {
	return &CurationActionsCommand{
		decider:         githubactions.NewMockActionCurationDecider(),
		vcsRepoResolver: githubactions.NewMockArtifactoryVcsRepoResolver(),
	}
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

// SetWorkflowFile overrides the workflow file to cross-reference against; defaults to the
// running workflow derived from GITHUB_WORKFLOW_REF. A relative path resolves against the
// working directory. Mainly useful for local/test runs outside an actual GitHub Actions runner.
func (c *CurationActionsCommand) SetWorkflowFile(path string) *CurationActionsCommand {
	c.workflowFile = path
	return c
}

// SetJobID overrides the workflow job to scope curation to; defaults to the running job's
// job_id from GITHUB_JOB. Mainly useful for local/test runs outside an actual runner.
func (c *CurationActionsCommand) SetJobID(jobID string) *CurationActionsCommand {
	c.jobID = jobID
	return c
}

// SetGithubRepo overrides the GitHub repository to resolve the Artifactory VCS repository from;
// defaults to GITHUB_REPOSITORY.
func (c *CurationActionsCommand) SetGithubRepo(githubRepo string) *CurationActionsCommand {
	c.githubRepo = githubRepo
	return c
}

// SetVcsRepoResolver overrides the Artifactory VCS repository resolver; exposed for tests.
func (c *CurationActionsCommand) SetVcsRepoResolver(resolver githubactions.ArtifactoryVcsRepoResolver) *CurationActionsCommand {
	c.vcsRepoResolver = resolver
	return c
}

// SetDecider overrides the curation decider; exposed for tests.
func (c *CurationActionsCommand) SetDecider(decider githubactions.ActionCurationDecider) *CurationActionsCommand {
	c.decider = decider
	return c
}

func (c *CurationActionsCommand) CommandName() string {
	return "curate_gh_actions"
}

// Run discovers the actions resolved on this job's runner, decides a curation outcome per
// action, prints and records the report, and returns an error if any action was Rejected. The
// delivery action (jfrog/setup-jfrog-cli) itself is always excluded.
//
// If any action cannot be decided at all, Run returns that error and produces no report and no
// job summary - a partial one would omit exactly the actions whose status is unknown.
//
// It runs in one of two modes, depending on whether the workflow YAML is available:
//
//   - ATTRIBUTED - a workflow file was identified. Its "uses:" lines
//     supply the direct references, so entries are cross-referenced for Parent and Subpath
//     metadata and narrowed to this workflow's dependency graph. The report carries a Parent
//     column.
//   - STRUCTURE-ONLY - no workflow file. The runner's action cache is taken as-is: every
//     discovered entry is curated, with no Parent or Subpath metadata and no Parent column.
func (c *CurationActionsCommand) Run() (err error) {
	// A one-shot CLI invocation, so this is the root of the call tree. No deadline is imposed
	// here: how long to wait on the decision service, and whether a timeout should fail the job
	// or let it through, are curation-system policy rather than this command's to decide.
	ctx := context.Background()

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

	used, target, attributed, err := c.parseWorkflowUses(workingDir)
	if err != nil {
		return err
	}
	if attributed {
		discovered = githubactions.CrossReference(discovered, used)
		discovered = githubactions.FilterRelevant(discovered, used)
	}
	discovered = githubactions.ExcludeDeliveryAction(discovered)
	if len(discovered) == 0 {
		log.Info("No GitHub Actions relevant to this workflow found in the runner's action cache - nothing to curate.")
		return nil
	}

	// Resolved once, after the early returns above: a job with nothing to curate makes no call.
	artifactoryVcsRepo, err := c.resolveArtifactoryVcsRepo(ctx)
	if err != nil {
		return err
	}

	rows := make([]githubactions.ActionReportRow, 0, len(discovered))
	var decideErrs error
	for _, ref := range discovered {
		result, decideErr := c.decider.Decide(ctx, artifactoryVcsRepo, ref)
		if decideErr != nil {
			decideErrs = errors.Join(decideErrs, fmt.Errorf("deciding curation status for %s/%s@%s: %w", ref.Owner, ref.Repo, ref.Ref, decideErr))
			continue
		}
		rows = append(rows, githubactions.NewActionReportRow(ref, result))
	}
	if decideErrs != nil {
		return decideErrs
	}

	log.Info(fmt.Sprintf("GitHub Actions Curation Report:\n%s", githubactions.RenderMarkdownTable(rows, attributed)))

	if recordErr := c.recordSummary(rows, target, attributed); recordErr != nil {
		log.Warn(fmt.Sprintf("failed to record GitHub Actions curation summary: %v", recordErr))
	}

	if githubactions.AnyRejected(rows) {
		return errors.New("one or more GitHub Actions were rejected by curation policy")
	}
	return nil
}

// parseWorkflowUses resolves which workflow file to attribute against, returning its uses:
// refs, a target label for the report, and whether attribution is possible at all.
//
// attributed is false when no workflow file could be identified, or when a file named by the
// environment turns out not to exist. Run then curates the action cache structure alone - see
// its doc comment for why that is sound rather than degraded.
//
// Resolution order:
//
//  1. --workflow-file (+ --workflow-job) - explicit. Unreadable is an error: the caller
//     asserted the file exists.
//  2. GITHUB_WORKFLOW_REF (+ GITHUB_JOB) - the running workflow and job on a runner. Absent
//     from disk falls back to file system
//  3. neither - fall back to file system.
func (c *CurationActionsCommand) parseWorkflowUses(workingDir string) (used []githubactions.WorkflowUse, target string,
	attributed bool, err error) {
	jobID := c.jobID
	if jobID == "" {
		jobID = githubactions.DefaultJobID()
	}
	// Whether the caller named the file matters below: an explicit path is an assertion that
	// it exists, a derived one is not.
	workflowFile, explicit := c.workflowFile, c.workflowFile != ""
	if !explicit {
		workflowFile = githubactions.DefaultWorkflowFile()
	}
	if workflowFile == "" {
		log.Info("No workflow file was identified - curating the runner's action cache as-is, without parent attribution.")
		return nil, c.actionsCacheDir, false, nil
	}
	// GITHUB_WORKFLOW_REF yields a repo-relative path, and --workflow-file is documented as one
	// (".github/workflows/ci.yml"), so both resolve against the working directory.
	if !filepath.IsAbs(workflowFile) {
		workflowFile = filepath.Join(workingDir, workflowFile)
	}
	used, err = githubactions.ParseWorkflowUses(workflowFile, jobID)
	if err == nil {
		return used, workflowFile, true, nil
	}
	if errors.Is(err, githubactions.ErrJobUnknown) {
		log.Info(fmt.Sprintf("Cannot identify job %q in workflow file %q - curating the runner's action cache as-is, without parent attribution.", jobID, workflowFile))
		return nil, c.actionsCacheDir, false, nil
	}
	if explicit || !errors.Is(err, os.ErrNotExist) {
		return nil, workflowFile, false, err
	}
	log.Warn(fmt.Sprintf("Workflow file %q (from %s) is not on disk - curating the runner's action cache as-is, without parent attribution. "+
		"The workspace has no checkout this early in the job; pass --workflow-file to attribute against a copy fetched over the API.",
		workflowFile, githubactions.WorkflowRefEnvVar))
	return nil, c.actionsCacheDir, false, nil
}

// resolveArtifactoryVcsRepo returns the Artifactory VCS repository whose curation policies
// govern this job, looked up from the GitHub repository running it. githubRepoName is available in all runners and the
// argument which command takes is for the purpose of testing
func (c *CurationActionsCommand) resolveArtifactoryVcsRepo(ctx context.Context) (string, error) {
	githubRepo := c.githubRepo
	if githubRepo == "" {
		githubRepo = githubactions.DefaultGithubRepo()
	}
	if githubRepo == "" {
		return "", fmt.Errorf("cannot determine which GitHub repository this job belongs to: "+
			"neither --%s nor %s is set", flagGithubRepo, githubactions.GithubRepoEnvVar)
	}
	repo, err := c.vcsRepoResolver.Resolve(ctx, githubRepo)
	if err != nil {
		return "", fmt.Errorf("resolving the Artifactory VCS repository governing %q: %w", githubRepo, err)
	}
	log.Debug(fmt.Sprintf("github-actions curation: %q is governed by Artifactory VCS repository %q", githubRepo, repo))
	return repo, nil
}

// recordSummary records the report through the same "security" job-summary manager
// curation-audit already uses (output.RecordSecurityCommandSummary), so it's picked up by the
// existing generate-summary-markdown pipeline with no changes needed outside this repo. This is
// a no-op when JFROG_CLI_COMMAND_SUMMARY_OUTPUT_DIR isn't set (e.g. a local/manual run) - the
// console log above is what carries the result in that case.
func (c *CurationActionsCommand) recordSummary(rows []githubactions.ActionReportRow, target string, attributed bool) error {
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
	return output.RecordSecurityCommandSummary(output.NewCurationActionsSummary(actions, target, attributed))
}
