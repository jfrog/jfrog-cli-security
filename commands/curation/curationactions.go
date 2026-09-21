package curation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/jfrog-cli-security/commands/curation/githubactions"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/results/output"
)

// CurationActionsCommand curates the GitHub Actions that actually resolved on this job's
// runner, taking the runner's action cache as the source of truth.
type CurationActionsCommand struct {
	workingDir      string
	actionsCacheDir string
	workflowFile    string
	jobID           string
	githubRepo      string
	decider         githubactions.ActionCurationDecider
	vcsRepoResolver githubactions.ArtifactoryVcsRepoResolver
}

func NewCurationActionsCommand() *CurationActionsCommand {
	return &CurationActionsCommand{
		decider:         githubactions.NewMockActionCurationDecider(),
		vcsRepoResolver: githubactions.NewMockArtifactoryVcsRepoResolver(),
	}
}

// SetWorkingDir overrides the repo root; defaults to the process's working directory. No flag
// sets this - it exists so a test can anchor the path GITHUB_WORKFLOW_REF derives.
func (c *CurationActionsCommand) SetWorkingDir(dir string) *CurationActionsCommand {
	c.workingDir = dir
	return c
}

// SetActionsCacheDir overrides the runner's action cache directory; defaults to
// githubactions.DefaultActionsCacheDir() (derived from RUNNER_WORKSPACE).
func (c *CurationActionsCommand) SetActionsCacheDir(dir string) *CurationActionsCommand {
	c.actionsCacheDir = dir
	return c
}

// SetWorkflowFile overrides the workflow file to cross-reference against; defaults to the
// running workflow derived from GITHUB_WORKFLOW_REF.
func (c *CurationActionsCommand) SetWorkflowFile(path string) *CurationActionsCommand {
	c.workflowFile = path
	return c
}

// SetJobID overrides the workflow job to scope curation to; defaults to the running job's
// job_id from GITHUB_JOB.
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

// SetVcsRepoResolver overrides the Artifactory VCS repository resolver
func (c *CurationActionsCommand) SetVcsRepoResolver(resolver githubactions.ArtifactoryVcsRepoResolver) *CurationActionsCommand {
	c.vcsRepoResolver = resolver
	return c
}

// SetDecider overrides the curation decider
func (c *CurationActionsCommand) SetDecider(decider githubactions.ActionCurationDecider) *CurationActionsCommand {
	c.decider = decider
	return c
}

func (c *CurationActionsCommand) CommandName() string {
	return "curate_gh_actions"
}

// Run discovers the actions resolved on this job's runner, decides a curation outcome per
// action, prints and records the report, and returns an error unless every action was Approved.
// Only that exact status clears the gate - a rejection withholds the job, and so would a status
// this code does not recognize, which is what keeps a future decider's unhandled outcome from
// reading as a pass.
//
// If any action cannot be decided at all Run returns that error and produces no report and no job summary.
//
// With a workflow file cross-referencing entries for Parent and Subpath
// metadata and rendering a Parent column; without one, STRUCTURE-ONLY.
func (c *CurationActionsCommand) Run() (err error) {
	// A one-shot CLI invocation, so this is the root of the call tree, and no deadline is imposed
	// here. Artifactory carries a fail-open / fail-close setting that governs what happens when
	// curation cannot reach a verdict - a timeout, or a decision service that is unreachable.
	// Fetching that setting and honouring it lands with the real decision client; until then this
	// command is unconditionally fail-closed.
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

	scan, err := githubactions.DiscoverActionCache(actionsCacheDir)
	if err != nil {
		return err
	}
	if err = scan.UnaccountedError(); err != nil {
		return err
	}
	discovered := scan.Refs
	if len(discovered) == 0 {
		return githubactions.ErrCacheNotReadable()
	}

	used, attributed, err := c.parseWorkflowUses(workingDir)
	if err != nil {
		return err
	}
	var localUses []githubactions.LocalUse
	if attributed {
		discovered, localUses = githubactions.CrossReference(discovered, used)
	}
	// Resolved once, after the early return above: a job with nothing to curate makes no call.
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

	curated := curatedActions(rows, attributed, localUses)
	caveat := formats.RenderActionsException([]formats.CuratedActions{curated})
	log.Info(fmt.Sprintf("GitHub Actions Curation Report:\n%s%s", githubactions.RenderReportTable(rows, attributed), caveat))

	// Warn rather than fail: every action above was decided, so the verdicts are complete and
	// already reported. Only the job summary is lost, and failing a job over the summary
	// directory being unwritable would fail it for a reporting problem rather than a curation one.
	if recordErr := c.recordSummary(curated); recordErr != nil {
		log.Warn(fmt.Sprintf("Failed to record the GitHub Actions curation summary, so the job summary will not show "+
			"the curation section - the report above is the complete result: %v", recordErr))
	}

	if notApproved := githubactions.NotApproved(rows); len(notApproved) > 0 {
		var msg strings.Builder
		msg.WriteString("curation policy did not approve every GitHub Action this job resolved:")
		for _, row := range notApproved {
			fmt.Fprintf(&msg, "\n  %s@%s: status %q", row.Action, row.Ref, row.Status)
			if row.Notes != "" {
				fmt.Fprintf(&msg, " - %s", row.Notes)
			}
		}
		return errors.New(msg.String())
	}
	return nil
}

// parseWorkflowUses resolves which workflow file to attribute against, returning its uses:
// refs and whether attribution is possible at all. Resolution order:
//
//  1. SetWorkflowFile (+ SetJobID) - set explicitly, by a test. The path must be absolute: the
//     caller named one specific file, so there is deliberately nothing to resolve it against.
//  2. GITHUB_WORKFLOW_REF (+ GITHUB_JOB) - the running workflow and job on a runner. GitHub sets
//     this to a repo-relative path, so it resolves against workingDir - the process's working
//     directory, which is the runner's workspace.
//  3. neither.
//
// Nothing about the workflow file fails the command. Curating the cache is the job; attribution
// only explains what is already being curated, so a file that is absent, unreadable, unparsable
// or silent about this job costs the Parent column and nothing else - the cache is still the
// complete account of what will execute, and every entry in it is decided either way. That holds
// for an explicitly set file too: a job gated on this command must not fail because a path
// was wrong. It is not silent either way, because a run without attribution says so in the
// report - see formats.RenderActionsException.
//
// The one error returned is an explicitly set path that is not absolute, which is a malformed
// argument rather than a condition of the run, and is rejected before anything is read.
//
// This also matches parseCompositeActionUses, which takes the same view of an action.yml it
// cannot read.
func (c *CurationActionsCommand) parseWorkflowUses(workingDir string) (used githubactions.JobUses, attributed bool, err error) {
	jobID := c.jobID
	if jobID == "" {
		jobID = githubactions.DefaultJobID()
	}
	workflowFile := c.workflowFile
	if explicit := workflowFile != ""; explicit {
		if !filepath.IsAbs(workflowFile) {
			return githubactions.JobUses{}, false, errorutils.CheckErrorf("the workflow file must be an absolute path, got %q", workflowFile)
		}
	} else {
		workflowFile = githubactions.DefaultWorkflowFile()
		if workflowFile == "" {
			log.Info("No workflow file was identified - curating the runner's action cache as-is, without parent attribution.")
			return githubactions.JobUses{}, false, nil
		}
		workflowFile = filepath.Join(workingDir, workflowFile)
	}
	if used, err = githubactions.ParseWorkflowUses(workflowFile, jobID); err == nil {
		return used, true, nil
	}
	switch {
	case errors.Is(err, githubactions.ErrJobUnknown):
		log.Info(fmt.Sprintf("Cannot identify job %q in workflow file %q - curating the runner's action cache as-is, without parent attribution.", jobID, workflowFile))
	case errors.Is(err, githubactions.ErrWorkflowUnparsable):
		log.Warn(fmt.Sprintf("Cannot parse workflow file %q - curating the runner's action cache as-is, without parent attribution: %v", workflowFile, err))
	case errors.Is(err, os.ErrNotExist):
		log.Warn(fmt.Sprintf("Workflow file %q is not on disk - curating the runner's action cache as-is, without parent attribution. "+
			"The workspace has no checkout this early in the job, so there is nothing to attribute against.",
			workflowFile))
	default:
		// Permissions, an I/O error, a path that is a directory. Distinct from the cases above
		// only in cause, not in consequence: nothing can be attributed, and everything is still
		// curated.
		log.Warn(fmt.Sprintf("Cannot read workflow file %q - curating the runner's action cache as-is, without parent attribution: %v", workflowFile, err))
	}
	return githubactions.JobUses{}, false, nil
}

// resolveArtifactoryVcsRepo returns the Artifactory VCS repository whose curation policies
// govern this job, looked up from the GitHub repository running it. GITHUB_REPOSITORY is set on
// every runner; SetGithubRepo overrides it for tests.
func (c *CurationActionsCommand) resolveArtifactoryVcsRepo(ctx context.Context) (string, error) {
	githubRepo := c.githubRepo
	if githubRepo == "" {
		githubRepo = githubactions.DefaultGithubRepo()
	}
	if githubRepo == "" {
		return "", errorutils.CheckErrorf("cannot determine which GitHub repository this job belongs to: "+
			"%s is not set", githubactions.GithubRepoEnvVar)
	}
	repo, err := c.vcsRepoResolver.Resolve(ctx, githubRepo)
	if err != nil {
		return "", fmt.Errorf("resolving the Artifactory VCS repository governing %q: %w", githubRepo, err)
	}
	log.Debug(fmt.Sprintf("github-actions curation: %q is governed by Artifactory VCS repository %q", githubRepo, repo))
	return repo, nil
}

// curatedActions assembles this run's result in the job summary's wire shape - the facts the
// report is rendered from, in one value, so the console report and the job summary are given
// the same thing rather than each being handed a different summary of it.
//
// Converted rather than shared: one set of types is this command's view, the other is what gets
// serialized, and a field added to either should have to be reconciled at compile time.
func curatedActions(rows []githubactions.ActionReportRow, attributed bool, localUses []githubactions.LocalUse) formats.CuratedActions {
	actions := make([]formats.CuratedAction, 0, len(rows))
	for _, row := range rows {
		// A conversion rather than a field-by-field copy: the two types are deliberately separate -
		// one is this package's report row, the other the job summary's wire shape with its json
		// tags - but they describe the same five columns. Converting makes them diverge at compile
		// time rather than silently dropping a column from the job summary.
		actions = append(actions, formats.CuratedAction(row))
	}
	converted := formats.CuratedActions{Actions: actions, Attributed: attributed}
	for _, use := range localUses {
		converted.LocalCompositeActions = append(converted.LocalCompositeActions,
			formats.LocalCompositeAction{Path: use.Raw, DeclaredBy: use.DeclaredBy})
	}
	return converted
}

// recordSummary records the report through the "security" job-summary manager
func (c *CurationActionsCommand) recordSummary(curated formats.CuratedActions) error {
	return output.RecordSecurityCommandSummary(output.NewCurationActionsSummary(curated))
}
