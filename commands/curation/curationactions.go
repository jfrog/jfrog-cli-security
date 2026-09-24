package curation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/jfrog/gofrog/parallel"
	"github.com/jfrog/jfrog-cli-core/v2/common/cliutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
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
	workingDir       string
	actionsCacheDir  string
	workflowFile     string
	jobID            string
	githubRepo       string
	parallelRequests int
	serverDetails    *config.ServerDetails
	decider          githubactions.ActionCurationDecider
	vcsRepoResolver  githubactions.ArtifactoryVcsRepoResolver
}

func NewCurationActionsCommand() *CurationActionsCommand {
	return &CurationActionsCommand{
		vcsRepoResolver: githubactions.NewMockArtifactoryVcsRepoResolver(),
	}
}

// SetServerDetails sets the JFrog server details from jf config
func (c *CurationActionsCommand) SetServerDetails(serverDetails *config.ServerDetails) *CurationActionsCommand {
	c.serverDetails = serverDetails
	return c
}

// SetParallelRequests bounds how many actions are decided at once - the --threads flag. Zero
// falls back to the CLI's default thread count.
func (c *CurationActionsCommand) SetParallelRequests(threads int) *CurationActionsCommand {
	c.parallelRequests = threads
	return c
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

// SetDecider overrides the curation decider; Run otherwise builds the Artifactory decider from
// the server details. It must be safe for concurrent use.
func (c *CurationActionsCommand) SetDecider(decider githubactions.ActionCurationDecider) *CurationActionsCommand {
	c.decider = decider
	return c
}

func (c *CurationActionsCommand) CommandName() string {
	return "curate_gh_actions"
}

// Run curates every action in the runner's cache and fails unless all are Approved. Undetermined
// actions are reported and fail the job; an access failure stops the run and returns only that
// error, with no report.
func (c *CurationActionsCommand) Run() (err error) {
	// A one-shot CLI invocation, so this is the root of the call tree, and no deadline is imposed
	// here. Artifactory carries a fail-open / fail-close setting that governs what happens when
	// curation cannot reach a verdict - a timeout, or a decision service that is unreachable.
	// That setting is not fetched or honoured yet, so this command is unconditionally fail-closed.
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
	artifactoryVcsRepo, err := c.resolveArtifactoryVcsRepo(ctx)
	if err != nil {
		return err
	}

	decider, err := c.resolveDecider()
	if err != nil {
		return err
	}
	outcome := c.decideAll(ctx, decider, artifactoryVcsRepo, discovered)
	if outcome.accessErr != nil {
		// Nothing is reported: the run stopped part-way, and a table of mostly-skipped actions
		// would read as a verdict when none was reached.
		return outcome.accessErr
	}
	rows := outcome.rows

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

	return errors.Join(outcome.decideErr(), notApprovedError(outcome.decidedRows()))
}

// notApprovedError fails the gate unless every row is Approved. A decider that returns any status other than Approved,
// without an error still fails the job.
func notApprovedError(rows []githubactions.ActionReportRow) error {
	var msg strings.Builder
	for _, row := range githubactions.NotApproved(rows) {
		if msg.Len() == 0 {
			msg.WriteString("curation policy did not approve every GitHub Action this job resolved:")
		}
		fmt.Fprintf(&msg, "\n  %s@%s: status %q", row.Action, row.Ref, row.Status)
		if row.Notes != "" {
			fmt.Fprintf(&msg, " - %s", row.Notes)
		}
	}
	if msg.Len() == 0 {
		return nil
	}
	return errors.New(msg.String())
}

func (c *CurationActionsCommand) resolveDecider() (githubactions.ActionCurationDecider, error) {
	if c.decider != nil {
		return c.decider, nil
	}
	if err := RequireArtifactoryServer(c.serverDetails); err != nil {
		return nil, err
	}
	return githubactions.NewArtifactoryActionCurationDecider(c.serverDetails)
}

// RequireArtifactoryServer fails when serverDetails names no Artifactory. With nothing in jf config
// the CLI resolves an empty, non-nil ServerDetails rather than an error, so this checks the URL.
func RequireArtifactoryServer(serverDetails *config.ServerDetails) error {
	if serverDetails == nil || serverDetails.ArtifactoryUrl == "" {
		return errorutils.CheckErrorf("no JFrog server is configured: run 'jf config add', or add jfrog/setup-jfrog-cli " +
			"with JF_URL (or oidc-provider-name) before this step")
	}
	return nil
}

// decideOutcome is every action's decision, in discovery order.
type decideOutcome struct {
	rows []githubactions.ActionReportRow
	// errs[i] is why no decision was reached for rows[i], or nil when one was. A failed row is
	// reported Undetermined, with the error as its Notes.
	errs []error
	// accessErr is 401 for download apis and 403 from git refs api. Job stops when encountered.
	// no report generated in this case.
	accessErr error
}

// decideErr joins the error of every action no decision was reached for, or nil when every
// action was decided.
func (o decideOutcome) decideErr() error {
	return errors.Join(o.errs...)
}

// decidedRows is every row a decision was reached for - the rows the approval gate judges. A
// failed row is left out because decideErr already fails the run with its cause, and naming it a
// second time as "status Undetermined" would bury that cause.
func (o decideOutcome) decidedRows() []githubactions.ActionReportRow {
	decided := make([]githubactions.ActionReportRow, 0, len(o.rows))
	for i, row := range o.rows {
		if o.errs[i] == nil {
			decided = append(decided, row)
		}
	}
	return decided
}

// decideAll decides every action with at most parallelRequests in flight at once.
func (c *CurationActionsCommand) decideAll(ctx context.Context, decider githubactions.ActionCurationDecider,
	artifactoryVcsRepo string, refs []githubactions.ActionRef) decideOutcome {
	parallelRequests := c.parallelRequests
	if parallelRequests <= 0 {
		parallelRequests = cliutils.Threads
	}
	type decision struct {
		result githubactions.ActionCurationResult
		err    error
	}
	decisions := make([]decision, len(refs))
	var stopped atomic.Bool
	// Written only by the task that wins the CompareAndSwap, and read only after runner.Run
	// returns, which is after every task has finished.
	var accessErr error

	runner := parallel.NewBounedRunner(parallelRequests, false)
	go func() {
		defer runner.Done()
		for i, ref := range refs {
			if stopped.Load() {
				return
			}
			// AddTask fails only once the runner is cancelled, which this never does.
			if _, err := runner.AddTask(func(int) error {
				if stopped.Load() {
					return nil
				}
				result, err := decider.Decide(ctx, artifactoryVcsRepo, ref)
				decisions[i] = decision{result: result, err: err}
				if errors.Is(err, githubactions.ErrAccessDenied) && stopped.CompareAndSwap(false, true) {
					accessErr = err
				}
				return nil
			}); err != nil {
				// No task was queued for this action or any after it, so nothing else writes their
				// slots. Recording the cause keeps each one a reported row rather than a blank.
				for j := i; j < len(refs); j++ {
					decisions[j].err = fmt.Errorf("not queued for a decision: %w", err)
				}
				return
			}
		}
	}()
	runner.Run()

	if accessErr != nil {
		return decideOutcome{accessErr: accessErr}
	}
	outcome := decideOutcome{rows: make([]githubactions.ActionReportRow, 0, len(refs)), errs: make([]error, len(refs))}
	for i, ref := range refs {
		d := decisions[i]
		if d.err != nil {
			outcome.errs[i] = fmt.Errorf("deciding curation status for %s/%s@%s: %w", ref.Owner, ref.Repo, ref.Ref, d.err)
			d.result = githubactions.ActionCurationResult{Status: githubactions.ActionUndetermined, Notes: d.err.Error()}
		}
		outcome.rows = append(outcome.rows, githubactions.NewActionReportRow(ref, d.result))
	}
	return outcome
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
