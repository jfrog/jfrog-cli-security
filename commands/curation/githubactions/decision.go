package githubactions

import "context"

// ActionCurationStatus is the curation outcome for one action.
type ActionCurationStatus string

const (
	ActionApproved ActionCurationStatus = "Approved"
	ActionRejected ActionCurationStatus = "Rejected"
	// ActionUndetermined to cover the cases of decider failures.
	ActionUndetermined ActionCurationStatus = "Undetermined"
)

// ActionCurationResult is the decision for one resolved action.
type ActionCurationResult struct {
	Status ActionCurationStatus
	Notes  string
}

// ActionCurationDecider decides the curation outcome for a single action reference. It must be
// safe for concurrent use, and must normalize Owner, Repo and hex SHAs to lower case: the runner
// names cache directories verbatim from uses:, so one action can arrive under several spellings.
type ActionCurationDecider interface {
	// Decide returns the outcome under artifactoryVcsRepo's policies. A non-nil error means no
	// decision: the action is reported Undetermined and the job fails. ErrAccessDenied stops the run.
	Decide(ctx context.Context, artifactoryVcsRepo string, ref ActionRef) (ActionCurationResult, error)
}
