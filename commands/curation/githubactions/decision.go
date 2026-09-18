package githubactions

import "context"

// ActionCurationStatus is the curation outcome for one action.
type ActionCurationStatus string

const (
	ActionApproved ActionCurationStatus = "Approved"
	ActionRejected ActionCurationStatus = "Rejected"
)

// ActionCurationResult is the decision for one resolved action.
type ActionCurationResult struct {
	Status ActionCurationStatus
	Notes  string
}

// ActionCurationDecider decides the curation outcome for a single action reference. Only the
// mock implementation exists till support exists at Artifactory/Catalog.
//
// An implementation must normalize ref before looking it up: lower-case Owner and Repo, and a Ref
// that is a hex SHA. Discovery reports what the cache directory is named, and the runner names it
// verbatim from the uses: line, so one action reaches Decide under as many identities as the
// workflow spelled it. Measured on a hosted runner: `uses: Actions/Checkout@v4` alongside
// `uses: actions/checkout@v4` produces both _actions/Actions/Checkout/v4 and
// _actions/actions/checkout/v4, and the same commit pinned in upper- and lower-case hex produces
// two directories likewise. GitHub resolves either spelling, so both are the same action to
// curate - but a case-sensitive catalog lookup would give one of them a different verdict, or no
// verdict at all, and fail a job over a spelling. Normalizing here rather than in discovery keeps
// the verbatim casing that attribution matches uses: lines on (see refKey in workflow.go).
type ActionCurationDecider interface {
	// Decide returns the curation outcome for one action reference under the policies of
	// artifactoryVcsRepo. A non-nil error means no decision was reached - distinct from
	// Rejected, and fatal to the command.
	Decide(ctx context.Context, artifactoryVcsRepo string, ref ActionRef) (ActionCurationResult, error)
}
