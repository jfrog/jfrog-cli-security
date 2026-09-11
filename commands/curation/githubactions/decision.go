package githubactions

import "context"

// ActionCurationStatus is the curation outcome for one action. An action that cannot be
// decided never fails instead.
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

// ActionCurationDecider decides the curation outcome for a single action reference.
// No real implementation exists yet - there is no Artifactory/Catalog package type for
// GitHub Actions today - so only the mock in decision_mock.go exists for now.
type ActionCurationDecider interface {
	// Decide returns the curation outcome for a single action reference, under the policies of
	// artifactoryVcsRepo.
	//
	// A non-nil error means no decision was reached for this action, as distinct from a
	// Rejected decision. An error here always means "no decision", and no decision fails the command.
	Decide(ctx context.Context, artifactoryVcsRepo string, ref ActionRef) (ActionCurationResult, error)
}
