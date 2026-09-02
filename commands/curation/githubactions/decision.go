package githubactions

// ActionCurationStatus is the curation outcome for one action. Exactly two values exist -
// no partial/warning state - matching the agreed v1 scope.
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
	// Decide returns the curation outcome for a single action reference. ref.Subpath and
	// ref.Parent are irrelevant to the decision itself - only Owner/Repo/Ref matter.
	Decide(ref ActionRef) (ActionCurationResult, error)
}
