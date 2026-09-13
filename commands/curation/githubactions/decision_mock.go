package githubactions

import (
	"context"
	"fmt"
)

// mockActionCurationDecider stands in for the decision service, which does not exist yet. The
// parity of the action name's length decides the outcome (even -> Approved, odd -> Rejected),
// A Rejected result is simply recorded and once CVS is implemented content is overridden with compliant
// version. Docker based actions need special handling: the runner pulls or
// builds the action's image during job setup, before curation decides anything here, so
// selecting a compliant version also means rebuilding that runner-built image and replacing
// otherwise the job goes on running the image produced from the version CVS moved off.
type mockActionCurationDecider struct{}

// NewMockActionCurationDecider returns the name-parity stand-in decider.
func NewMockActionCurationDecider() ActionCurationDecider {
	return mockActionCurationDecider{}
}

func (mockActionCurationDecider) Decide(_ context.Context, _ string, ref ActionRef) (ActionCurationResult, error) {
	action := ref.Owner + "/" + ref.Repo
	if len(action)%2 == 0 {
		return ActionCurationResult{Status: ActionApproved}, nil
	}
	return ActionCurationResult{
		Status: ActionRejected,
		Notes:  fmt.Sprintf("mock decision: rejected %s@%s", action, ref.Ref),
	}, nil
}
