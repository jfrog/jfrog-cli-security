package githubactions

import (
	"fmt"
	"time"
)

// mockActionCurationDecider is a hand-written fake, matching this repo's existing test
// convention (no gomock anywhere in the repo - see curationaudit_test.go's httptest-based
// curationServer). No real decision service exists yet, so this stands in for one: parity of
// the current Unix timestamp decides the outcome (even -> Approved, odd -> Rejected), purely
// so the command's end-to-end plumbing - including a real Rejected row and non-zero exit - is
// exercisable today without any backing service.
//
// This is intentionally non-deterministic across calls a second apart. Tests inject a fixed
// now func rather than asserting against the real clock.
//
// On Rejected: no retry, no CVS override, no re-resolution is attempted here. The result is
// simply recorded as Rejected - resolving to a compliant alternative is out of scope until a
// real decision service exists.
type mockActionCurationDecider struct {
	now func() time.Time
}

// NewMockActionCurationDecider returns the timestamp-parity mock decider described above.
func NewMockActionCurationDecider() *mockActionCurationDecider {
	return &mockActionCurationDecider{now: time.Now}
}

func (m *mockActionCurationDecider) Decide(ref ActionRef) (ActionCurationResult, error) {
	if m.now().Unix()%2 == 0 {
		return ActionCurationResult{Status: ActionApproved}, nil
	}
	return ActionCurationResult{
		Status: ActionRejected,
		Notes:  fmt.Sprintf("mock decision: rejected %s/%s@%s", ref.Owner, ref.Repo, ref.Ref),
	}, nil
}
