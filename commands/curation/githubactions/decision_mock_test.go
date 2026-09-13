package githubactions

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockActionCurationDecider(t *testing.T) {
	decider := NewMockActionCurationDecider()

	tests := []struct {
		name       string
		ref        ActionRef
		wantStatus ActionCurationStatus
		wantNotes  bool
	}{
		{
			name:       "verify when the action name has an even length then it is approved",
			ref:        ActionRef{Owner: "actions", Repo: "checkout", Ref: "v4"}, // "actions/checkout" is 16
			wantStatus: ActionApproved,
		},
		{
			name:       "verify when the action name has an odd length then it is rejected",
			ref:        ActionRef{Owner: "actions", Repo: "cache", Ref: "v3"}, // "actions/cache" is 13
			wantStatus: ActionRejected,
			wantNotes:  true,
		},
		{
			name:       "verify when only the ref differs then the decision is unchanged",
			ref:        ActionRef{Owner: "actions", Repo: "checkout", Ref: "8f4b7f8"},
			wantStatus: ActionApproved,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decider.Decide(context.Background(), "vcs-repo", tt.ref)
			require.NoError(t, err)

			assert.Equal(t, tt.wantStatus, got.Status)
			if tt.wantNotes {
				assert.NotEmpty(t, got.Notes, "a rejection must say why")
			} else {
				assert.Empty(t, got.Notes)
			}

			again, err := decider.Decide(context.Background(), "vcs-repo", tt.ref)
			require.NoError(t, err)
			assert.Equal(t, got, again, "the same action must decide the same way on every call")
		})
	}
}
