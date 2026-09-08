package githubactions

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMockActionCurationDecider_TimestampParity(t *testing.T) {
	ref := ActionRef{Owner: "actions", Repo: "checkout", Ref: "v4"}

	evenSecond := time.Unix(1000, 0) // even
	oddSecond := time.Unix(1001, 0)  // odd

	approvedDecider := &mockActionCurationDecider{now: func() time.Time { return evenSecond }}
	result, err := approvedDecider.Decide(ref)
	assert.NoError(t, err)
	assert.Equal(t, ActionApproved, result.Status)
	assert.Empty(t, result.Notes)

	rejectedDecider := &mockActionCurationDecider{now: func() time.Time { return oddSecond }}
	result, err = rejectedDecider.Decide(ref)
	assert.NoError(t, err)
	assert.Equal(t, ActionRejected, result.Status)
	assert.NotEmpty(t, result.Notes)
}
