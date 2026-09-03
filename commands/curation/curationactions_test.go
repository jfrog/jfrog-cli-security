package curation

import (
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/commands/curation/githubactions"
	"github.com/stretchr/testify/assert"
)

const curationActionsFixture = "../../tests/testdata/projects/githubactions/curation-project"

// fixedDecider deterministically rejects exactly the given "owner/repo@ref" keys and approves
// everything else - used instead of the timestamp-parity mock so this test doesn't depend on
// the real clock.
type fixedDecider struct {
	rejected map[string]bool
}

func (f *fixedDecider) Decide(ref githubactions.ActionRef) (githubactions.ActionCurationResult, error) {
	key := ref.Owner + "/" + ref.Repo + "@" + ref.Ref
	if f.rejected[key] {
		return githubactions.ActionCurationResult{Status: githubactions.ActionRejected, Notes: "rejected in test"}, nil
	}
	return githubactions.ActionCurationResult{Status: githubactions.ActionApproved}, nil
}

func TestCurationActionsCommand_Run_AllApproved(t *testing.T) {
	cmd := NewCurationActionsCommand().
		SetActionsCacheDir(filepath.Join(curationActionsFixture, "_work", "_actions")).
		SetWorkflowFile(filepath.Join(curationActionsFixture, ".github", "workflows", "ci.yml")).
		SetDecider(&fixedDecider{})

	assert.NoError(t, cmd.Run())
}

func TestCurationActionsCommand_Run_RejectedActionFailsTheCommand(t *testing.T) {
	cmd := NewCurationActionsCommand().
		SetActionsCacheDir(filepath.Join(curationActionsFixture, "_work", "_actions")).
		SetWorkflowFile(filepath.Join(curationActionsFixture, ".github", "workflows", "ci.yml")).
		SetDecider(&fixedDecider{rejected: map[string]bool{"some-org/transitive-action@v1": true}})

	err := cmd.Run()
	assert.Error(t, err)
}

func TestCurationActionsCommand_Run_NoActionsIsANoop(t *testing.T) {
	cmd := NewCurationActionsCommand().
		SetActionsCacheDir(t.TempDir()).
		SetWorkflowFile(filepath.Join(curationActionsFixture, ".github", "workflows", "ci.yml")).
		SetDecider(&fixedDecider{})

	assert.NoError(t, cmd.Run())
}
