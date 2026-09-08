package curation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/commands/curation/githubactions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestCurationActionsCommand_Run_UnrelatedCachedActionDoesNotFailTheCommand(t *testing.T) {
	// Simulates a self-hosted runner where _actions/ retained a leftover entry from a previous,
	// unrelated job. It's present in the cache but never referenced (directly or transitively)
	// by this job's workflow, so FilterRelevant must drop it before it's ever decided - a
	// decider that would reject it must never even be consulted.
	actionsCacheDir := t.TempDir()
	require.NoError(t, os.CopyFS(actionsCacheDir, os.DirFS(filepath.Join(curationActionsFixture, "_work", "_actions"))))
	require.NoError(t, os.MkdirAll(filepath.Join(actionsCacheDir, "some-other-org", "leftover-action", "v9"), 0755))

	cmd := NewCurationActionsCommand().
		SetActionsCacheDir(actionsCacheDir).
		SetWorkflowFile(filepath.Join(curationActionsFixture, ".github", "workflows", "ci.yml")).
		SetDecider(&fixedDecider{rejected: map[string]bool{"some-other-org/leftover-action@v9": true}})

	assert.NoError(t, cmd.Run(), "an unrelated leftover cache entry must never be decided, let alone fail the command")
}

func TestCurationActionsCommand_Run_NoActionsIsANoop(t *testing.T) {
	cmd := NewCurationActionsCommand().
		SetActionsCacheDir(t.TempDir()).
		SetWorkflowFile(filepath.Join(curationActionsFixture, ".github", "workflows", "ci.yml")).
		SetDecider(&fixedDecider{})

	assert.NoError(t, cmd.Run())
}
