package githubactions

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const resolvedSHANotePrefix = "resolved SHA: "

type artifactoryActionCurationDecider struct {
	client *vcsClient
}

func NewArtifactoryActionCurationDecider(serverDetails *config.ServerDetails) (ActionCurationDecider, error) {
	client, err := newVCSClient(serverDetails)
	if err != nil {
		return nil, err
	}
	return &artifactoryActionCurationDecider{client: client}, nil
}

// Decide classifies ref, downloads it from artifactoryVcsRepo on curation approval, writes
// the served content over the runner's copy at ref.Path.
//
// Owner and Repo are handled as case-insensitive and ref is case-sensitive
// and only an object ID is normalized
func (d *artifactoryActionCurationDecider) Decide(ctx context.Context, artifactoryVcsRepo string, ref ActionRef) (ActionCurationResult, error) {
	if err := ctx.Err(); err != nil {
		return ActionCurationResult{}, err
	}
	owner, repo := strings.ToLower(ref.Owner), strings.ToLower(ref.Repo)

	var adv *RefAdvertisement
	if NeedsRefs(ref.Ref) {
		var err error
		if adv, err = d.client.GetRefs(artifactoryVcsRepo, owner, repo); err != nil {
			return ActionCurationResult{}, fmt.Errorf("reading the git refs of %s/%s: %w", owner, repo, err)
		}
	}
	resolved, err := ClassifyRef(ref.Ref, adv)
	if err != nil {
		return ActionCurationResult{}, err
	}

	body, filename, err := d.client.Download(artifactoryVcsRepo, owner, repo, resolved)
	var blocked *BlockedError
	if errors.As(err, &blocked) {
		return ActionCurationResult{Status: ActionRejected, Notes: blocked.Reason}, nil
	}
	if err != nil {
		return ActionCurationResult{}, fmt.Errorf("downloading %s %q: %w", resolved.Kind, resolved.APIRef, err)
	}
	defer closeResponseBody(body)

	if err = ReplaceActionContent(ref.Path, body); err != nil {
		return ActionCurationResult{}, err
	}
	result := ActionCurationResult{Status: ActionApproved}
	// Empty when Artifactory's filename carries no SHA - a tag, today.
	sha := ExtractResolvedSHA(filename)
	if sha != "" {
		result.Notes = resolvedSHANotePrefix + sha
	}
	log.Debug(fmt.Sprintf("github-actions curation: %s/%s@%s approved via %q as %s %q, resolved SHA %q, content replaced at %q",
		owner, repo, ref.Ref, artifactoryVcsRepo, resolved.Kind, resolved.APIRef, sha, ref.Path))
	return result, nil
}
