package githubactions

import (
	"context"
	"fmt"
	"strings"
)

const mockVcsRepoSuffix = "-github-remote-stand-in"

// mockArtifactoryVcsRepoResolver stands in for the curation service's repository-mapping API,
// which does not exist yet.
type mockArtifactoryVcsRepoResolver struct{}

// NewMockArtifactoryVcsRepoResolver returns a resolver that derives the repository key from
// the GitHub owner.
func NewMockArtifactoryVcsRepoResolver() ArtifactoryVcsRepoResolver {
	return mockArtifactoryVcsRepoResolver{}
}

func (mockArtifactoryVcsRepoResolver) Resolve(_ context.Context, githubRepo string) (string, error) {
	owner, repo, found := strings.Cut(githubRepo, "/")
	if !found || owner == "" || repo == "" || strings.Contains(repo, "/") {
		return "", fmt.Errorf("github repository %q is not in <owner>/<repo> form", githubRepo)
	}
	return owner + mockVcsRepoSuffix, nil
}
