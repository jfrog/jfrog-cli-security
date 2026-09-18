package githubactions

import "context"

// ArtifactoryVcsRepoResolver maps the GitHub repository running the current job to the
// Artifactory VCS repository whose curation policies govern it - per onboarded repository.
// Only the mock implementation exists.
type ArtifactoryVcsRepoResolver interface {
	// Resolve returns the Artifactory VCS repository key for githubRepo ("<owner>/<repo>", the
	// shape GITHUB_REPOSITORY carries).
	Resolve(ctx context.Context, githubRepo string) (string, error)
}
