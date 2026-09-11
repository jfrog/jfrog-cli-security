package githubactions

import "context"

// ArtifactoryVcsRepoResolver maps the GitHub repository running the current job to the
// Artifactory VCS repository whose curation policies govern it.
//
// The mapping is per onboarded GitHub repository, not per action.
//
// No real implementation exists yet - the curation service's mapping API is still being built -
// so only the mock in reporesolver_mock.go exists for now.
type ArtifactoryVcsRepoResolver interface {
	// Resolve returns the Artifactory VCS repository key for githubRepo, which is in
	// "<owner>/<repo>" form (the shape GITHUB_REPOSITORY carries).
	//
	// An error means the governing repository could not be determined, which leaves no basis
	// for any curation decision. Callers must fail rather than substitute a default: deciding
	// against the wrong repository's policies would report Approved without having applied the
	// policies that actually govern the job.
	Resolve(ctx context.Context, githubRepo string) (string, error)
}
