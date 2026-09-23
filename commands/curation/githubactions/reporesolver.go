package githubactions

import "context"

// ArtifactoryVcsRepoResolver maps the GitHub repository running the current job to the
// Artifactory VCS repository whose curation policies govern it - per onboarded repository.
// Only the mock implementation exists.
type ArtifactoryVcsRepoResolver interface {
	// Resolve returns the Artifactory VCS repository key for githubRepo ("<owner>/<repo>", the
	// shape GITHUB_REPOSITORY carries).
	//
	// githubRepo decides which policies judge the job, so its only legitimate source is the
	// runner's own GITHUB_REPOSITORY - see DefaultGithubRepo. The runner does not let a
	// workflow-, job- or step-level env: block override that variable, which is what makes it
	// trustworthy; a value reaching this call from anywhere a workflow author can write would
	// let the subject of the check choose the policies applied to it. SetGithubRepo exists for
	// tests and is deliberately not reachable from the CLI.
	Resolve(ctx context.Context, githubRepo string) (string, error)
}
