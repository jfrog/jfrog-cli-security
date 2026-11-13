package contributors

func GetContContributorsDescription() string {
	return "List all GIT providers' contributing developers."
}

func GetContContributorsAIDescription() string {
	return `Count unique contributing developers across one or more Git repositories on GitHub, GitLab, or Bitbucket Server over a configurable time window. Use when an agent needs developer-count data for JFrog licensing/seat reporting or compliance audits.

When to use:
- Compute the developer-seat count for a JFrog license review.
- Produce a per-repo or per-organization contributor report for compliance.
- Aggregate counts across many repositories from an input file.

Prerequisites:
- A personal access token for the SCM provider with read access to the target repos.
- Either --input-file pointing to a repo list JSON, or the full set of mandatory flags: --scm-type, --token (or env var), --owner, --scm-api-url.
- Supported --scm-type values: github, gitlab, bitbucketServer.
- Optional env vars for tokens: JFROG_CLI_GITHUB_TOKEN, JFROG_CLI_GITLAB_TOKEN, JFROG_CLI_BITBUCKET_TOKEN, or the generic JFROG_CLI_GIT_TOKEN.

Common patterns:
  $ jf git count-contributors --scm-type=github --token=$GITHUB_TOKEN --owner=my-org --scm-api-url=https://api.github.com
  $ jf git cc --scm-type=gitlab --owner=my-group --scm-api-url=https://gitlab.com/api/v4 --repo-name="repo-a;repo-b"
  $ jf git count-contributors --input-file=repos.json --months=12 --detailed-summary

Gotchas:
- --months must be a positive integer; defaults to a built-in window if omitted.
- When --input-file is used, the other mandatory flags are ignored.
- --repo-name is a semicolon-separated list, not comma-separated.
- The command is currently hidden from top-level help.

Related: jf git audit`
}
