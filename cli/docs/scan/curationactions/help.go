package curationactions

func GetDescription() string {
	return "Curate the third-party GitHub Actions resolved on this job's runner."
}

func GetAIDescription() string {
	return `Inspect every GitHub Action that GitHub's runner actually downloaded for this job (its _actions cache directory, not the workflow YAML alone) and report a curation Approved/Rejected status per action, including actions pulled in transitively by another action's own action.yml.

Scope: the job it runs in. The workflow file comes from GITHUB_WORKFLOW_REF and the job from GITHUB_JOB, so actions referenced only by a different workflow in the repository - or by a different job in the same workflow file - are not curated by this invocation.

When to use:
- Run as an early step in a GitHub Actions job to curate third-party actions before the rest of the job executes.
- Produce a curation report of every resolved action (direct and transitive) for the current job.

Which policies apply: the Artifactory repository governing the job, looked up from the GitHub repository running it (GITHUB_REPOSITORY, or --github-repo). The mapping is curation-side configuration. If it cannot be resolved the command fails.

Prerequisites:
- Must run on a GitHub Actions runner (or point --actions-cache-dir at a directory shaped like the runner's _actions cache for local testing). Outside a runner, GITHUB_REPOSITORY is unset, so pass --github-repo.

Common patterns:
  $ jf curate-gh-actions
  $ jf curate-gh-actions --actions-cache-dir=/path/to/_actions
  $ jf curate-gh-actions --workflow-file=.github/workflows/ci.yml
  $ jf curate-gh-actions --workflow-file=.github/workflows/ci.yml --workflow-job=build
  $ jf curate-gh-actions --github-repo=my-org/my-repo

Gotchas:
- jfrog/setup-jfrog-cli is excluded from the report at every version. It installs this CLI and invokes the check, so curating it would let the check fail a job on the tool performing it rather than on a third-party action.
- If the runner's action cache directory can't be found (e.g. not running under GitHub Actions and no override given), the command reports an error rather than guessing a path.
- Subpath and parent attribution for actions bundled inside another composite action's own action.yml is best-effort: an action that pulls in others via a run: step instead of its own action.yml uses: is not attributed.
- Actions used by a called reusable workflow (jobs.<id>.uses:) are not curated by the calling job. A called workflow's jobs run on their own runners with their own action caches, so those actions never reach this runner. Add jfrog/setup-jfrog-cli as a step in the reusable workflow to curate them.
- If no workflow file is available, curation still runs against every action in the runner's cache, but without parent attribution - the report omits the Parent column rather than showing a column of blanks. Coverage is unaffected: the runner populates the cache with exactly the actions the current job resolved. This applies both when nothing identifies the workflow and when GITHUB_WORKFLOW_REF names a file that is not on disk, which is the normal case early in a job - the workspace holds no checkout yet.
- --workflow-file is treated as an assertion that the file exists: if it cannot be read, the command fails rather than falling back. Pass it when you have fetched the workflow YAML over the API; omit it to curate the cache alone.

Related: jf curation-audit

QA:
Q: What's the command to curate the GitHub Actions used in this job?
A: jf curate-gh-actions

Q: How do I run it outside a GitHub Actions runner, where GITHUB_REPOSITORY is unset?
A: jf curate-gh-actions --github-repo=my-org/my-repo --actions-cache-dir=/path/to/_actions

Q: How do I run GitHub Actions curation against a specific workflow file?
A: jf curate-gh-actions --workflow-file=.github/workflows/ci.yml

Q: Does this curate the actions used by a reusable workflow my job calls?
A: No - a called reusable workflow runs its jobs on their own runners, so add jf curate-gh-actions as a step inside that reusable workflow.
`
}
