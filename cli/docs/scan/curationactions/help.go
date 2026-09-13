package curationactions

func GetDescription() string {
	return "Curate the third-party GitHub Actions resolved on this job's runner."
}

func GetAIDescription() string {
	return `Inspect every GitHub Action that GitHub's runner actually downloaded for this job (its _actions cache directory) and report a curation Approved/Rejected status per action, including actions pulled in transitively by another action's own action.yml.

Scope: the actions in this job's runner cache. Each job runs on its own runner with its own cache, so that is exactly what this job resolved. The workflow file (GITHUB_WORKFLOW_REF) and job (GITHUB_JOB) are used to attribute those actions to the uses: lines that declared them, not to decide which ones get curated.

When to use:
- Run as an early step in a GitHub Actions job to curate third-party actions before the rest of the job executes.
- Produce a curation report of every resolved action (direct and transitive) for the current job.

Which policies apply: the Artifactory repository governing the job, looked up from the GitHub repository running it (GITHUB_REPOSITORY, or --github-repo). The mapping is curation-side configuration. If it cannot be resolved the command fails.

Prerequisites:
- Must run on a GitHub Actions runner (or point --actions-cache-dir at a directory shaped like the runner's _actions cache for local testing: <owner>/<repo>/<ref>, with a '<ref>.completed' file beside each action, since that marker is what identifies one). Outside a runner, GITHUB_REPOSITORY is unset, so pass --github-repo.

Common patterns:
  $ jf curate-gh-actions
  $ jf curate-gh-actions --actions-cache-dir=/path/to/_actions
  $ jf curate-gh-actions --workflow-file=/path/to/repo/.github/workflows/ci.yml
  $ jf curate-gh-actions --workflow-file=/path/to/repo/.github/workflows/ci.yml --workflow-job=build
  $ jf curate-gh-actions --github-repo=my-org/my-repo

Gotchas:
- jfrog/setup-jfrog-cli is excluded from the report at every version. It installs this CLI and invokes the check, so curating it would let the check fail a job on the tool performing it rather than on a third-party action.
- If the action cache directory cannot be located at all - not running under GitHub Actions, so RUNNER_WORKSPACE is unset, and no --actions-cache-dir given - the command reports an error. A directory that is located but absent is different: it reads as an empty cache, so the command reports nothing to curate and succeeds. Check the path if you passed --actions-cache-dir and expected entries.
- Subpath and parent attribution is best-effort and additive: it adds a Parent when it can explain where an action came from. Actions pulled in transitively by a composite action's own action.yml uses: lines are attributed and reported with that action as their Parent. One it cannot place - pulled in by an action.yml this parser cannot read - is reported with an empty Parent, still curated, just unexplained.
- Steps that run a container image rather than an action are not curated. A step using 'uses: docker://<image>' resolves to a container reference, so the runner pulls the image during job setup instead of into the action cache and it never appears in the scan. Curate those images with 'jf curation-audit --image <image>'.
- An action that itself runs in a container ('runs: using: docker' in its action.yml) is curated as an action, but the image it pulls is not. The same 'jf curation-audit --image' applies.
- An action reached only through a local composite action ('uses: ./...') is not curated. The runner cannot resolve a local action's own references until the workspace is checked out, so it downloads them when that step runs - after this command has already read the cache. An action pulled in via a 'run:' step is never resolved into the cache at all.
- Actions used by a called reusable workflow (jobs.<id>.uses:) are not curated by the calling job. A called workflow's jobs run on their own runners with their own action caches, so those actions never reach this runner. Add jfrog/setup-jfrog-cli as a step in the reusable workflow to curate them.
- If no workflow file can be used, curation still runs against every action in the runner's cache, but without parent attribution - the report omits the Parent column. That covers every case where the file cannot be read or understood: nothing identified a workflow; GITHUB_WORKFLOW_REF named a file that is not on disk, which is normal early in a job since the workspace holds no checkout yet; the file does not declare the job being curated; or the YAML cannot be parsed. Coverage never changes - every action in the cache is decided either way - only the report's detail does.
- A workflow file that cannot be parsed is not an error, whether it was named with --workflow-file or derived from GITHUB_WORKFLOW_REF. GitHub's YAML reader accepts input this one rejects (duplicate mapping keys, for instance), and the runner has already accepted the file, so the run degrades to curating the cache alone rather than failing.
- --workflow-file is an assertion that the file exists and is readable: if it cannot be read, the command fails rather than falling back, since a path you named and this command cannot open is a mistake worth surfacing. Pass it when you have fetched the workflow YAML over the API; omit it to curate the cache alone. It must be an absolute path - a relative one is rejected rather than resolved against the working directory.

Related: jf curation-audit

QA:
Q: What's the command to curate the GitHub Actions used in this job?
A: jf curate-gh-actions

Q: How do I run it outside a GitHub Actions runner, where GITHUB_REPOSITORY is unset?
A: jf curate-gh-actions --github-repo=my-org/my-repo --actions-cache-dir=/path/to/_actions

Q: How do I run GitHub Actions curation against a specific workflow file?
A: jf curate-gh-actions --workflow-file=/path/to/repo/.github/workflows/ci.yml

Q: Does this curate the actions used by a reusable workflow my job calls?
A: No - a called reusable workflow runs its jobs on their own runners, so add jf curate-gh-actions as a step inside that reusable workflow.

Q: Does this curate a step that uses docker://<image>?
A: No - the runner pulls that image during job setup rather than into the action cache, so it never reaches this scan. Curate it with jf curation-audit --image <image>.
`
}
