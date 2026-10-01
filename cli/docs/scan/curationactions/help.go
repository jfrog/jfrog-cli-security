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

Which policies apply: the Artifactory repository governing the job, looked up from the GitHub repository running it (GITHUB_REPOSITORY). The mapping is curation-side configuration. If it cannot be resolved the command fails.

How each action is decided: it is evaluated against the curation policies configured using the ref the runner resolved - a tag, a branch or a commit. An approved action's content replaces the runner's copy in its cache; for a branch or a commit, the report's Notes shows the SHA Artifactory resolved it to (tags carry none yet). A blocked action is reported Rejected with Artifactory's block reason in Notes, and the runner's copy is left as it was.

Prerequisites:
- Must run on a GitHub Actions runner. What is curated comes from the runner environment (RUNNER_WORKSPACE, GITHUB_WORKFLOW_REF, GITHUB_JOB, GITHUB_REPOSITORY). Outside a runner those are unset and the command reports an error.
- A JFrog server configured (jf config, or jfrog/setup-jfrog-cli earlier in the job). The default server is used; to pick another, set JFROG_CLI_SERVER_ID to its server ID. setup-jfrog-cli's server is the default only when it is the first one configured, so on a runner that already has a JFrog config, or when a JF_ENV_* config token is also set, point at it explicitly: JFROG_CLI_SERVER_ID=setup-jfrog-cli-server (or the action's custom-server-id).
- For a self-signed or internal-CA Artifactory, add its CA certificate to the runner's trust store or to ~/.jfrog/security/certs. TLS verification cannot be turned off for this command, because it replaces the action code the runner executes.

Flags:
- --threads: how many actions are decided at once (default 3).

Common patterns:
  $ jf curate-gh-actions
  $ jf curate-gh-actions --threads 8

Gotchas:
- If the action cache cannot be read - RUNNER_WORKSPACE is unset, or the directory it points at is absent the command reports an error.
- An action no decision can be reached for (Artifactory unreachable, the ref not found) is reported as Undetermined with the cause, and the job fails; the other actions are still decided and reported. The command stops at first authentication failure and reports only that error.
- Subpath and parent attribution is best-effort and additive: it adds a Parent when it can explain where an action came from. Actions pulled in transitively by a composite action's own action.yml uses: lines are attributed and reported with that action as their Parent. One it cannot place - pulled in by an action.yml this parser cannot read - is reported with an empty Parent, still curated, just unexplained.
- Steps that run a container image rather than an action are not curated. A step using 'uses: docker://<image>' resolves to a container reference, so the runner pulls the image during job setup instead of into the action cache and it never appears in the scan. Curate those images with 'jf curation-audit --image <image>'.
- An action that itself runs in a container ('runs: using: docker' in its action.yml) is curated as an action, but the image it pulls is not. The same 'jf curation-audit --image' applies.
- An action reached only through a local composite action ('uses: ./...') is not curated. The runner cannot resolve a local action's own references until the workspace is checked out, so it downloads them when that step runs - after this command has already read the cache. An action pulled in via a 'run:' step is never resolved into the cache at all. The same applies to a 'uses: ./...' inside a third-party composite action's own action.yml: a relative path there names a directory in YOUR repository rather than one inside the action, so it resolves from the workspace at step time too. The report says so rather than leaving it to this page: when a workflow file is available it carries a 'Not covered' line naming each local step the job reaches - from the workflow itself and from any composite action's action.yml, at any depth, with the declaring action named - and when no workflow file is available (the normal case, since the check runs before the checkout) it carries that line unconditionally, because it cannot tell whether one is reached.
- Actions used by a called reusable workflow (jobs.<id>.uses:) are not curated by the calling job. A called workflow's jobs run on their own runners with their own action caches, so those actions never reach this runner. Add jfrog/setup-jfrog-cli as a step in the reusable workflow to curate them.
- Attribution can be wrong inside a called reusable workflow and is a known limitation in parsing because of incorrect information github refs hold.
- If no workflow file can be used, curation still runs against every action in the runner's cache, but without parent attribution - the report omits the Parent column and carries the 'Not covered' line described above. That covers every case where the file cannot be read or understood: nothing identified a workflow; GITHUB_WORKFLOW_REF named a file that is not on disk, which is normal early in a job since the workspace holds no checkout yet; the file does not declare the job being curated; or the YAML cannot be parsed. Coverage never changes - every action in the cache is decided either way - only the report's detail does.
- A workflow file that cannot be parsed does not fail the command but produces a non attributed report.

Related: jf curation-audit

QA:
Q: What's the command to curate the GitHub Actions used in this job?
A: jf curate-gh-actions

Q: Can I run it outside a GitHub Actions runner?
A: No. It reads what to curate from the runner environment, so off a runner it reports an error.

Q: How do I make it curate faster?
A: Raise --threads, e.g. jf curate-gh-actions --threads 8. It bounds how many actions are decided at once; the default is 3.

Q: Does this curate the actions used by a reusable workflow my job calls?
A: No - a called reusable workflow runs its jobs on their own runners, so add jf curate-gh-actions as a step inside that reusable workflow.

Q: Why does a green report still say "Not covered"?
A: An all-Approved table covers the actions the runner had already resolved when the check ran. Local composite actions ('uses: ./...') resolve their own references later in the job, so the report states that boundary rather than letting the table read as full coverage.

Q: Does this curate a step that uses docker://<image>?
A: No - the runner pulls that image during job setup rather than into the action cache, so it never reaches this scan. Curate it with jf curation-audit --image <image>.
`
}
