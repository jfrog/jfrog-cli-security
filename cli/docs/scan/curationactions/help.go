package curationactions

func GetDescription() string {
	return "Curate the third-party GitHub Actions resolved on this job's runner."
}

func GetAIDescription() string {
	return `Inspect every GitHub Action that GitHub's runner actually downloaded for this job (its _actions cache directory, not the workflow YAML alone) and report a curation Approved/Rejected status per action, including actions pulled in transitively by another action's own action.yml.

When to use:
- Run as an early step in a GitHub Actions job to curate third-party actions before the rest of the job executes.
- Produce a curation report of every resolved action (direct and transitive) for the current job.

Prerequisites:
- Must run on a GitHub Actions runner (or point --actions-cache-dir at a directory shaped like the runner's _actions cache for local testing).
- No live Artifactory/Catalog decision service exists for GitHub Actions yet - the curation decision is currently a stand-in that will be replaced once one does.

Common patterns:
  $ jf curate-gh-actions
  $ jf curate-gh-actions --actions-cache-dir=/path/to/_actions
  $ jf curate-gh-actions --workflow-file=.github/workflows/ci.yml

Gotchas:
- If the runner's action cache directory can't be found (e.g. not running under GitHub Actions and no override given), the command reports an error rather than guessing a path.
- Subpath and parent attribution for actions bundled inside another composite action's own action.yml is best-effort and one level deep only; deeper nesting is not attributed.

Related: jf curation-audit

QA:
Q: What's the command to curate the GitHub Actions used in this job?
A: jf curate-gh-actions

Q: How do I run GitHub Actions curation against a specific workflow file?
A: jf curate-gh-actions --workflow-file=.github/workflows/ci.yml
`
}
