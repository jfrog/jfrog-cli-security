package audit

func GetDescription() string {
	return "Audit your local git repository project for security issues."
}

func GetAIDescription() string {
	return `Audit a local Git repository for security issues by combining SCA dependency scanning with JAS scans (SAST, Secrets, IaC, Applicability) and correlating findings to Git/VCS metadata (remote URL, branch, commit) so results surface in the Platform under the right Git context. Use when an agent wants jf audit results tagged with repository identity for cross-PR/cross-branch tracking.

When to use:
- Scan a working tree the same way a PR/CI bot would, with Git context attached.
- Aggregate audit findings per repository in the JFrog Platform UI.
- Run a snippet-aware SAST scan on changed files.

Prerequisites:
- Configured JFrog Platform server (jf c add) with Xray (and JAS for advanced scans).
- The current working directory must be inside a Git repository (with a remote and at least one commit).
- analyzerManager binary (auto-installed) for JAS scans.

Common patterns:
  $ jf git audit
  $ jf git audit --format=sarif --output-dir=./results
  $ jf git audit --watches=my-watch --fail=true
  $ jf git audit --sast --secrets --threads=4

Gotchas:
- Requires a Git repo with valid remote metadata; otherwise context resolution fails.
- The command is currently hidden from top-level help.
- Without --watches or --project, only general vulnerabilities are reported.

Related: jf audit, jf scan, jf git count-contributors`
}
