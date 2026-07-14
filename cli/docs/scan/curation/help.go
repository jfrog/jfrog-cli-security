package curation

func GetDescription() string {
	return "Audit your project dependencies for their curation status."
}

func GetAIDescription() string {
	return `Inspect the project's package-manager dependencies against the JFrog Curation service and report which packages were blocked by curation policy along with the matching policies. Use when an agent suspects a package install failure was due to curation, or wants a preemptive curation report.

When to use:
- Diagnose 403/forbidden errors during npm/pip/pipenv/poetry/maven/gradle/nuget/go install steps in a curation-enabled remote.
- Produce a curation-status report (blocked packages and policies) for the current project.
- Run automatically after a failed install via the JFROG_CLI_SKIP_CURATION_AFTER_FAILURE workflow.

Prerequisites:
- A configured JFrog Platform server (jf c add) with JFrog Curation entitlement.
- Project must use a supported package manager (npm, yarn, pnpm, pip, pipenv, poetry, maven, gradle, nuget, go) resolved through a curation-configured remote.
- The package manager must be present in the working directory. Lockfiles are required where the package manager's flow depends on one (e.g. npm, yarn, pnpm, poetry); pipenv generates/refreshes Pipfile.lock as part of the audit, so a pre-existing lockfile is not required.

Common patterns:
  $ jf curation-audit
  $ jf ca --working-dirs=services/api,services/web
  $ jf curation-audit --format=json --threads=4
  $ jf curation-audit --requirements-file=requirements-dev.txt
  $ jf curation-audit --docker-image=my-image:tag

Gotchas:
- The user/token must be entitled for Curation; otherwise the command exits with an entitlement notice.
- Requires the project's package manager binary on PATH (npm, mvn, etc.).
- Run from the project root or pass --working-dirs.
- For Maven multi-module: --use-wrapper if mvnw is used.

Related: jf audit, jf rt npm-install, jf rt mvn`
}
