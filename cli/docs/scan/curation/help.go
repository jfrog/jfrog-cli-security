package curation

func GetDescription() string {
	return "Audit your project dependencies for their curation status."
}

func GetAIDescription() string {
	return `Inspect the project's package-manager dependencies against the JFrog Curation service and report which packages were blocked by curation policy along with the matching policies. Use when an agent suspects a package install failure was due to curation, or wants a preemptive curation report.

When to use:
- Diagnose 403/forbidden errors during npm/pip/pipenv/poetry/maven/gradle/nuget/go/cargo install steps in a curation-enabled remote.
- Produce a curation-status report (blocked packages and policies) for the current project.
- Run automatically after a failed install via the JFROG_CLI_SKIP_CURATION_AFTER_FAILURE workflow.

Prerequisites:
- A configured JFrog Platform server (jf c add) with JFrog Curation entitlement.
- Project must use a supported package manager (e.g. npm, yarn, pnpm, pip, pipenv, poetry, maven, gradle, nuget, go, cargo) resolved through a curation-configured remote. Docker images and Hugging Face models are audited via dedicated flags.
- The package manager and its lockfile(if applicable) must be present in the working directory. Cargo has no dedicated 'jf cargo-config' command — it reads the Artifactory registry directly from .cargo/config.toml, the same file Artifactory's "Set Me Up" instructions already produce.

Common patterns:
  $ jf curation-audit
  $ jf ca --working-dirs=services/api,services/web
  $ jf curation-audit --format=json --threads=4
  $ jf curation-audit --requirements-file=requirements-dev.txt
  $ jf curation-audit --docker-image=my-image:tag
  $ HF_ENDPOINT=https://my.jfrog.io/artifactory/api/huggingfaceml/my-hf-repo jf curation-audit --hugging-face-model=org/model:main
  $ jf ca --script=script.py

Gotchas:
- The user/token must be entitled for Curation; otherwise the command exits with an entitlement notice.
- Requires the project's package manager binary on PATH (npm, mvn, etc.).
- Run from the project root or pass --working-dirs.
- For Maven multi-module: --use-wrapper if mvnw is used.
- --script (uv only) audits one PEP 723 inline-script .py file directly; --script and --working-dirs cannot be used together, run separate commands for each.
- --hugging-face-model requires HF_ENDPOINT set to the Artifactory Hugging Face repository URL. Datasets are not audited (curation does not currently cover datasets).

Related: jf audit, jf rt npm-install, jf rt mvn

QA:
Q: What's the command to scan project dependencies and find packages that were blocked by the JFrog Curation service?
A: jf curation-audit

Q: Can you tell me the command to scan project dependencies find blocked packages by Curation and get the results in JSON format?
A: jf curation-audit --format=json

Q: I want to scan the dependencies of projects in the directories 'npm_project1' and 'npm_project2' and find packages blocked by JFrog Curation. What's the command for that?
A: jf curation-audit --working-dirs='npm_project1,npm_project2'

Q: Can you tell me the command to scan the dependencies of projects in the directories 'npm_project1' and 'npm_project2' find blocked packages by Curation and get the results in JSON format?
A: jf curation-audit --working-dirs='npm_project1,npm_project2' --format=json

Q: How can I audit the project in the current directory using 5 threads to check the packages Curation status in parallel and display all known packages blocked by Curation Policies?
A: jf curation-audit --threads=5

Q: How can I curation-audit the project using a specific pip requirements file and display the output in JSON format?
A: jf curation-audit --requirements-file='requirements.txt' --format=json
`
}
