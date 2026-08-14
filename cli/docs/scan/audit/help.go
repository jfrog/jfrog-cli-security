package audit

func GetDescription() string {
	return "Scan your source code on demand to detect CVEs, license issues, misconfigurations, secrets, and other risks, with results shown in the terminal and in the JFrog Platform."
}

func GetAIDescription() string {
	return `Run a local source-code security audit against the JFrog Platform (Xray + JAS). Combines Software Composition Analysis (SCA) on the project's dependency graph with optional JFrog Advanced Security scans: Applicability/Contextual Analysis, IAC, Secrets Detection, SAST, and Malicious Code. Use this when an agent needs to assess a checked-out project before committing, opening a PR, or releasing.

When to use:
- Inspect a local repo for CVEs, license violations, IaC misconfigurations, leaked secrets, or SAST findings.
- Gate a build by failing on policy violations from configured watches or a project key.
- Produce SARIF or SBOM (CycloneDX) output for IDE/CI consumption.

Prerequisites:
- A configured JFrog Platform server (jf c add) with Xray entitlement.
- For JAS scans (SAST/IAC/Secrets/Applicability): a JFrog Advanced Security subscription.
- The auto-installed analyzerManager binary; pass --analyzer-manager-path to override or --skip-auto-install to use a pre-staged copy.
- Package-manager tooling (e.g., mvn, gradle, npm, pip, go) must be on PATH for tech-specific dependency resolution.

Common patterns:
  $ jf audit
  $ jf audit --format=sarif --output-dir=./scan-results
  $ jf audit --watches=my-watch1,my-watch2 --fail=true
  $ jf audit --project=my-project --vuln --licenses
  $ jf audit --sca --sast --secrets --working-dirs=services/api,services/web

Gotchas:
- Without --watches, --project, or --repo-path, no policy violations are evaluated; the command only reports raw vulnerabilities.
- --fail defaults to true: a CI run will exit non-zero on findings unless explicitly set to false.
- Technology flags (--mvn, --gradle, --npm, --go, --pip, --pipenv, --nuget, --yarn) restrict the scan; otherwise auto-detection runs every detected stack.
- --add-sast-rules requires --sast to be active.

Related: jf scan, jf build-scan, jf curation-audit, jf sbom-enrich

QA:
Q: How can I audit the project in the current directory using the policies defined for 'project-1' in JFrog Xray?
A: jf audit --project 'project-1'

Q: What is the command to audit the project in the current directory using the policies defined for 'libs-local/release-artifacts/' path in Xray?
A: jf audit --repo-path 'libs-local/release-artifacts/'

Q: How can I audit the code project in the current directory excluding all files inside the 'node_modules' directory and files with the 'to_exclude' suffix in the repo?
A: jf audit --exclusions '*node_modules*;*to_exclude'

Q: What is the command to audit the project in the current directory using 'watch1' and 'watch2' defined in JFrog Xray?
A: jf audit --watches 'watch1,watch2'

Q: How can I audit the project in the current directory and show only maven and npm vulnerabilities?
A: jf audit --mvn --npm

Q: How can I scan my local sources and show only go and gradle vulnerabilities?
A: jf audit --go --gradle
`
}
