package scan

import (
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	"github.com/jfrog/jfrog-cli-security/cli/docs"
)

func GetDescription() string {
	return "Scan files located on the local file-system with Xray."
}

func GetAIDescription() string {
	return `Scan local files or archives against Xray (binary scan) to detect vulnerabilities and license issues without resolving a project's dependency graph. Use when an agent already has a built artifact (tar.gz, jar, zip, container layer, package file) and needs an Xray verdict before publishing or distributing it.

When to use:
- Inspect already-built artifacts, third-party binaries, or downloaded packages before promotion.
- Scan a directory tree of release candidates using a file spec or wildcard pattern.
- Produce SARIF, JSON, table, or CycloneDX output for CI gating.

Prerequisites:
- Configured JFrog Platform server (jf c add) with Xray entitlement.
- Either a positional source-pattern argument OR --spec pointing to a file-spec JSON.
- For policy-based gating: --watches, --project, or --repo-path mapped to Xray watches.

Common patterns:
  $ jf scan path/to/file.tgz
  $ jf scan "build/libs/*.jar" --format=sarif
  $ jf scan ./dist --recursive --min-severity=High --fail=true
  $ jf scan --spec=scan-spec.json --threads=4
  $ jf scan ./artifact.zip --watches=prod-watch --project=my-project --vuln

Gotchas:
- Without --watches, --project, or --repo-path, vulnerabilities are included by default but no violations are evaluated.
- Wildcards must be quoted to avoid shell expansion.
- --bypass-archive-limits is required for archives that exceed Xray's default size limit.
- --fail defaults to true and exits non-zero on findings.

Related: jf audit, jf build-scan, jf docker scan, jf sbom-enrich`
}

func GetArguments() []components.Argument {
	return []components.Argument{{Name: "source pattern", ReplaceWithFlag: docs.SpecFlag, Description: `Specifies the local file system path of the files to be scanned.
		You can specify multiple files by using wildcards, Ant pattern or a regular expression.
		If you have specified that you are using regular expressions, then the first one used in the argument must be enclosed in parenthesis.`}}
}
