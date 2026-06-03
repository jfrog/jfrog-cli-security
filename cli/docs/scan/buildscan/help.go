package buildscan

import "github.com/jfrog/jfrog-cli-core/v2/plugins/components"

func GetDescription() string {
	return "Scan a published build-info with Xray."
}

func GetAIDescription() string {
	return `Trigger an Xray scan against an already-published build-info record in Artifactory. Use when an agent has run jf rt build-publish for a CI build and wants to fetch the Xray verdict (vulnerabilities and violations) for that exact build/number pair before promoting or distributing it.

When to use:
- Gate promotion/distribution on a build's Xray scan results.
- Wait for Xray to finish scanning a freshly published build and surface findings.
- Re-scan an existing build after policy or DB updates.

Prerequisites:
- A configured JFrog Platform server (jf c add) with Xray entitlement.
- The build-info must already be published to Artifactory (jf rt build-publish).
- For violations: the build must be associated with a project key or matched by Xray watches.

Common patterns:
  $ jf build-scan my-build 42
  $ jf bs my-build 42 --fail=true --format=sarif
  $ jf build-scan my-build 42 --project=my-project --vuln --violations
  $ jf build-scan my-build 42 --rescan=true --extended-table

Gotchas:
- If build name/number are omitted, values from the build configuration env or jfrog-cli build context are used.
- --fail defaults to true; set --fail=false to inspect results without exiting non-zero.
- Xray may need time to index the build; --trigger-scan-retries controls how long the CLI waits.
- Without project/watches, no violations are produced even if --violations is set.

Related: jf audit, jf scan, jf rt build-publish`
}

func GetArguments() []components.Argument {
	return []components.Argument{
		{
			Name:        "build name",
			Description: "Build name.",
		},
		{
			Name:        "build number",
			Description: "Build number.",
		},
	}
}
