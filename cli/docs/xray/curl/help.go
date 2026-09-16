package curl

import "github.com/jfrog/jfrog-cli-core/v2/plugins/components"

func GetDescription() string {
	return "Execute a cURL command, using the configured Xray details."
}

func GetAIDescription() string {
	return `Issue an arbitrary HTTP request to the Xray REST API using credentials from the active jf config, much like curl but with the Xray URL and auth headers injected automatically. Use when an agent needs to call Xray endpoints that have no dedicated CLI wrapper.

When to use:
- Call Xray admin or reporting endpoints not yet exposed via dedicated subcommands.
- Quickly script Xray API calls without manually assembling auth headers.

Prerequisites:
- A configured JFrog Platform server (jf c add) whose Xray URL is set; the command errors out otherwise.
- The active user/token must have permission for the targeted endpoint.

Common patterns:
  $ jf xr curl -XGET /api/v1/system/ping
  $ jf xr cl -XGET /api/v2/policies
  $ jf xr curl -XPOST /api/v1/binMgr/search -H 'Content-Type: application/json' -d '{"sha1":"abc..."}'

Gotchas:
- Paths are relative to the Xray base URL; do not prepend the full host.
- The leading -- separator may be required to stop the CLI from intercepting curl flags.
- The configured server must have a non-empty XrayUrl; older configs without an Xray URL fail with a clear error.

Related: jf rt curl, jf c show, jf xr offline-update`
}

func GetArguments() []components.Argument {
	return []components.Argument{{Name: "curl command", Description: "cURL command to run."}}
}
