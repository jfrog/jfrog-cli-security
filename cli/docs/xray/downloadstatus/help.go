package downloadstatus

import "github.com/jfrog/jfrog-cli-core/v2/plugins/components"

func GetDescription() string {
	return "Show whether an artifact's download is blocked by Xray and, if so, the violations causing it."
}

func GetAIDescription() string {
	return `Given an artifact, report its Xray violation-scan status and the current violations affecting it, including which ones are configured to block downloads. Use this when a download was blocked and the user has no way, short of the platform UI, to see why.

When to use:
- A user's download of an artifact is unexpectedly blocked and they want to know why without leaving the CLI.
- Checking whether an artifact currently has any blocking violations before attempting to use it.

Prerequisites:
- The artifact must exist in the configured Artifactory instance.
- The caller needs the same read permission on the artifact's repository that download requires.

Notes:
- The reported download status is computed from the current violation and scan data, not from a live download attempt, and may not exactly match what a real download would do.
- Results are looked up by repository and path; if the same path has been overwritten with a different binary, matched violations reflect the current path rather than a specific build.

Common patterns:
  $ jf xr status libs-release-local/com/acme/foo-1.2.jar
  $ jf xr status https://acme.jfrog.io/artifactory/libs-release-local/com/acme/foo-1.2.jar
  $ jf xr status libs-release-local/com/acme/foo-1.2.jar --format=json

Related: jf xr curl
`
}

func GetArguments() []components.Argument {
	return []components.Argument{{
		Name:        "artifact",
		Description: "The artifact to check, given either as '<repo>/<path>' or a full platform URL (https://<host>/artifactory/<repo>/<path>).",
	}}
}
