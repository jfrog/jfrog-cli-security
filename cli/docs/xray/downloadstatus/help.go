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
- The reported download status is computed from the current violation and scan data, not from a live download attempt.
- UNKNOWN means the violation scan has not finished, failed, or is partial, or the indexed checksum does not match the current file. A watch that blocks unscanned artifacts can still block the download while the status is UNKNOWN.
- A docker pull reference ([host/]<repo>/<image>:<tag>, or @sha256:<digest>) is resolved to the manifest Artifactory stores for that image.

Common patterns:
  $ jf xr status libs-release-local/com/acme/foo-1.2.jar
  $ jf xr status https://acme.jfrog.io/artifactory/libs-release-local/com/acme/foo-1.2.jar
  $ jf xr status my-docker-repo/nginx:1.25
  $ jf xr status libs-release-local/com/acme/foo-1.2.jar --format=json

Related: jf xr curl
`
}

func GetArguments() []components.Argument {
	return []components.Argument{{
		Name:        "artifact",
		Description: "The artifact to check. A '<repo>/<path>', a platform URL (https://<host>/artifactory/<repo>/<path>), or a docker pull reference ([host/]<repo>/<image>:<tag> or @sha256:<digest>).",
	}}
}
