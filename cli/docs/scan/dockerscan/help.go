package dockerscan

import "github.com/jfrog/jfrog-cli-core/v2/plugins/components"

func GetDescription() string {
	return "Scan local docker image using the docker client and Xray."
}

func GetAIDescription() string {
	return `Scan a local Docker image (resolved via the local docker daemon) against Xray and JAS for vulnerabilities, license issues, secrets, and applicability. Invoked as the sub-command of jf docker. Use when an agent has built or pulled an image and wants Xray's verdict on it before pushing or running.

When to use:
- Inspect a freshly built image (e.g., from a Dockerfile) before pushing to a registry.
- Scan a third-party image pulled to the local daemon.
- Generate SARIF or CycloneDX for CI gating of container builds.

Prerequisites:
- Configured JFrog Platform server (jf c add) with Xray entitlement; JAS scans require Advanced Security.
- A running Docker daemon and the image present locally (docker images shows it).
- For applicability/JAS layers: the analyzerManager binary (auto-installed).

Common patterns:
  $ jf docker scan my-image:latest
  $ jf docker scan my-image:1.2.3 --format=sarif --fail=true
  $ jf docker scan my-registry/my-image:tag --watches=prod-watch --vuln
  $ jf docker scan my-image:tag --bypass-archive-limits --threads=4

Gotchas:
- The image must already be loaded into the local Docker daemon; this command does not pull from a registry.
- --bypass-archive-limits may be required for large layers.
- Without --watches or --project, only general vulnerabilities are reported (no violations).

Related: jf scan, jf audit, jf build-scan`
}

func GetArguments() []components.Argument {
	return []components.Argument{
		{
			Name:        "image tag",
			Description: "The docker image tag to scan.",
		},
	}
}
