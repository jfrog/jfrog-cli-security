package upload

import "github.com/jfrog/jfrog-cli-core/v2/plugins/components"

func GetDescription() string {
	return "Upload a CycloneDX SBOM file to a JFrog repository."
}

func GetAIDescription() string {
	return `Upload a CycloneDX SBOM (.cdx.json) to a target JFrog Artifactory repository so it can be associated with a build/project and indexed by Xray. Use when an agent has generated an SBOM (via jf audit, jf sbom-enrich, or an external tool) and needs to persist it on the platform.

When to use:
- Persist a generated SBOM for downstream Xray indexing or compliance reporting.
- Attach an SBOM to a project/build artifact pipeline.

Prerequisites:
- Configured JFrog Platform server (jf c add) with write permission to the target repo.
- Input file must have a .cdx.json extension and contain a valid CycloneDX JSON document.
- A target repository (--repo-path) that accepts SBOM uploads.

Common patterns:
  $ jf upload-cdx ./build/bom.cdx.json --repo-path=my-repo
  $ jf ucdx ./bom.cdx.json --repo-path=sbom-repo --project=my-project

Gotchas:
- File extension must be exactly .cdx.json; other extensions are rejected.
- The command is currently hidden from top-level help while the upload flow stabilizes.

Related: jf sbom-enrich, jf audit, jf rt upload`
}

func GetArguments() []components.Argument {
	return []components.Argument{{Name: "cycloneDx file path", Description: "Path to the JSON CycloneDX file to upload. (must be a '.cdx.json' extension)"}}
}
