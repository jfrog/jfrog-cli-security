package enrich

import (
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
)

func GetDescription() string {
	return "Enrich sbom format JSON located on the local file-system with Xray."
}

func GetAIDescription() string {
	return `Send an existing CycloneDX SBOM JSON file to Xray for enrichment with vulnerability and license metadata. Use when an agent has produced an SBOM from another tool (Syft, CDXgen, Maven, etc.) and wants Xray's intelligence layered on top without rerunning a full dependency resolution.

When to use:
- Annotate a third-party-generated CycloneDX SBOM with Xray vulnerability and license data.
- Add Xray context to SBOMs produced earlier in a CI pipeline.
- Bridge external SBOM tooling with the JFrog Platform.

Prerequisites:
- A configured JFrog Platform server (jf c add) with Xray entitlement.
- An input CycloneDX SBOM JSON file on the local filesystem.
- The SBOM must contain components Xray can resolve (purl identifiers).

Common patterns:
  $ jf sbom-enrich path/to/sbom.cdx.json
  $ jf se path/to/sbom.cdx.json --threads=4

Gotchas:
- Input must be CycloneDX JSON; SPDX or other formats are not accepted.
- Components without a resolvable purl will not be enriched.
- The command requires the file-path argument; no spec-based input is supported.

Related: jf audit, jf scan, jf upload-cdx`
}

func GetArguments() []components.Argument {
	return []components.Argument{{Name: "File path", Description: `Specifies the local file system path of the JSON to be scanned.`}}
}
