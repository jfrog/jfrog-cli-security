package maliciousscan

import (
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
)

func GetDescription() string {
	return "[Beta] Scan malicious models (pickle files, etc.) located in the working directory."
}

func GetAIDescription() string {
	return `[Beta] Scan the working directory for malicious ML model artifacts (Python pickle files, serialized models) using the JAS analyzerManager. Use when an agent ingests untrusted models from public registries (HuggingFace, model zoos) and needs to detect embedded code-execution payloads before loading them.

When to use:
- Vet downloaded .pkl, .pt, .pth, .joblib, .h5, .pb model files before loading into a Python runtime.
- Add a malicious-model gate to ML supply-chain pipelines.

Prerequisites:
- A configured JFrog Platform server (jf c add) with JFrog Advanced Security entitlement.
- The analyzerManager binary (auto-installed); pass --analyzer-manager-path to override.
- Run from the directory containing the model files, or pass --working-dirs.

Common patterns:
  $ jf malicious-scan
  $ jf ms --working-dirs=./models --format=sarif
  $ jf malicious-scan --min-severity=High --project=my-project

Gotchas:
- Beta surface; flags and output schema may change.
- Only known malicious-model patterns are detected; this is not a general SCA or SAST scan.
- Without --working-dirs, only the current directory is scanned.

Related: jf audit, jf scan`
}

func GetArguments() []components.Argument {
	return []components.Argument{}
}
