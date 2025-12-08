package maliciousscan

import (
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
)

func GetDescription() string {
	return "Scan malicious models (pickle files, etc.) located in the working directory with AnalyzerManager."
}

func GetArguments() []components.Argument {
	return []components.Argument{}
}
