package formats

import (
	outputFormat "github.com/jfrog/jfrog-cli-core/v2/common/format"
)

func GetOutputFormat(format string) (f outputFormat.OutputFormat, err error) {
	f = outputFormat.Table
	if format != "" {
		f, err = outputFormat.ParseOutputFormat(format, outputFormat.All)
	}
	return
}
