package output

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/commands/upload"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion"
)

func UploadCommandResults(serverDetails *config.ServerDetails, rtResultRepository string, cmdResults *results.SecurityCommandResults) (err error) {
	cdxResults, err := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{
		IncludeSbom:            true,
		IncludeVulnerabilities: true,
	}).ConvertToCycloneDx(cmdResults)
	if err != nil {
		return
	}
	uploadCmd := upload.NewUploadCycloneDxCommand().
		SetContentToUpload(cdxResults).
		SetFilePrefix(string(cmdResults.CmdType)).
		SetServerDetails(serverDetails).
		SetUploadRepository(rtResultRepository).
		SetProjectKey(cmdResults.ResultContext.ProjectKey)
	if err = uploadCmd.Run(); err != nil {
		return
	}
	return
}
