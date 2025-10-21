package output

import (
	"fmt"
	"net/url"
	"path/filepath"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/commands/upload"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion"
	"github.com/jfrog/jfrog-client-go/auth"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xsc/services"
)

func UploadCommandResults(serverDetails *config.ServerDetails, rtResultRepository string, cmdResults *results.SecurityCommandResults) (artifactPath string, err error) {
	// Convert the scan results to CycloneDX format
	cdxResults, err := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{
		IncludeSbom:            true,
		IncludeVulnerabilities: true,
	}).ConvertToCycloneDx(cmdResults)
	if err != nil {
		return "", fmt.Errorf("failed converting the scan results to CycloneDX format: %w", err)
	}
	// Calculate the artifact path in Artifactory based on the command contexts
	artifactFinalRepoPath, err := getResultsArtifactPath(cmdResults, serverDetails)
	if err != nil {
		return "", fmt.Errorf("failed calculating the artifact path: %w", err)
	}
	// Upload the CycloneDX results to Artifactory
	uploadCmd := upload.NewUploadCycloneDxCommand().
		SetContentToUpload(cdxResults).
		SetFilePrefix(string(cmdResults.CmdType)).
		SetServerDetails(serverDetails).
		SetUploadRepository(filepath.ToSlash(filepath.Join(rtResultRepository, artifactFinalRepoPath))).
		SetProjectKey(cmdResults.ResultContext.ProjectKey)
	artifactName, err := uploadCmd.Upload()
	if err != nil {
		return "", fmt.Errorf("failed uploading the scan results: %w", err)
	}
	// Set the results platform URL in the command results and log it
	if resultsUrl := getCommandScanResultsPlatformUrl(cmdResults, cdxResults, serverDetails, filepath.ToSlash(filepath.Join(rtResultRepository, artifactFinalRepoPath)), artifactName); resultsUrl != "" {
		cmdResults.SetResultsPlatformUrl(resultsUrl)
		log.Info(fmt.Sprintf("%s:\n%s", GetCommandResultsPlatformUrlMessage(cmdResults), resultsUrl))
	}
	return filepath.ToSlash(filepath.Join(artifactFinalRepoPath, artifactName)), nil
}

func GetCommandResultsPlatformUrlMessage(cmdResults *results.SecurityCommandResults) string {
	return upload.GetScanResultsPlatformUrlMessage(cmdResults.CmdType == utils.SourceCode && cmdResults.GitContext != nil)
}

func getCommandScanResultsPlatformUrl(cmdResults *results.SecurityCommandResults, cdxResults *cdxutils.FullBOM, serverDetails *config.ServerDetails, repoPath, artifactName string) string {
	content, err := utils.GetAsJsonBytes(cdxResults, true, true)
	if err != nil {
		log.Debug(fmt.Sprintf("Failed to generate CycloneDX content bytes for scan results URL: %s", err.Error()))
		return ""
	}
	sha256, err := utils.Sha256Hash(string(content))
	if err != nil {
		log.Debug(fmt.Sprintf("Failed to calculate SHA256 for scan results URL: %s", err.Error()))
		return ""
	}
	return upload.GetCdxScanResultsUrl(serverDetails.GetUrl(), repoPath, artifactName, sha256)
}

func getResultsArtifactPath(cmdResults *results.SecurityCommandResults, serverDetails *config.ServerDetails) (string, error) {
	if cmdResults.GitContext != nil {
		return getGitContextArtifactPath(cmdResults.GitContext)
	}
	return getLocalArtifactPath(serverDetails)
}

func getLocalArtifactPath(serverDetails *config.ServerDetails) (string, error) {
	if serverDetails == nil {
		return "", fmt.Errorf("server details are missing from the command results")
	}
	// Extract JFROG user from server details.
	user := serverDetails.User
	if serverDetails.AccessToken != "" {
		user = auth.ExtractUsernameFromAccessToken(serverDetails.AccessToken)
	}
	return user, nil
}

func getGitContextArtifactPath(gitContext *services.XscGitInfoContext) (string, error) {
	artifactPath, err := extractBaseGitPath(gitContext.Source.GitRepoHttpsCloneUrl, gitContext.Source.BranchName)
	if err != nil {
		return "", err
	}
	if gitContext.PullRequest == nil || gitContext.Target == nil {
		// not a pull request, just return the source commit path
		return filepath.ToSlash(filepath.Join(artifactPath, "commits")), nil
	}
	// pull request, return the path with source and target commit hashes
	return filepath.ToSlash(filepath.Join(artifactPath, "PR")), nil
}

func extractBaseGitPath(gitCloneUrl, sourceBranchName string) (string, error) {
	// Parse the URL to handle different formats (with or without protocol)
	gitUrlParsed, err := url.Parse(gitCloneUrl)
	if err != nil {
		return "", err
	}
	// Extract the host and path, removing any .git suffix
	return gitUrlParsed.Host + "/" + gitUrlParsed.Path[:len(gitUrlParsed.Path)-len(filepath.Ext(gitUrlParsed.Path))] + "/" + sourceBranchName, nil
}
