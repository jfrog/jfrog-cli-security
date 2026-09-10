package output

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/commands/upload"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion"
	"github.com/jfrog/jfrog-client-go/auth"
	"github.com/jfrog/jfrog-client-go/xsc/services"
	xscUtils "github.com/jfrog/jfrog-client-go/xsc/services/utils"
)

func UploadCommandResults(serverDetails *config.ServerDetails, rtResultRepository string, cmdResults *results.SecurityCommandResults) (artifactPath string, err error) {
	cdxResults, err := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{
		IncludeSbom:            true,
		IncludeLicenses:        true,
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
	return filepath.ToSlash(filepath.Join(artifactFinalRepoPath, artifactName)), nil
}

func GetCommandResultsPlatformUrlMessage(cmdResults *results.SecurityCommandResults, pretty bool) string {
	uploadMsg := upload.GetScanResultsPlatformUrlMessage(cmdResults.CmdType == utils.SourceCode && cmdResults.GitContext != nil)
	if pretty {
		uploadMsg = coreutils.PrintTitle(uploadMsg)
	}
	if cmdResults.ResultsPlatformUrl == "" {
		return uploadMsg
	}
	link := cmdResults.ResultsPlatformUrl
	if pretty {
		link = coreutils.PrintLink(link)
	}
	return fmt.Sprintf("%s:\n%s", uploadMsg, link)
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
	if gitContext.PullRequest != nil && gitContext.Target != nil {
		// pull request, return the path with source and target commit hashes
		return filepath.ToSlash(filepath.Join(artifactPath, "PR")), nil
	}
	// not a pull request, just return the source commit path
	return filepath.ToSlash(filepath.Join(artifactPath, "commits")), nil
}

func extractBaseGitPath(gitCloneUrl, sourceBranchName string) (string, error) {
	lower := strings.ToLower(gitCloneUrl)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		parsed, err := url.Parse(gitCloneUrl)
		if err != nil || parsed.Host == "" {
			return "", fmt.Errorf("failed to parse git clone URL %q", gitCloneUrl)
		}
		repoPath := strings.TrimSuffix(parsed.EscapedPath(), filepath.Ext(parsed.EscapedPath()))
		return parsed.Host + repoPath + "/" + sourceBranchName, nil
	}
	gitRepoKey := xscUtils.GetGitRepoUrlKey(gitCloneUrl)
	if gitRepoKey == "" {
		return "", fmt.Errorf("failed to parse git clone URL %q", gitCloneUrl)
	}
	return strings.TrimSuffix(gitRepoKey, ".git") + "/" + sourceBranchName, nil
}
