package output

import (
	"fmt"
	"net/url"
	"path/filepath"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	securityxray "github.com/jfrog/jfrog-cli-core/v2/utils/xray"
	"github.com/jfrog/jfrog-cli-security/commands/upload"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion"
	"github.com/jfrog/jfrog-client-go/auth"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/xsc/services"
)

func UploadCommandResults(serverDetails *config.ServerDetails, rtResultRepository string, cmdResults *results.SecurityCommandResults, xrayVersion string) (artifactPath string, err error) {
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
	projectKey := cmdResults.ResultContext.ProjectKey

	if shouldUseXrayScanCdxUploadApi(xrayVersion) {
		fileName := buildScanCdxFileName(cmdResults.CmdType)
		return uploadViaXrayApi(serverDetails, rtResultRepository, artifactFinalRepoPath, fileName, projectKey, cdxResults)
	}
	return uploadViaArtifactoryDirect(serverDetails, rtResultRepository, artifactFinalRepoPath, cmdResults.CmdType, projectKey, cdxResults)
}

func shouldUseXrayScanCdxUploadApi(xrayVersion string) bool {
	if xrayVersion == "" {
		return false
	}
	return clientutils.ValidateMinimumVersion(clientutils.Xray, xrayVersion, utils.XrayCdxUploadMinVersion) == nil
}

func buildScanCdxFileName(cmdType utils.CommandType) string {
	return utils.BuildResultFileName(string(cmdType), "cdx.json")
}

func uploadViaXrayApi(serverDetails *config.ServerDetails, rtResultRepository, artifactFinalRepoPath, fileName, projectKey string, cdxResults *cdxutils.FullBOM) (artifactPath string, err error) {
	bomBytes, err := utils.GetAsJsonBytes(cdxResults, true, true)
	if err != nil {
		return "", fmt.Errorf("failed marshaling cdx for upload: %w", err)
	}
	// Xray uses legacy SARIF format, so we need to strip the unset indexes
	if bomBytes, err = sarifutils.StripUnsetIndexes(bomBytes); err != nil {
		return "", fmt.Errorf("failed to sanitize CycloneDx SARIF indexes: %w", err)
	}
	xrayManager, err := securityxray.CreateXrayServiceManager(serverDetails, securityxray.WithScopedProjectKey(projectKey))
	if err != nil {
		return "", fmt.Errorf("failed creating xray service manager: %w", err)
	}
	resp, err := xrayManager.Xsc().UploadScanCdx(services.UploadScanCdxParams{
		RepoName: rtResultRepository,
		RepoPath: artifactFinalRepoPath,
		FileName: fileName,
		Bom:      string(bomBytes),
	})
	if err != nil {
		return "", fmt.Errorf("failed uploading the scan results via xray: %w", err)
	}
	return resp.Path, nil
}

// Used for direct upload only through upload-cdx command.
// This flow still required an access token with necessary permission to upload an artifact directly to Artifactory and permission to create a repo in Artifactory if doeant exist.
func uploadViaArtifactoryDirect(serverDetails *config.ServerDetails, rtResultRepository, artifactFinalRepoPath string, cmdType utils.CommandType, projectKey string, cdxResults *cdxutils.FullBOM) (artifactPath string, err error) {
	uploadCmd := upload.NewUploadCycloneDxCommand().
		SetContentToUpload(cdxResults).
		SetFilePrefix(string(cmdType)).
		SetServerDetails(serverDetails).
		SetUploadRepository(filepath.ToSlash(filepath.Join(rtResultRepository, artifactFinalRepoPath))).
		SetProjectKey(projectKey)
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
	// Parse the URL to handle different formats (with or without protocol)
	gitUrlParsed, err := url.Parse(gitCloneUrl)
	if err != nil {
		return "", err
	}
	// Extract the host and path, removing any .git suffix
	return gitUrlParsed.Host + "/" + gitUrlParsed.Path[:len(gitUrlParsed.Path)-len(filepath.Ext(gitUrlParsed.Path))] + "/" + sourceBranchName, nil
}
