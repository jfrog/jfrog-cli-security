package upload

import (
	"fmt"
	"path/filepath"
	"strings"

	ioUtils "github.com/jfrog/jfrog-client-go/utils/io"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/artifactory"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-cli-security/utils/xray/artifact"
)

type UploadCycloneDxCommand struct {
	serverDetails *config.ServerDetails
	progress      ioUtils.ProgressMgr

	fileToUpload    string
	contentToUpload *cdxutils.FullBOM
	filePrefix      string

	// Options
	scanResultsRepository string
	projectKey            string
}

func NewUploadCycloneDxCommand() *UploadCycloneDxCommand {
	return &UploadCycloneDxCommand{}
}

func (ucc *UploadCycloneDxCommand) CommandName() string {
	return "upload-cdx"
}

func (ucc *UploadCycloneDxCommand) SetContentToUpload(bom *cdxutils.FullBOM) *UploadCycloneDxCommand {
	ucc.contentToUpload = bom
	return ucc
}

func (ucc *UploadCycloneDxCommand) SetFilePrefix(filePrefix string) *UploadCycloneDxCommand {
	ucc.filePrefix = filePrefix
	return ucc
}

func (ucc *UploadCycloneDxCommand) SetFileToUpload(filePath string) *UploadCycloneDxCommand {
	ucc.fileToUpload = filePath
	return ucc
}

func (ucc *UploadCycloneDxCommand) SetUploadRepository(repo string) *UploadCycloneDxCommand {
	ucc.scanResultsRepository = repo
	return ucc
}

func (ucc *UploadCycloneDxCommand) SetProgress(progress ioUtils.ProgressMgr) {
	ucc.progress = progress
}

func (ucc *UploadCycloneDxCommand) SetServerDetails(server *config.ServerDetails) *UploadCycloneDxCommand {
	ucc.serverDetails = server
	return ucc
}

func (ucc *UploadCycloneDxCommand) SetProjectKey(projectKey string) *UploadCycloneDxCommand {
	ucc.projectKey = projectKey
	return ucc
}

func (ucc *UploadCycloneDxCommand) ServerDetails() (*config.ServerDetails, error) {
	return ucc.serverDetails, nil
}

func (ucc *UploadCycloneDxCommand) Run() (err error) {
	// Upload the CycloneDx file to the JFrog repository
	if _, err = ucc.Upload(); err != nil {
		return fmt.Errorf("failed to upload file %s to repository %s: %w", ucc.fileToUpload, ucc.scanResultsRepository, err)
	}
	if err = ucc.waitForUploadCompletion(); err != nil {
		return fmt.Errorf("failed while waiting for Xray to start scanning the uploaded CycloneDx file: %w", err)
	}
	// Report the URL for the scan results
	if err = ucc.outputArtifactScanResultsUrl(ucc.serverDetails, ucc.scanResultsRepository, ucc.fileToUpload); err != nil {
		log.Error(fmt.Sprintf("Failed to output the CycloneDx scan results URL: %s", err.Error()))
	}
	return
}

func (ucc *UploadCycloneDxCommand) waitForUploadCompletion() error {
	xrayManager, err := xray.CreateXrayServiceManager(ucc.serverDetails, xray.WithScopedProjectKey(ucc.projectKey))
	if err != nil {
		return err
	}
	// Not providing any options means we are waiting for the scan to start (so the UI can show content when pressing the generate scan results link)
	return artifact.WaitForArtifactScanStatus(xrayManager, ucc.scanResultsRepository, filepath.Base(ucc.fileToUpload), artifact.OverallCompletion())
}

func (ucc *UploadCycloneDxCommand) Upload() (artifactPath string, err error) {
	// If content to upload is provided, create a temp file and write the content to it
	if ucc.contentToUpload != nil {
		tempDir, err := fileutils.CreateTempDir()
		if err != nil {
			return "", fmt.Errorf("failed to create temp dir: %w", err)
		}
		outputBytes, err := utils.GetAsJsonBytes(ucc.contentToUpload, true, true)
		if err != nil {
			return "", fmt.Errorf("failed to convert CycloneDx content to JSON: %w", err)
		}
		if ucc.fileToUpload, err = utils.DumpCdxJsonContentToFile(outputBytes, tempDir, ucc.filePrefix, 0); err != nil {
			return "", fmt.Errorf("failed to save CycloneDx content to file: %w", err)
		}
		log.Debug(fmt.Sprintf("Created temp CycloneDx file: %s", ucc.fileToUpload))
	}
	if ucc.fileToUpload == "" {
		return "", fmt.Errorf("no CycloneDx file or content to upload was provided")
	}
	// Validate the file is cdx
	if err = validateInputFile(ucc.fileToUpload); err != nil {
		return
	}
	// Upload the CycloneDx file to the JFrog repository
	if artifactPath, err = createRepositoryIfNeededAndUploadFile(ucc.fileToUpload, ucc.serverDetails, ucc.scanResultsRepository, ucc.projectKey); err != nil {
		return "", fmt.Errorf("failed to upload file %s to repository %s: %w", ucc.fileToUpload, ucc.scanResultsRepository, err)
	}
	return
}

func validateInputFile(cdxFilePath string) (err error) {
	if !strings.HasSuffix(cdxFilePath, ".cdx.json") {
		return fmt.Errorf("provided file %s is not a valid CycloneDX SBOM file: it must have a '.cdx.json' extension", cdxFilePath)
	}
	// check if the file exists
	if exists, err := fileutils.IsFileExists(cdxFilePath, false); err != nil {
		return fmt.Errorf("failed to check if file %s exists: %w", cdxFilePath, err)
	} else if !exists {
		return fmt.Errorf("provided path '%s' is not existing file", cdxFilePath)
	}
	// check if the file is a valid cdx file
	bom, err := utils.ReadSbomFromFile(cdxFilePath)
	if err != nil || bom == nil {
		return fmt.Errorf("provided file %s is not a valid CycloneDX SBOM: %w", cdxFilePath, err)
	}
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		componentStr, err := utils.GetAsJsonString(bom.Metadata.Component, true, true)
		if err == nil {
			log.Debug(fmt.Sprintf("found valid CycloneDX SBOM file with Metadata component:\n%s", componentStr))
		}
	}
	return
}

func createRepositoryIfNeededAndUploadFile(filePath string, serverDetails *config.ServerDetails, scanResultsRepository, relatedProjectKey string) (artifactPath string, err error) {
	// scanResultsRepository may be the repository name and after the slash the path in the repository, we want to extract the repository name
	repoName := strings.Split(scanResultsRepository, "/")[0]
	if repoName == "" {
		return "", fmt.Errorf("invalid repository name: %s", scanResultsRepository)
	}
	repoExists, err := artifactory.IsRepoExists(repoName, serverDetails)
	if err != nil {
		return "", fmt.Errorf("failed to check if repository %s exists: %s", repoName, err.Error())
	}
	// If the repository doesn't exist, create it
	if !repoExists {
		if err = artifactory.CreateGenericLocalRepository(repoName, serverDetails, true, relatedProjectKey); err != nil {
			return "", fmt.Errorf("failed to create generic local (indexed by Xray) repository %s: %s", repoName, err.Error())
		}
	}
	log.Debug(fmt.Sprintf("Uploading scan results to %s", scanResultsRepository))
	// target repo is <repository name>/<repository path>, If the target path ends with a slash, the path is assumed to be a folder.
	// Else it is assumed to be a file. so we add a slash to the end of the repo to indicate that it is a folder.
	uploaded, err := artifactory.UploadArtifactsByPattern(filePath, serverDetails, artifactory.AddSuffixSlashIfNeeded(scanResultsRepository), relatedProjectKey)
	if err != nil {
		return "", fmt.Errorf("failed to upload file %s to repository %s: %w", filePath, scanResultsRepository, err)
	}
	if len(uploaded) == 0 {
		return "", fmt.Errorf("no files were uploaded to repository %s", scanResultsRepository)
	}
	artifactPath = uploaded[0]
	return
}

func (ucc *UploadCycloneDxCommand) outputArtifactScanResultsUrl(serverDetails *config.ServerDetails, repoPath, filePath string) error {
	link, err := generateURLFromPath(serverDetails.GetUrl(), repoPath, filePath)
	if err != nil {
		return err
	}
	log.Output(coreutils.PrintTitle(GetScanResultsPlatformUrlMessage(false)) + ":\n" + coreutils.PrintLink(link))
	return nil
}

func GetScanResultsPlatformUrlMessage(gitContext bool) string {
	outputMessage := "You may view the scan results in the JFrog platform, under Xray -> Scans List ->"
	if gitContext {
		outputMessage += " Git Repositories"
	} else {
		outputMessage += " Repositories"
	}
	return outputMessage
}

func generateURLFromPath(baseUrl, repoPath, filePath string) (string, error) {
	artifactName := filepath.Base(filePath)
	// Calculate SHA256
	sha256, err := calculateFileSHA256(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to calculate sha256: %w", err)
	}
	return GetCdxScanResultsUrl(baseUrl, repoPath, artifactName, sha256), nil
}

func GetCdxScanResultsUrl(baseUrl, repoPath, artifactName, sha256 string) string {
	if sha256 != "" {
		sha256 = fmt.Sprintf("sha256:%s/", sha256)
	}
	packageID := fmt.Sprintf("generic://%s%s", sha256, artifactName)
	return utils.GetRepositoriesScansListUrlForArtifact(baseUrl, repoPath, artifactName, packageID)
}

func calculateFileSHA256(filePath string) (string, error) {
	// Read the file content
	content, err := fileutils.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", filePath, err)
	}
	return utils.Sha256Hash(string(content))
}
