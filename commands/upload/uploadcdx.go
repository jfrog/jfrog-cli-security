package upload

import (
	"fmt"
	"path/filepath"

	ioUtils "github.com/jfrog/jfrog-client-go/utils/io"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/artifactory"
)

type UploadCycloneDxCommand struct {
	serverDetails *config.ServerDetails
	progress      ioUtils.ProgressMgr

	fileToUpload          string
	scanResultsRepository string
}

func NewUploadCycloneDxCommand() *UploadCycloneDxCommand {
	return &UploadCycloneDxCommand{}
}

func (ucc *UploadCycloneDxCommand) CommandName() string {
	return "upload-cdx"
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

func (ucc *UploadCycloneDxCommand) ServerDetails() (*config.ServerDetails, error) {
	return ucc.serverDetails, nil
}

func (ucc *UploadCycloneDxCommand) Run() (err error) {
	// Validate the file is cdx
	if err = validateInputFile(ucc.fileToUpload); err != nil {
		return
	}
	// Upload the CycloneDx file to the JFrog repository
	if err = createRepositoryIfNeededAndUploadFile(ucc.fileToUpload, ucc.serverDetails, ucc.scanResultsRepository); err != nil {
		return fmt.Errorf("failed to upload file %s to repository %s: %w", ucc.fileToUpload, ucc.scanResultsRepository, err)
	}
	// Report the URL for the scan results
	scanResultsUrl, err := generateURLFromPath(ucc.serverDetails.GetUrl(), ucc.scanResultsRepository, ucc.fileToUpload)
	if err != nil {
		return fmt.Errorf("failed to generate scan results URL: %w", err)
	}
	log.Output(fmt.Sprintf("CycloneDx content uploaded successfully. You can view the results at:\n%s", scanResultsUrl))
	return
}

func validateInputFile(cdxFilePath string) (err error) {
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
	metadata, err := utils.GetAsJsonString(bom.Metadata, true, true)
	if err == nil {
		log.Debug(fmt.Sprintf("found valid CycloneDX SBOM file with Metadata:\n%s", metadata))
	}
	// No error means the file is valid
	return nil
}

func createRepositoryIfNeededAndUploadFile(filePath string, serverDetails *config.ServerDetails, scanResultsRepository string) (err error) {
	repoExists, err := artifactory.IsRepoExists(scanResultsRepository, serverDetails)
	if err != nil {
		return fmt.Errorf("failed to check if repository %s exists: %s", scanResultsRepository, err.Error())
	}
	// If the repository doesn't exist, create it
	if !repoExists {
		if err = artifactory.CreateGenericLocalRepository(scanResultsRepository, serverDetails, true); err != nil {
			return fmt.Errorf("failed to create generic local (indexed by Xray) repository %s: %s", scanResultsRepository, err.Error())
		}
	}
	log.Debug(fmt.Sprintf("Uploading scan results to %s", scanResultsRepository))
	return artifactory.UploadArtifactsByPattern(filePath, serverDetails, scanResultsRepository)
}

func generateURLFromPath(baseUrl, repoPath, filePath string) (string, error) {
	artifactName := filepath.Base(filePath)
	// Calculate SHA256
	sha256, err := calculateFileSHA256(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to calculate sha256: %w", err)
	}
	return utils.GetRepositoriesScansListUrlForArtifact(baseUrl, repoPath, artifactName, artifactName, sha256), nil
}

func calculateFileSHA256(filePath string) (string, error) {
	// Read the file content
	content, err := fileutils.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", filePath, err)
	}
	return utils.Sha256Hash(string(content))
}
