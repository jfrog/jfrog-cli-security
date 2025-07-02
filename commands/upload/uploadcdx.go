package upload

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
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
	metadata, err := validateInputFile(ucc.fileToUpload)
	if err != nil {
		return
	}
	// Upload the CycloneDx file to the JFrog repository
	if err = createRepositoryIfNeededAndUploadFile(ucc.fileToUpload, ucc.serverDetails, ucc.scanResultsRepository); err != nil {
		return fmt.Errorf("failed to upload file %s to repository %s: %w", ucc.fileToUpload, ucc.scanResultsRepository, err)
	}
	// Report the URL for the scan results
	scanResultsUrl, err := generateURLFromPath(ucc.serverDetails.GetUrl(), ucc.scanResultsRepository, ucc.fileToUpload, metadata)
	if err != nil {
		return fmt.Errorf("failed to generate scan results URL: %w", err)
	}
	log.Output(fmt.Sprintf("Your CycloneDx file was successfully uploaded. You may view the file content in the JFrog platform, under Xray -> Scans List -> Repositories :\n%s", scanResultsUrl))
	return
}

func validateInputFile(cdxFilePath string) (metadata *cyclonedx.Metadata, err error) {
	if !strings.HasSuffix(cdxFilePath, ".cdx.json") {
		return nil, fmt.Errorf("provided file %s is not a valid CycloneDX SBOM file: it must have a '.cdx.json' extension", cdxFilePath)
	}
	// check if the file exists
	if exists, err := fileutils.IsFileExists(cdxFilePath, false); err != nil {
		return nil, fmt.Errorf("failed to check if file %s exists: %w", cdxFilePath, err)
	} else if !exists {
		return nil, fmt.Errorf("provided path '%s' is not existing file", cdxFilePath)
	}
	// check if the file is a valid cdx file
	bom, err := utils.ReadSbomFromFile(cdxFilePath)
	if err != nil || bom == nil {
		return nil, fmt.Errorf("provided file %s is not a valid CycloneDX SBOM: %w", cdxFilePath, err)
	}
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		metadata = bom.Metadata
		componentStr, err := utils.GetAsJsonString(bom.Metadata.Component, true, true)
		if err == nil {
			log.Debug(fmt.Sprintf("found valid CycloneDX SBOM file with Metadata component:\n%s", componentStr))
		}
	}
	return
}

func createRepositoryIfNeededAndUploadFile(filePath string, serverDetails *config.ServerDetails, scanResultsRepository string) (err error) {
	// scanResultsRepository may be the repository name and after the slash the path in the repository, we want to extract the repository name
	repoName := strings.Split(scanResultsRepository, "/")[0]
	if repoName == "" {
		return fmt.Errorf("invalid repository name: %s", scanResultsRepository)
	}
	repoExists, err := artifactory.IsRepoExists(repoName, serverDetails)
	if err != nil {
		return fmt.Errorf("failed to check if repository %s exists: %s", repoName, err.Error())
	}
	// If the repository doesn't exist, create it
	if !repoExists {
		if err = artifactory.CreateGenericLocalRepository(repoName, serverDetails, true); err != nil {
			return fmt.Errorf("failed to create generic local (indexed by Xray) repository %s: %s", repoName, err.Error())
		}
	}
	log.Debug(fmt.Sprintf("Uploading scan results to %s", scanResultsRepository))
	return artifactory.UploadArtifactsByPattern(filePath, serverDetails, scanResultsRepository)
}

func generateURLFromPath(baseUrl, repoPath, filePath string, metadata *cyclonedx.Metadata) (string, error) {
	artifactName := filepath.Base(filePath)

	metadataComponent := artifactName
	shaPart := ""
	if metadata == nil || metadata.Component == nil || metadata.Component.Version == "" {
		// Calculate SHA256
		sha256, err := calculateFileSHA256(filePath)
		if err != nil {
			return "", fmt.Errorf("failed to calculate sha256: %w", err)
		}
		if sha256 != "" {
			shaPart = fmt.Sprintf("sha256:%s/", sha256)
		}
	} else {
		metadataComponent = metadata.Component.Name
	}

	packageID := fmt.Sprintf("generic://%s%s", shaPart, metadataComponent)
	return utils.GetRepositoriesScansListUrlForArtifact(baseUrl, repoPath, artifactName, packageID), nil
}

func calculateFileSHA256(filePath string) (string, error) {
	// Read the file content
	content, err := fileutils.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", filePath, err)
	}
	return utils.Sha256Hash(string(content))
}
