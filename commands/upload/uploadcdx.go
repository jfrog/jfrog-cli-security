package upload

import (
	"fmt"
	"os"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/gofrog/log"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	ioUtils "github.com/jfrog/jfrog-client-go/utils/io"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"

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
	// Upload the file to the JFrog repository
	return createRepositoryIfNeededAndUploadFile(ucc.fileToUpload, ucc.serverDetails, ucc.scanResultsRepository)
}

func validateInputFile(cdxFilePath string) (err error) {
	// check if the file exists
	if exists, err := fileutils.IsFileExists(cdxFilePath, false); err != nil {
		return fmt.Errorf("failed to check if file %s exists: %w", cdxFilePath, err)
	} else if !exists {
		return fmt.Errorf("provided path '%s' is not existing file", cdxFilePath)
	}
	// check if the file is a valid cdx file
	bom, err := readSbomFile(cdxFilePath)
	if err != nil || bom == nil {
		return fmt.Errorf("provided file %s is not a valid CycloneDX SBOM: %w", cdxFilePath, err)
	}
	metadata, err := utils.GetAsJsonString(bom.Metadata, true, true)
	if err == nil {
		log.Debug(fmt.Sprintf("found valid CycloneDX SBOM file:\n%s", metadata))
	}
	// No error means the file is valid
	return nil
}

func readSbomFile(cdxFilePath string) (*cyclonedx.BOM, error) {
	bom := cyclonedx.NewBOM()
	file, err := os.Open(cdxFilePath)
	if errorutils.CheckError(err) != nil {
		return nil, fmt.Errorf("failed to open cdx file %s: %w", cdxFilePath, err)
	}
	if err = cyclonedx.NewBOMDecoder(file, cyclonedx.BOMFileFormatJSON).Decode(bom); err != nil {
		return nil, fmt.Errorf("failed to decode provided cdx file %s: %w", cdxFilePath, err)
	}
	return bom, nil
}

func createRepositoryIfNeededAndUploadFile(filePath string, serverDetails *config.ServerDetails, scanResultsRepository string) (err error) {
	if scanResultsRepository == "" {
		// No need to upload the scan results
		return
	}
	// If the repository doesn't exist, create it
	if err = artifactory.CreateRepository(scanResultsRepository, serverDetails, true); err != nil {
		return fmt.Errorf("failed to create repository %s: %s", scanResultsRepository, err.Error())
	}
	log.Debug(fmt.Sprintf("Uploading scan results to %s", scanResultsRepository))
	return artifactory.UploadArtifactsByPatternWithProgress(filePath, serverDetails, scanResultsRepository)
}
