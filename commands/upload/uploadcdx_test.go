package upload

import (
	"path/filepath"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/stretchr/testify/assert"
)

func TestValidateInputFile(t *testing.T) {
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	// Create a valid CycloneDX file for testing
	validCdxFilePath := filepath.Join(tempDirPath, "some_results.cdx.json")
	fileComponent := cdxutils.CreateFileOrDirComponent(filepath.Join("a", "directory", "file.txt"))
	cdx := cyclonedx.NewBOM()
	cdx.Metadata = &cyclonedx.Metadata{
		Component: &fileComponent,
	}
	assert.NoError(t, utils.SaveCdxContentToFile(validCdxFilePath, cdx))
	// create a file with not valid extension
	noCdxExtensionFile := filepath.Join(tempDirPath, "invalid_results.json")
	assert.NoError(t, utils.DumpContentToFile([]byte("This is not a valid CycloneDX file."), tempDirPath, "invalid_results", ".json", -1))

	tests := []struct {
		name        string
		filePath    string
		expectError bool
	}{
		{
			name:        "Valid CycloneDX file",
			filePath:    validCdxFilePath,
			expectError: false,
		},
		{
			name:        "Not valid existent file",
			filePath:    noCdxExtensionFile,
			expectError: true,
		},
		{
			name:        "Not existing file",
			filePath:    "testdata/invalid_cdx.json",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateInputFile(tt.filePath)
			if (err != nil) != tt.expectError {
				t.Errorf("validateInputFile() error = %v, expectError %v", err, tt.expectError)
			}
		})
	}
}

func TestGenerateURLFromPath(t *testing.T) {
	baseUrl := "https://example.com/"
	// Create a temp file with some content for testing
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	// Create a valid CycloneDX file for testing
	validCdxFilePath := filepath.Join(tempDirPath, "valid_cdx.json")
	fileComponent := cdxutils.CreateFileOrDirComponent(filepath.Join("a", "directory", "file.txt"))
	cdx := cyclonedx.NewBOM()
	cdx.Metadata = &cyclonedx.Metadata{
		Component: &fileComponent,
	}
	assert.NoError(t, utils.SaveCdxContentToFile(validCdxFilePath, cdx))

	tests := []struct {
		name     string
		repoPath string
		filePath string
		metadata *cyclonedx.Metadata
		expected string
	}{
		{
			name:     "No metadata component",
			repoPath: "testdata/",
			filePath: validCdxFilePath,
			expected: "https://example.com/ui/scans-list/repositories/testdata/scan-descendants/valid_cdx.json?package_id=generic%3A%2F%2Fsha256%3A0d4ec5a32b4e6f0dcda6d22ae7b802339a0e9931dbd62363365e8e2977b943f0%2Fvalid_cdx.json&page_type=overview&path=testdata%2F%2Fvalid_cdx.json",
		},
		{
			name:     "With metadata component",
			repoPath: "testdata/",
			filePath: validCdxFilePath,
			metadata: &cyclonedx.Metadata{Component: &cyclonedx.Component{Name: "metadata-comp:name", Version: "1.0", Type: cyclonedx.ComponentTypeFile}},
			expected: "https://example.com/ui/scans-list/repositories/testdata/scan-descendants/valid_cdx.json?package_id=generic%3A%2F%2Fmetadata-comp%3Aname&page_type=overview&path=testdata%2F%2Fvalid_cdx.json",
		},
		{
			name:     "With subdirectory in repoPath",
			repoPath: "testdata/subdir/",
			filePath: validCdxFilePath,
			expected: "https://example.com/ui/scans-list/repositories/testdata/scan-descendants/valid_cdx.json?package_id=generic%3A%2F%2Fsha256%3A0d4ec5a32b4e6f0dcda6d22ae7b802339a0e9931dbd62363365e8e2977b943f0%2Fvalid_cdx.json&page_type=overview&path=testdata%2Fsubdir%2F%2Fvalid_cdx.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := generateURLFromPath(baseUrl, tt.repoPath, tt.filePath, tt.metadata)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
