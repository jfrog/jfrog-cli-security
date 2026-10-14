package utils

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
)

func TestUniqueIntersection(t *testing.T) {
	testCases := []struct {
		name     string
		slice1   []string
		slice2   []string
		expected []string
	}{
		{
			name:     "Empty",
			slice1:   []string{},
			slice2:   []string{},
			expected: []string{},
		},
		{
			name:     "One element",
			slice1:   []string{"element1"},
			slice2:   []string{"element1"},
			expected: []string{"element1"},
		},
		{
			name:     "Two elements",
			slice1:   []string{"element1", "element2"},
			slice2:   []string{"element2", "element3"},
			expected: []string{"element2"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ElementsMatch(t, tc.expected, UniqueIntersection(tc.slice1, tc.slice2...))
		})
	}
}

func TestUniqueUnion(t *testing.T) {
	testCases := []struct {
		name     string
		slice    []string
		elements []string
		expected []string
	}{
		{
			name:     "Empty",
			slice:    []string{},
			elements: []string{},
			expected: []string{},
		},
		{
			name:     "One element",
			slice:    []string{"element1"},
			elements: []string{"element1"},
			expected: []string{"element1"},
		},
		{
			name:     "Two elements",
			slice:    []string{"element1", "element2"},
			elements: []string{"element2", "element3"},
			expected: []string{"element1", "element2", "element3"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ElementsMatch(t, tc.expected, UniqueUnion(tc.slice, tc.elements...))
		})
	}
}

func TestToCommandEnvVars(t *testing.T) {
	testCases := []struct {
		name       string
		envVarsMap map[string]string
		expected   []string
	}{
		{
			name:       "Empty",
			envVarsMap: map[string]string{},
			expected:   []string{},
		},
		{
			name:       "One key-value pair",
			envVarsMap: map[string]string{"key1": "value1"},
			expected:   []string{"key1=value1"},
		},
		{
			name:       "Two key-value pairs",
			envVarsMap: map[string]string{"key1": "value1", "key2": "value2"},
			expected:   []string{"key1=value1", "key2=value2"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ElementsMatch(t, tc.expected, EnvironmentVariables(tc.envVarsMap).ToCommandEnvVars())
		})
	}
}

func TestToEnvVarsMap(t *testing.T) {
	testCases := []struct {
		name     string
		envVars  []string
		expected map[string]string
	}{
		{
			name:     "Empty",
			envVars:  []string{},
			expected: map[string]string{},
		},
		{
			name:     "One key-value pair",
			envVars:  []string{"key1=value1"},
			expected: map[string]string{"key1": "value1"},
		},
		{
			name:     "Two key-value pairs",
			envVars:  []string{"key1=value1", "key2=value2"},
			expected: map[string]string{"key1": "value1", "key2": "value2"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, ToEnvVarsMap(tc.envVars))
		})
	}
}

func TestMergeMaps(t *testing.T) {
	testCases := []struct {
		name     string
		maps     []map[string]string
		expected map[string]string
	}{
		{
			name:     "Empty",
			maps:     []map[string]string{},
			expected: map[string]string{},
		},
		{
			name:     "One map",
			maps:     []map[string]string{{"key1": "value1"}},
			expected: map[string]string{"key1": "value1"},
		},
		{
			name:     "Two maps",
			maps:     []map[string]string{{"key1": "value1"}, {"key2": "value2"}},
			expected: map[string]string{"key1": "value1", "key2": "value2"},
		},
		{
			name:     "Two maps with same key",
			maps:     []map[string]string{{"key1": "value1"}, {"key1": "value2"}},
			expected: map[string]string{"key1": "value2"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, MergeMaps(tc.maps...))
		})
	}
}

func TestElementsEqual(t *testing.T) {
	testCases := []struct {
		name     string
		slice1   []string
		slice2   []string
		expected bool
	}{
		{
			name:     "Both empty",
			slice1:   []string{},
			slice2:   []string{},
			expected: true,
		},
		{
			name:     "Equal single element",
			slice1:   []string{"a"},
			slice2:   []string{"a"},
			expected: true,
		},
		{
			name:     "Same elements different order",
			slice1:   []string{"a", "b", "c"},
			slice2:   []string{"c", "a", "b"},
			expected: true,
		},
		{
			name:     "Different lengths",
			slice1:   []string{"a", "b"},
			slice2:   []string{"a"},
			expected: false,
		},
		{
			name:     "Same length different elements",
			slice1:   []string{"a", "b"},
			slice2:   []string{"a", "c"},
			expected: false,
		},
		{
			name:     "Duplicate mismatch",
			slice1:   []string{"a", "a", "b"},
			slice2:   []string{"a", "b", "b"},
			expected: false,
		},
		{
			name:     "Equal with duplicates",
			slice1:   []string{"a", "a", "b"},
			slice2:   []string{"a", "b", "a"},
			expected: true,
		},
		{
			name:     "Different with duplicates",
			slice1:   []string{"a", "b", "c"},
			slice2:   []string{"a", "b", "b"},
			expected: false,
		},
		{
			name:     "Different with duplicates in different order",
			slice1:   []string{"a", "b", "b"},
			slice2:   []string{"a", "c", "b"},
			expected: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, ElementsEqual(tc.slice1, tc.slice2))
		})
	}
}

const (
	encryptedArchiveName    = "resource.zip"
	encryptedArchivePath    = "resources/" + encryptedArchiveName
	encryptedArchiveContent = "resource executable"
	resourcesRemoteRepo     = "resources-remote"
)

func TestRemoteResourceDownloadEncrypted(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	encryptedArchive := encryptAesCtr(t, key, createZip(t, "resource", encryptedArchiveContent))
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		encryptedArchiveSha256 := sha256.Sum256(encryptedArchive)
		w.Header().Set("X-Checksum-Sha256", hex.EncodeToString(encryptedArchiveSha256[:]))
		if r.Method == http.MethodGet {
			_, err := w.Write(encryptedArchive)
			assert.NoError(t, err)
		}
	}))
	defer mockServer.Close()

	testCases := []struct {
		name          string
		decryptionKey []byte
		expectError   bool
	}{
		{name: "Correct key", decryptionKey: key},
		{name: "Wrong key", decryptionKey: bytes.Repeat([]byte{9}, 16), expectError: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			targetDir := t.TempDir()
			resource, err := GetRemoteResource("Resource", encryptedArchivePath, resourcesRemoteRepo, &config.ServerDetails{ArtifactoryUrl: mockServer.URL + "/artifactory/"})
			require.NoError(t, err)

			err = resource.Download(targetDir, encryptedArchiveName, true, 0, testCase.decryptionKey)

			assert.Equal(t, testCase.expectError, err != nil)
			cached, cacheErr := resource.IsCached(targetDir)
			require.NoError(t, cacheErr)
			assert.Equal(t, !testCase.expectError, cached)
			extracted, readErr := os.ReadFile(filepath.Join(targetDir, "resource"))
			if testCase.expectError {
				assert.True(t, os.IsNotExist(readErr))
				return
			}
			require.NoError(t, readErr)
			assert.Equal(t, encryptedArchiveContent, string(extracted))
		})
	}
}

func createZip(t *testing.T, fileName, content string) []byte {
	var buffer bytes.Buffer
	zipWriter := zip.NewWriter(&buffer)
	fileWriter, err := zipWriter.Create(fileName)
	require.NoError(t, err)
	_, err = fileWriter.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, zipWriter.Close())
	return buffer.Bytes()
}

func encryptAesCtr(t *testing.T, key, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	require.NoError(t, err)
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, plaintext)
	return slices.Concat(iv, ciphertext)
}
