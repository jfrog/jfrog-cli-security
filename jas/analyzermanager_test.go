package jas

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
)

func TestDownloadAnalyzerManagerIfNeeded(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	bundles := map[string][]byte{
		"1.61.0": encryptAesCtr(t, key, createZip(t, "analyzerManager", "1.61.0")),
		"1.60.0": createZip(t, "analyzerManager", "1.60.0"),
	}
	testCases := []struct {
		name                          string
		pinnedVersion                 string
		publishedKey                  string
		expectedVersion               string
		expectedKeyRequests           int32
		expectedKeyRequestsAfterRerun int32
	}{
		{
			name:                          "Default version is decrypted with the published key",
			publishedKey:                  hex.EncodeToString(key),
			expectedVersion:               "1.61.0",
			expectedKeyRequests:           1,
			expectedKeyRequestsAfterRerun: 1,
		},
		{
			name:                          "Default version falls back to the last unencrypted version",
			publishedKey:                  hex.EncodeToString(bytes.Repeat([]byte{9}, 16)),
			expectedVersion:               "1.60.0",
			expectedKeyRequests:           1,
			expectedKeyRequestsAfterRerun: 2,
		},
		{
			name:                "Pinned encrypted version fails without falling back",
			pinnedVersion:       "1.61.0",
			publishedKey:        hex.EncodeToString(bytes.Repeat([]byte{9}, 16)),
			expectedKeyRequests: 1,
		},
		{
			name:            "Pinned unencrypted version is downloaded without a key",
			pinnedVersion:   "1.60.0",
			expectedVersion: "1.60.0",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var keyRequests atomic.Int32
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/xray/") {
					keyRequests.Add(1)
					body, err := io.ReadAll(r.Body)
					assert.NoError(t, err)
					assert.JSONEq(t, `{"vulnerabilities":["XRAY-1103252"]}`, string(body))
					_, err = w.Write([]byte(`{"explanation":{"XRAY-1103252":"` + testCase.publishedKey + `"}}`))
					assert.NoError(t, err)
					return
				}
				for analyzerManagerVersion, bundle := range bundles {
					if strings.Contains(r.URL.Path, "/"+analyzerManagerVersion+"/") {
						bundleSha256 := sha256.Sum256(bundle)
						w.Header().Set("X-Checksum-Sha256", hex.EncodeToString(bundleSha256[:]))
						if r.Method == http.MethodGet {
							_, err := w.Write(bundle)
							assert.NoError(t, err)
						}
						return
					}
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer mockServer.Close()
			t.Setenv(coreutils.HomeDir, t.TempDir())
			t.Setenv(jfrogCliAnalyzerManagerVersionEnvVariable, testCase.pinnedVersion)
			serverDetails := &config.ServerDetails{ArtifactoryUrl: mockServer.URL + "/artifactory/", XrayUrl: mockServer.URL + "/xray/"}

			analyzerManagerVersion, err := DownloadAnalyzerManagerIfNeeded("releases-remote", serverDetails, "", 0)

			assert.Equal(t, testCase.expectedKeyRequests, keyRequests.Load())
			if testCase.expectedVersion == "" {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, testCase.expectedVersion, analyzerManagerVersion)
			analyzerManagerDir, err := GetAnalyzerManagerDirAbsolutePath()
			require.NoError(t, err)
			installed, err := os.ReadFile(filepath.Join(analyzerManagerDir, "analyzerManager"))
			require.NoError(t, err)
			assert.Equal(t, testCase.expectedVersion, string(installed))

			_, err = DownloadAnalyzerManagerIfNeeded("releases-remote", serverDetails, "", 0)
			require.NoError(t, err)
			assert.Equal(t, testCase.expectedKeyRequestsAfterRerun, keyRequests.Load())
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
