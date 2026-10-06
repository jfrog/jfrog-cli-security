package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	artifactoryUtils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	corexray "github.com/jfrog/jfrog-cli-core/v2/utils/xray"

	"github.com/jfrog/jfrog-cli-security/commands/xray/downloadstatus"
	securityTests "github.com/jfrog/jfrog-cli-security/tests"
	integration "github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	"github.com/jfrog/jfrog-cli-security/utils/xray/artifact"

	clientartifactory "github.com/jfrog/jfrog-client-go/artifactory"
	"github.com/jfrog/jfrog-client-go/artifactory/services"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
)

func TestXrStatusUploadedArtifact(t *testing.T) {
	integration.InitXrayTest(t, "")
	repo := securityTests.RtRepo1
	require.NotEmpty(t, repo)

	dir := t.TempDir()
	name := "xr-status-" + strconv.FormatInt(time.Now().UnixNano(), 10) + ".txt"
	localPath := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(localPath, []byte("xr-status"), 0o644))

	server := *integration.GetTestServerDetails()
	if server.XrayUrl == "" {
		server.XrayUrl = clientutils.AddTrailingSlashIfNeeded(server.Url) + securityTests.XrayEndpoint
	}

	rtManager, err := artifactoryUtils.CreateServiceManager(&server, -1, 0, false)
	require.NoError(t, err)
	params := services.NewUploadParams()
	params.Pattern = localPath
	params.Target = repo + "/"
	params.Flat = true
	uploaded, failed, err := rtManager.UploadFiles(clientartifactory.UploadServiceOptions{FailFast: true}, params)
	require.NoError(t, err)
	require.Equal(t, 0, failed)
	require.Equal(t, 1, uploaded)
	defer func() {
		deleteParams := services.NewDeleteParams()
		deleteParams.Pattern = repo + "/" + name
		reader, delErr := rtManager.GetPathsToDelete(deleteParams)
		if assert.NoError(t, delErr) {
			defer reader.Close()
			_, delErr = rtManager.DeleteFiles(reader)
			assert.NoError(t, delErr)
		}
	}()

	repoName, paths, err := downloadstatus.ParseArtifact(repo+"/"+name, server.Url)
	require.NoError(t, err)

	xrayManager, err := corexray.CreateXrayServiceManager(&server)
	require.NoError(t, err)
	require.NoError(t, artifact.WaitForArtifactScanStatus(xrayManager, repoName, paths[0], artifact.OverallCompletion()))

	result, err := downloadstatus.NewDownloadStatusCommand().
		SetServerDetails(&server).
		SetRepoAndPathCandidates(repoName, paths).
		SetOutputFormat(format.Json).
		FetchResult()
	require.NoError(t, err)
	assert.Equal(t, repo, result.Repo)
	assert.Equal(t, name, result.Path)
	// No watch targets this artifact, so once scanning is done, nothing can block it.
	assert.Equal(t, downloadstatus.StatusAllowed, result.DownloadStatus)
	assert.Empty(t, result.Violations)
}
