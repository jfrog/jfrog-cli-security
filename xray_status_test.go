package main

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-artifactory/artifactory/commands/repository"
	artifactoryUtils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	commonCommands "github.com/jfrog/jfrog-cli-core/v2/common/commands"
	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	corexray "github.com/jfrog/jfrog-cli-core/v2/utils/xray"

	"github.com/jfrog/jfrog-cli-security/commands/xray/downloadstatus"
	securityTests "github.com/jfrog/jfrog-cli-security/tests"
	integration "github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	securityArtifactory "github.com/jfrog/jfrog-cli-security/utils/artifactory"

	clientartifactory "github.com/jfrog/jfrog-client-go/artifactory"
	"github.com/jfrog/jfrog-client-go/artifactory/services"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/httputils"
	xrayServices "github.com/jfrog/jfrog-client-go/xray/services"
)

func xrStatusServer() config.ServerDetails {
	server := *integration.GetTestServerDetails()
	if server.XrayUrl == "" {
		server.XrayUrl = clientutils.AddTrailingSlashIfNeeded(server.Url) + securityTests.XrayEndpoint
	}
	return server
}

func createXrStatusLocalRepo(t *testing.T, server *config.ServerDetails) string {
	// cli-rt1 and the other shared fixtures are only provisioned for
	// --test.artifactory/--test.dockerScan jobs, not for an Xray-only job, and
	// may not be Xray-indexed either. These tests need a repo they know is both.
	repo := "xr-status-test-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	require.NoError(t, securityArtifactory.CreateGenericLocalRepository(repo, server, true, ""))
	t.Cleanup(func() { deleteXrStatusRepo(t, server, repo) })
	return repo
}

func deleteXrStatusRepo(t *testing.T, server *config.ServerDetails, repo string) {
	assert.NoError(t, commonCommands.Exec(repository.NewRepoDeleteCommand().SetRepoPattern(repo).SetServerDetails(server).SetQuiet(true)))
}

func uploadXrStatusArtifact(t *testing.T, server *config.ServerDetails, repo string) (name string) {
	name = "xr-status-" + strconv.FormatInt(time.Now().UnixNano(), 10) + ".txt"
	localPath := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(localPath, []byte("xr-status"), 0o644))

	rtManager, err := artifactoryUtils.CreateServiceManager(server, -1, 0, false)
	require.NoError(t, err)
	params := services.NewUploadParams()
	params.Pattern = localPath
	params.Target = repo + "/"
	params.Flat = true
	uploaded, failed, err := rtManager.UploadFiles(clientartifactory.UploadServiceOptions{FailFast: true}, params)
	require.NoError(t, err)
	require.Equal(t, 0, failed)
	require.Equal(t, 1, uploaded)
	return name
}

func waitForXrStatusViolationScan(t *testing.T, server *config.ServerDetails, repo, path string) {
	xrayManager, err := corexray.CreateXrayServiceManager(server)
	require.NoError(t, err)
	// OverallCompletion also stops on FAILED/PARTIAL (which this command treats as
	// UNKNOWN, not ALLOWED) and NOT_SCANNED never reaches a terminal overall status at
	// all, so waiting on it here could run for the full 20-minute timeout. Poll the
	// violations step directly for the two states this command treats as ALLOWED.
	pollingExecutor := httputils.PollingExecutor{
		PollingInterval: 5 * time.Second,
		Timeout:         5 * time.Minute,
		MsgPrefix:       "Waiting for violation scan to reach a done/not-supported state... ",
		PollingAction: func() (shouldStop bool, responseBody []byte, err error) {
			status, statusErr := xrayManager.GetArtifactStatus(repo, path)
			if statusErr != nil {
				return true, nil, statusErr
			}
			switch status.Details.Violations.Status {
			case xrayServices.ArtifactStatusDone, xrayServices.ArtifactStatusNotSupported:
				return true, nil, nil
			default:
				return false, nil, nil
			}
		},
	}
	_, err = pollingExecutor.Execute()
	require.NoError(t, err)
}

func fetchXrStatus(t *testing.T, server *config.ServerDetails, repo, path string) *downloadstatus.Result {
	repoName, paths, err := downloadstatus.ParseArtifact(repo+"/"+path, server.Url)
	require.NoError(t, err)
	result, err := downloadstatus.NewDownloadStatusCommand().
		SetServerDetails(server).
		SetRepoAndPathCandidates(repoName, paths).
		SetOutputFormat(format.Json).
		FetchResult()
	require.NoError(t, err)
	return result
}

func TestXrStatusUploadedArtifact(t *testing.T) {
	integration.InitXrayTest(t, "")
	server := xrStatusServer()

	repo := createXrStatusLocalRepo(t, &server)
	name := uploadXrStatusArtifact(t, &server, repo)
	waitForXrStatusViolationScan(t, &server, repo, name)

	result := fetchXrStatus(t, &server, repo, name)
	assert.Equal(t, repo, result.Repo)
	assert.Empty(t, result.RequestedRepo)
	assert.Equal(t, name, result.Path)
	// No watch targets this artifact, so once scanning is done, nothing can block it.
	assert.Equal(t, downloadstatus.StatusAllowed, result.DownloadStatus)
	assert.Empty(t, result.Violations)
}

func TestXrStatusVirtualRepoResolvesToMember(t *testing.T) {
	integration.InitXrayTest(t, "")
	server := xrStatusServer()

	localRepo := createXrStatusLocalRepo(t, &server)
	name := uploadXrStatusArtifact(t, &server, localRepo)

	rtManager, err := artifactoryUtils.CreateServiceManager(&server, -1, 0, false)
	require.NoError(t, err)
	virtualRepo := "xr-status-virtual-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	params := services.NewGenericVirtualRepositoryParams()
	params.Key = virtualRepo
	params.Repositories = []string{localRepo}
	require.NoError(t, rtManager.CreateVirtualRepository().Generic(params))
	t.Cleanup(func() { deleteXrStatusRepo(t, &server, virtualRepo) })

	waitForXrStatusViolationScan(t, &server, localRepo, name)

	result := fetchXrStatus(t, &server, virtualRepo, name)
	assert.Equal(t, localRepo, result.Repo)
	assert.Equal(t, virtualRepo, result.RequestedRepo)
	assert.Equal(t, name, result.Path)
	assert.Equal(t, downloadstatus.StatusAllowed, result.DownloadStatus)
}

func TestXrStatusRemoteRepoResolvesToCache(t *testing.T) {
	integration.InitXrayTest(t, "")
	server := xrStatusServer()

	rtManager, err := artifactoryUtils.CreateServiceManager(&server, -1, 0, false)
	require.NoError(t, err)
	remoteRepo := "xr-status-remote-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	params := services.NewGenericRemoteRepositoryParams()
	params.Key = remoteRepo
	params.Url = "https://repo1.maven.org/maven2"
	params.XrayIndex = clientutils.Pointer(true)
	require.NoError(t, rtManager.CreateRemoteRepository().Generic(params))
	t.Cleanup(func() { deleteXrStatusRepo(t, &server, remoteRepo) })

	path := "junit/junit/4.13.2/junit-4.13.2.pom"
	reader, err := rtManager.ReadRemoteFile(remoteRepo + "/" + path)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())

	cacheRepo := remoteRepo + "-cache"
	waitForXrStatusViolationScan(t, &server, cacheRepo, path)

	result := fetchXrStatus(t, &server, remoteRepo, path)
	assert.Equal(t, cacheRepo, result.Repo)
	assert.Equal(t, remoteRepo, result.RequestedRepo)
	assert.Equal(t, path, result.Path)
	assert.Equal(t, downloadstatus.StatusAllowed, result.DownloadStatus)
}
