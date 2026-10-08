package main

import (
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

func TestXrStatusUploadedArtifact(t *testing.T) {
	integration.InitXrayTest(t, "")

	server := *integration.GetTestServerDetails()
	if server.XrayUrl == "" {
		server.XrayUrl = clientutils.AddTrailingSlashIfNeeded(server.Url) + securityTests.XrayEndpoint
	}

	// cli-rt1 and the other shared fixtures are only provisioned for
	// --test.artifactory/--test.dockerScan jobs, not for an Xray-only job, and
	// may not be Xray-indexed either. This test needs a repo it knows is both.
	repo := "xr-status-test-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	require.NoError(t, securityArtifactory.CreateGenericLocalRepository(repo, &server, true, ""))
	defer func() {
		assert.NoError(t, commonCommands.Exec(repository.NewRepoDeleteCommand().SetRepoPattern(repo).SetServerDetails(&server).SetQuiet(true)))
	}()

	dir := t.TempDir()
	name := "xr-status-" + strconv.FormatInt(time.Now().UnixNano(), 10) + ".txt"
	localPath := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(localPath, []byte("xr-status"), 0o644))

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

	repoName, paths, err := downloadstatus.ParseArtifact(repo+"/"+name, server.Url)
	require.NoError(t, err)

	xrayManager, err := corexray.CreateXrayServiceManager(&server)
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
			status, statusErr := xrayManager.GetArtifactStatus(repoName, paths[0])
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
