package indexer

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	gofrogio "github.com/jfrog/gofrog/io"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/lock"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray"
)

const (
	indexerDirName     = "xray-indexer"
	tempIndexerDirName = "temp"
)

func DownloadIndexerIfNeeded(xrayManager *xray.XrayServicesManager, xrayVersionStr string) (indexerPath string, err error) {
	dependenciesPath, err := config.GetJfrogDependenciesPath()
	if err != nil {
		return
	}
	indexerDirPath := filepath.Join(dependenciesPath, indexerDirName)
	indexerBinaryName := getIndexerBinaryName()
	indexerPath = filepath.Join(indexerDirPath, xrayVersionStr, indexerBinaryName)

	locksDirPath, err := coreutils.GetJfrogLocksDir()
	if err != nil {
		return
	}
	unlockFunc, err := lock.CreateLock(filepath.Join(locksDirPath, indexerDirName))
	// Defer the lockFile.Unlock() function before throwing a possible error to avoid deadlock situations.
	defer func() {
		e := unlockFunc()
		if err == nil {
			err = e
		}
	}()
	if err != nil {
		return
	}
	exists, err := fileutils.IsFileExists(indexerPath, false)
	if exists || err != nil {
		return
	}

	log.Info("JFrog Xray Indexer " + xrayVersionStr + " is not cached locally. Downloading it now...")
	indexerPath, err = downloadIndexer(xrayManager, indexerDirPath, indexerBinaryName)
	if err != nil {
		err = errors.New("failed while attempting to download Xray indexer: " + err.Error())
	}
	return
}

func downloadIndexer(xrayManager *xray.XrayServicesManager, indexerDirPath, indexerBinaryName string) (string, error) {
	tempDirPath, err := getTempDirForDownload(indexerDirPath)
	if err != nil {
		return "", err
	}
	// Delete all old indexers, but the two newest
	err = deleteOldIndexers(indexerDirPath)
	if err != nil {
		return "", err
	}
	// Download the indexer to a temporary directory
	binaryTempPath, err := xrayManager.DownloadIndexer(tempDirPath, indexerBinaryName)
	if err != nil {
		return "", err
	}
	// Get actual version of the downloaded indexer
	indexerVersion, err := getIndexerVersion(binaryTempPath)
	if err != nil {
		return "", err
	}
	log.Info("The downloaded Xray Indexer version is " + indexerVersion)
	// In case of a hot upgrade of Xray in progress, the version of the downloaded indexer might be different from the Xray version we got above,
	// so the indexer we just downloaded may already exist.
	newDirPath := filepath.Join(indexerDirPath, indexerVersion)
	newDirExists, err := fileutils.IsDirExists(newDirPath, false)
	if err != nil {
		return "", err
	}
	if newDirExists {
		err = fileutils.RemoveTempDir(tempDirPath)
	} else {
		err = fileutils.MoveDir(tempDirPath, newDirPath)
	}
	return filepath.Join(newDirPath, indexerBinaryName), errorutils.CheckError(err)
}

func getTempDirForDownload(indexerDirPath string) (string, error) {
	tempDirPath := filepath.Join(indexerDirPath, tempIndexerDirName)
	// Delete the temporary directory if it exists
	tempDirExists, err := fileutils.IsDirExists(tempDirPath, false)
	if err != nil {
		return "", err
	}
	if tempDirExists {
		err = fileutils.RemoveTempDir(tempDirPath)
		if err != nil {
			return "", errorutils.CheckErrorf("Temporary download directory already exists, and can't be removed: %s\nRemove this directory manually and try again: %s", err.Error(), tempDirPath)
		}
	}
	return tempDirPath, nil
}

func getIndexerVersion(indexerPath string) (string, error) {
	indexCmd := &coreutils.GeneralExecCmd{
		ExecPath: indexerPath,
		Command:  []string{"version"},
	}
	output, err := gofrogio.RunCmdOutput(indexCmd)
	if err != nil {
		return "", errorutils.CheckError(err)
	}
	splitOutput := strings.Split(output, " ")
	// The output of the command looks like: jfrog xray indexer-app version 1.2.3
	indexerVersion := strings.TrimSuffix(splitOutput[len(splitOutput)-1], "\n")
	return indexerVersion, nil
}

func deleteOldIndexers(indexerDirPath string) error {
	indexerDirExists, err := fileutils.IsDirExists(indexerDirPath, false)
	if !indexerDirExists || err != nil {
		return err
	}

	filesList, err := os.ReadDir(indexerDirPath)
	if err != nil {
		return errorutils.CheckError(err)
	}
	var dirsList []string
	for _, file := range filesList {
		if file.IsDir() {
			dirsList = append(dirsList, file.Name())
		}
	}

	if len(dirsList) <= 2 {
		return nil
	}

	sort.Slice(dirsList, func(i, j int) bool {
		currVersion := version.NewVersion(dirsList[i])
		return currVersion.AtLeast(dirsList[j])
	})

	for i := 2; i < len(dirsList); i++ {
		err = os.RemoveAll(filepath.Join(indexerDirPath, dirsList[i]))
		if err != nil {
			return errorutils.CheckError(err)
		}
	}

	return nil
}

func getIndexerBinaryName() string {
	switch runtime.GOOS {
	case "windows":
		return "indexer-app.exe"
	default:
		return "indexer-app"
	}
}
