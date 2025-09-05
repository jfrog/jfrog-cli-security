package java

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jfrog/jfrog-cli-security/utils/xray"

	"github.com/jfrog/build-info-go/build"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/ioutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

const (
	remoteDepTreePath       = "artifactory/oss-release-local"
	gradlew                 = "gradlew"
	gradleDepTreeJarFile    = "gradle-dep-tree.jar"
	gradleDepTreeInitFile   = "gradledeptree.init"
	gradleDepTreeOutputFile = "gradledeptree.out"
	gradleNoCacheFlag       = "-Dorg.gradle.configuration-cache=false"
	gradleDepTreeInitScript = `initscript {
	repositories { %s
		mavenCentral()
	}
	dependencies {
		classpath files('%s')
	}
}

allprojects {
	repositories { %s
	}
	apply plugin: com.jfrog.GradleDepTree
}`
	artifactoryRepository = `
		maven {
			url "%s/%s"
			credentials {
				username = '%s'
				password = '%s'
			}
		}`
)

//go:embed resources/gradle-dep-tree.jar
var gradleDepTreeJar []byte

type gradleDepTreeManager struct {
	DepTreeManager
	isCurationCmd       bool
	curationCacheFolder string
	originalDepsRepo    string
}

func buildGradleDependencyTree(params *DepTreeParams) (dependencyTree []*xrayUtils.GraphNode, uniqueDeps map[string]*xray.DepTreeNode, err error) {
	manager := &gradleDepTreeManager{
		DepTreeManager:      NewDepTreeManager(params),
		isCurationCmd:       params.IsCurationCmd,
		curationCacheFolder: params.CurationCacheFolder,
		originalDepsRepo:    params.DepsRepo,
	}
	outputFileContent, err := manager.runGradleDepTree()
	if err != nil {
		return
	}
	dependencyTree, uniqueDeps, err = getGraphFromDepTree(outputFileContent)
	return
}

func (gdt *gradleDepTreeManager) runGradleDepTree() (string, error) {
	// Create the script file in the repository
	depTreeDir, err := gdt.createDepTreeScriptAndGetDir()
	if err != nil {
		return "", err
	}
	defer func() {
		err = errors.Join(err, fileutils.RemoveTempDir(depTreeDir))
	}()

	if gdt.useWrapper {
		gdt.useWrapper, err = isGradleWrapperExist()
		if err != nil {
			return "", err
		}
	}

	output, err := gdt.execGradleDepTree(depTreeDir)
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func (gdt *gradleDepTreeManager) createDepTreeScriptAndGetDir() (tmpDir string, err error) {
	tmpDir, err = fileutils.CreateTempDir()
	if err != nil {
		return
	}

	// Get repository configurations
	releasesRepo, err := constructReleasesRemoteRepo()
	if err != nil {
		return
	}

	// Get dependencies repository (with pass-through ONLY for curation commands)
	var depsRepo string
	if gdt.isCurationCmd {
		// Use pass-through URL for curation commands
		depsRepo, err = getDepTreeArtifactoryRepositoryWithPassThrough(gdt.originalDepsRepo, gdt.server, true)
	} else {
		// Use regular URL for non-curation commands
		depsRepo, err = getDepTreeArtifactoryRepository(gdt.DepTreeManager.depsRepo, gdt.DepTreeManager.server)
	}
	if err != nil {
		return
	}
	gradleDepTreeJarPath := filepath.Join(tmpDir, gradleDepTreeJarFile)
	if err = errorutils.CheckError(os.WriteFile(gradleDepTreeJarPath, gradleDepTreeJar, 0600)); err != nil {
		return
	}
	gradleDepTreeJarPath = ioutils.DoubleWinPathSeparator(gradleDepTreeJarPath)

	depTreeInitScript := fmt.Sprintf(gradleDepTreeInitScript, releasesRepo, gradleDepTreeJarPath, depsRepo)
	return tmpDir, errorutils.CheckError(os.WriteFile(filepath.Join(tmpDir, gradleDepTreeInitFile), []byte(depTreeInitScript), 0666))
}

func constructReleasesRemoteRepo() (string, error) {
	// Try to retrieve the serverID and remote repository that proxies https://releases.jfrog.io, from the environment variable
	serverId, repoName, err := coreutils.GetServerIdAndRepo(coreutils.ReleasesRemoteEnv)
	if err != nil || serverId == "" || repoName == "" {
		return "", err
	}
	releasesServer, err := config.GetSpecificConfig(serverId, false, true)
	if err != nil {
		return "", err
	}

	releasesPath := fmt.Sprintf("%s/%s", repoName, remoteDepTreePath)
	log.Debug("The `"+gradleDepTreeJarFile+"` will be resolved from", repoName)
	return getDepTreeArtifactoryRepository(releasesPath, releasesServer)
}

func (gdt *gradleDepTreeManager) execGradleDepTree(depTreeDir string) (outputFileContent []byte, err error) {

	gradleExecPath, err := build.GetGradleExecPath(gdt.useWrapper)
	if err != nil {
		err = errorutils.CheckError(err)
		return
	}
	outputFilePath := filepath.Join(depTreeDir, gradleDepTreeOutputFile)
	tasks := []string{
		"clean",
		"generateDepTrees", "-I", filepath.Join(depTreeDir, gradleDepTreeInitFile),
		"-q",
		gradleNoCacheFlag,
		fmt.Sprintf("-Dcom.jfrog.depsTreeOutputFile=%s", outputFilePath),
		"-Dcom.jfrog.includeAllBuildFiles=true"}

	// Always use temp directory for Gradle cache to isolate all downloads
	// This ensures all packages are downloaded to temp directory and cleaned up automatically
	gradleCacheDir := filepath.Join(depTreeDir, "gradle-cache")
	tasks = append(tasks, fmt.Sprintf("-Dgradle.user.home=%s", depTreeDir))
	log.Debug("Using temp directory for Gradle cache:", gradleCacheDir)

	log.Info("Running gradle deps tree command:", gradleExecPath, strings.Join(tasks, " "))
	if output, err := exec.Command(gradleExecPath, tasks...).CombinedOutput(); err != nil {
		return nil, errorutils.CheckErrorf("error running gradle-dep-tree: %s\n%s", err.Error(), string(output))
	}
	defer func() {
		err = errors.Join(err, errorutils.CheckError(os.Remove(outputFilePath)))
	}()
	outputFileContent, err = os.ReadFile(outputFilePath)
	err = errorutils.CheckError(err)
	return
}

func getDepTreeArtifactoryRepository(remoteRepo string, server *config.ServerDetails) (string, error) {
	if remoteRepo == "" || server.IsEmpty() {
		return "", nil
	}
	username, password, err := getArtifactoryAuthFromServer(server)
	if err != nil {
		return "", err
	}

	artifactoryUrl := strings.TrimSuffix(server.ArtifactoryUrl, "/")

	return fmt.Sprintf(artifactoryRepository,
		artifactoryUrl,
		remoteRepo,
		username,
		password), nil
}

func getDepTreeArtifactoryRepositoryWithPassThrough(remoteRepo string, server *config.ServerDetails, usePassThrough bool) (string, error) {
	if remoteRepo == "" || server.IsEmpty() {
		return "", nil
	}
	username, password, err := getArtifactoryAuthFromServer(server)
	if err != nil {
		return "", err
	}

	artifactoryUrl := strings.TrimSuffix(server.ArtifactoryUrl, "/")

	// Add /api/curation/audit/ prefix to bypass vulnerability blocking during security scanning
	if usePassThrough {
		artifactoryUrl += "/api/curation/audit"
	}
	return fmt.Sprintf(artifactoryRepository,
		artifactoryUrl,
		remoteRepo,
		username,
		password), nil
}

// This function assumes that the Gradle wrapper is in the root directory.
// The --project-dir option of Gradle won't work in this case.
func isGradleWrapperExist() (bool, error) {
	wrapperName := gradlew
	if coreutils.IsWindows() {
		wrapperName += ".bat"
	}
	return fileutils.IsFileExists(wrapperName, false)
}
