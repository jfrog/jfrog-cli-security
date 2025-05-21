package java

import (
	"bufio"
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
	isCurationCmd bool
}

func NewGradleDepTreeManager(params *DepTreeParams, cmdName MavenDepTreeCmd) *gradleDepTreeManager {
	depTreeManager := NewDepTreeManager(&DepTreeParams{
		Server:   params.Server,
		DepsRepo: params.DepsRepo,
	})
	return &gradleDepTreeManager{
		DepTreeManager: depTreeManager,
		isCurationCmd:  params.IsCurationCmd,
	}
}

func buildGradleDependencyTree(params *DepTreeParams) (dependencyTree []*xrayUtils.GraphNode, uniqueDeps map[string]*xray.DepTreeNode, err error) {
	manager := NewGradleDepTreeManager(params, Tree)
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
	var releasesRepo string
	releasesRepo, gdt.depsRepo, err = getRemoteRepos(gdt.depsRepo, gdt.server)
	if err != nil {
		return
	}
	gradleDepTreeJarPath := filepath.Join(tmpDir, gradleDepTreeJarFile)
	if err = errorutils.CheckError(os.WriteFile(gradleDepTreeJarPath, gradleDepTreeJar, 0600)); err != nil {
		return
	}
	gradleDepTreeJarPath = ioutils.DoubleWinPathSeparator(gradleDepTreeJarPath)

	depTreeInitScript := fmt.Sprintf(gradleDepTreeInitScript, releasesRepo, gradleDepTreeJarPath, gdt.depsRepo)
	return tmpDir, errorutils.CheckError(os.WriteFile(filepath.Join(tmpDir, gradleDepTreeInitFile), []byte(depTreeInitScript), 0666))
}

// getRemoteRepos constructs the sections of Artifactory's remote repositories in the gradle-dep-tree init script.
// depsRemoteRepo - name of the remote repository that proxies the relevant registry, e.g. maven central.
// server - the Artifactory server details on which the repositories reside in.
// Returns the constructed sections.
func getRemoteRepos(depsRepo string, server *config.ServerDetails) (string, string, error) {
	constructedReleasesRepo, err := constructReleasesRemoteRepo()
	if err != nil {
		return "", "", err
	}
	constructedDepsRepo, err := getDepTreeArtifactoryRepository(depsRepo, server)
	if err != nil {
		return "", "", err
	}
	return constructedReleasesRepo, constructedDepsRepo, nil
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
	TempFileCreated := false

	gradleExecPath, err := build.GetGradleExecPath(gdt.useWrapper)
	if err != nil {
		err = errorutils.CheckError(err)
		return
	}
	if gdt.isCurationCmd {
		TempFileCreated = createTempBuildGradleFile()
	}
	outputFilePath := filepath.Join(depTreeDir, gradleDepTreeOutputFile)
	tasks := []string{
		"clean",
		"generateDepTrees", "-I", filepath.Join(depTreeDir, gradleDepTreeInitFile),
		"-q",
		gradleNoCacheFlag,
		fmt.Sprintf("-Dcom.jfrog.depsTreeOutputFile=%s", outputFilePath),
		"-Dcom.jfrog.includeAllBuildFiles=true"}
	log.Info("Running gradle deps tree command:", gradleExecPath, strings.Join(tasks, " "))
	if output, err := exec.Command(gradleExecPath, tasks...).CombinedOutput(); err != nil {
		return nil, errorutils.CheckErrorf("error running gradle-dep-tree: %s\n%s", err.Error(), string(output))
	}
	defer func() {
		err = errors.Join(err, errorutils.CheckError(os.Remove(outputFilePath)))
	}()
	if TempFileCreated {
		if err := renameTempToBuildGradle(); err != nil {
			fmt.Printf("Failed to rename temporary build.gradle: %v\n", err)
		}
	}
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

	log.Debug("The project dependencies will be resolved from", server.ArtifactoryUrl, "from the", remoteRepo, "repository")
	return fmt.Sprintf(artifactoryRepository,
		strings.TrimSuffix(server.ArtifactoryUrl, "/"),
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

// this function attempts to create a temporary modified version of build.gradle.
// Returns true if successful, false otherwise.
func createTempBuildGradleFile() bool {
	cwd, err := os.Getwd()
	if err != nil {
		return false
	}
	buildGradlePath := filepath.Join(cwd, "build.gradle")
	if _, err := os.Stat(buildGradlePath); os.IsNotExist(err) {
		return false
	} else if err != nil {
		return false
	}
	if err := modifyArtifactoryURL(buildGradlePath); err != nil {
		return false
	}
	return true
}

// this functions renames the given build.gradle to a temp file, modifies URLs inside,
// and writes changes back to build.gradle.
// Returns error if any step fails.
func modifyArtifactoryURL(filePath string) error {
	// 1. Create the persistent backup of the original file
	persistentBackupPath := filePath + ".tmp"

	_ = os.Remove(persistentBackupPath)

	originalContent, err := os.ReadFile(filePath)

	if err != nil {
		return fmt.Errorf("failed to read original file '%s' for backup: %w", filePath, err)
	}
	err = os.WriteFile(persistentBackupPath, originalContent, 0644)
	if err != nil {
		return fmt.Errorf("failed to write persistent backup to '%s': %w", persistentBackupPath, err)
	}
	internalTmpFilePath := filePath + ".current_op_tmp"
	_ = os.Remove(internalTmpFilePath)
	err = os.Rename(filePath, internalTmpFilePath)
	if err != nil {
		return fmt.Errorf("failed to rename file '%s' to internal temp '%s': %w", filePath, internalTmpFilePath, err)
	}
	operationSuccessful := false
	defer func() {
		if !operationSuccessful {
			if _, statErr := os.Stat(internalTmpFilePath); statErr == nil {
				_ = os.Remove(filePath)
				_ = os.Rename(internalTmpFilePath, filePath)
			}
		} else {
			_ = os.Remove(internalTmpFilePath)
		}
	}()

	srcFile, err := os.Open(internalTmpFilePath)
	if err != nil {
		return fmt.Errorf("failed to open internal temp file '%s' for reading: %w", internalTmpFilePath, err)
	}
	defer srcFile.Close()

	destFile, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create target file '%s' for writing: %w", filePath, err)
	}
	defer destFile.Close()

	scanner := bufio.NewScanner(srcFile)
	writer := bufio.NewWriter(destFile)

	inPublishingBlock := false
	publishingBraceCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineToWrite := line
		trimmedLine := strings.TrimSpace(line)
		isLineEffectivelyInPublishingBlock := inPublishingBlock

		if !inPublishingBlock {
			if strings.Contains(strings.ToLower(trimmedLine), "publishing") && strings.Contains(trimmedLine, "{") {
				inPublishingBlock = true
				isLineEffectivelyInPublishingBlock = true
				publishingBraceCount += strings.Count(trimmedLine, "{")
				publishingBraceCount -= strings.Count(trimmedLine, "}")
				if publishingBraceCount <= 0 {
					inPublishingBlock = false
					publishingBraceCount = 0
				}
			}
		} else {
			publishingBraceCount += strings.Count(trimmedLine, "{")
			publishingBraceCount -= strings.Count(trimmedLine, "}")
			if publishingBraceCount <= 0 {
				inPublishingBlock = false
				publishingBraceCount = 0
			}
		}
		if !isLineEffectivelyInPublishingBlock {
			if strings.HasPrefix(strings.ToLower(trimmedLine), "url") &&
				strings.Contains(trimmedLine, "/artifactory/") &&
				!strings.Contains(trimmedLine, "/artifactory/api/curation/audit/") {
				lineToWrite = strings.Replace(line, "/artifactory/", "/artifactory/api/curation/audit/", 1)
			}
		}
		_, errWrite := writer.WriteString(lineToWrite + "\n")
		if errWrite != nil {
			return fmt.Errorf("failed to write to target file '%s': %w", filePath, errWrite)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading from internal temp file '%s': %w", internalTmpFilePath, err)
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush writer for target file '%s': %w", filePath, err)
	}
	operationSuccessful = true
	return nil
}

// renameTempToBuildGradle safely renames the temporary build.gradle.tmp file back to build.gradle,
// Returns error on failure.
func renameTempToBuildGradle() error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}
	tmpFilePath := filepath.Join(cwd, "build.gradle.tmp")
	buildGradlePath := filepath.Join(cwd, "build.gradle")

	if _, err := os.Stat(tmpFilePath); os.IsNotExist(err) {
		return fmt.Errorf("temporary file does not exist: %s", tmpFilePath)
	} else if err != nil {
		return fmt.Errorf("failed to stat temporary file: %w", err)
	}
	err = os.Rename(tmpFilePath, buildGradlePath)
	if err != nil {
		if _, err := os.Stat(buildGradlePath); err == nil {
			err = os.Remove(buildGradlePath)
			if err != nil {
				return fmt.Errorf("failed to remove existing build.gradle: %w", err)
			}
			err = os.Rename(tmpFilePath, buildGradlePath)
			if err != nil {
				return fmt.Errorf("failed to rename temporary file to build.gradle: %w", err)
			}
		} else {
			return fmt.Errorf("failed to rename temporary file to build.gradle: %w", err)
		}
	}
	return nil
}
