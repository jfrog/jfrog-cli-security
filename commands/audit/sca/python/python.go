package python

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jfrog/gofrog/version"

	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/build-info-go/utils/pythonutils"
	"github.com/jfrog/gofrog/datastructures"
	utils "github.com/jfrog/jfrog-cli-artifactory/artifactory/commands/python"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca"
	xrayutils2 "github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	PythonPackageTypeIdentifier = "pypi://"
	pythonReportFile            = "report.json"

	CurationPipMinimumVersion = "23.0.0"
)

type AuditPython struct {
	Server              *config.ServerDetails
	Tool                pythonutils.PythonTool
	RemotePypiRepo      string
	PipRequirementsFile string
	InstallCommandArgs  []string
	IsCurationCmd       bool
}

func BuildDependencyTree(auditPython *AuditPython) (dependencyTree []*xrayUtils.GraphNode, uniqueDeps []string, downloadUrls map[string]string, err error) {
	dependenciesGraph, directDependenciesList, pipUrls, errGetTree := getDependencies(auditPython)
	if errGetTree != nil {
		err = errGetTree
		return
	}
	downloadUrls = pipUrls
	directDependencies := []*xrayUtils.GraphNode{}
	uniqueDepsSet := datastructures.MakeSet[string]()
	for _, rootDep := range directDependenciesList {
		directDependency := &xrayUtils.GraphNode{
			Id:    PythonPackageTypeIdentifier + rootDep,
			Nodes: []*xrayUtils.GraphNode{},
		}
		populatePythonDependencyTree(directDependency, dependenciesGraph, uniqueDepsSet)
		directDependencies = append(directDependencies, directDependency)
	}
	root := &xrayUtils.GraphNode{
		Id:    "root",
		Nodes: directDependencies,
	}
	dependencyTree = []*xrayUtils.GraphNode{root}
	uniqueDeps = uniqueDepsSet.ToSlice()
	return
}

func getDependencies(auditPython *AuditPython) (dependenciesGraph map[string][]string, directDependencies []string, pipUrls map[string]string, err error) {
	wd, err := os.Getwd()
	if errorutils.CheckError(err) != nil {
		return
	}

	// Create temp dir to run all work outside users working directory
	tempDirPath, err := fileutils.CreateTempDir()
	if err != nil {
		return
	}

	err = os.Chdir(tempDirPath)
	if errorutils.CheckError(err) != nil {
		return
	}

	defer func() {
		err = errors.Join(
			err,
			errorutils.CheckError(os.Chdir(wd)),
			fileutils.RemoveTempDir(tempDirPath),
		)
	}()

	// Exclude Visual Studio inner directory since it is not necessary for the scan process and may cause race condition.
	err = biutils.CopyDir(wd, tempDirPath, true, []string{sca.DotVsRepoSuffix})
	if err != nil {
		return
	}

	restoreEnv, err := runPythonInstall(auditPython)
	defer func() {
		err = errors.Join(err, restoreEnv())
	}()
	if err != nil {
		return
	}

	localDependenciesPath, err := config.GetJfrogDependenciesPath()
	if err != nil {
		return
	}
	dependenciesGraph, directDependencies, err = pythonutils.GetPythonDependencies(auditPython.Tool, tempDirPath, localDependenciesPath, log.GetLogger())
	if err != nil {
		sca.LogExecutableVersion("python")
		sca.LogExecutableVersion(string(auditPython.Tool))
	}
	if !auditPython.IsCurationCmd {
		return
	}
	pipUrls, errProcessed := processPipDownloadsUrlsFromReportFile()
	if errProcessed != nil {
		err = errProcessed

	}
	return
}

func processPipDownloadsUrlsFromReportFile() (map[string]string, error) {
	pipReport, err := readPipReportIfExists()
	if err != nil {
		return nil, err
	}
	pipUrls := map[string]string{}
	for _, dep := range pipReport.Install {
		if dep.MetaData.Name != "" {
			compId := PythonPackageTypeIdentifier + strings.ToLower(dep.MetaData.Name) + ":" + dep.MetaData.Version
			pipUrls[compId] = strings.Replace(dep.DownloadInfo.Url, "api/curation/audit/", "", 1)
		}
	}
	return pipUrls, nil
}

func readPipReportIfExists() (pipReport *pypiReport, err error) {
	if exist, existErr := fileutils.IsFileExists(pythonReportFile, false); existErr != nil {
		err = existErr
		return
	} else if !exist {
		err = errors.New("process failed, report file wasn't found, cant processed with curation command")
		return
	}

	var reportBytes []byte
	if reportBytes, err = fileutils.ReadFile(pythonReportFile); err != nil {
		return
	}
	pipReport = &pypiReport{}
	if err = json.Unmarshal(reportBytes, pipReport); err != nil {
		return
	}
	return
}

type pypiReport struct {
	Install []pypiReportInfo
}

type pypiReportInfo struct {
	DownloadInfo pypiDownloadInfo `json:"download_info"`
	MetaData     pypiMetaData     `json:"metadata"`
}

type pypiDownloadInfo struct {
	Url string `json:"url"`
}

type pypiMetaData struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func runPythonInstall(auditPython *AuditPython) (restoreEnv func() error, err error) {
	switch auditPython.Tool {
	case pythonutils.Pip:
		return installPipDeps(auditPython)
	case pythonutils.Pipenv:
		return installPipenvDeps(auditPython)
	case pythonutils.Poetry:
		return installPoetryDeps(auditPython)
	}
	return
}

func installPoetryDeps(auditPython *AuditPython) (restoreEnv func() error, err error) {
	restoreEnv = func() error {
		return nil
	}
	if auditPython.RemotePypiRepo != "" {
		rtUrl, username, password, err := utils.GetPypiRepoUrlWithCredentials(auditPython.Server, auditPython.RemotePypiRepo, false)
		if err != nil {
			return restoreEnv, err
		}
		if password != "" {
			err = utils.ConfigPoetryRepo(rtUrl.Scheme+"://"+rtUrl.Host+rtUrl.Path, username, password, auditPython.RemotePypiRepo)
			if err != nil {
				return restoreEnv, err
			}
		}
	}
	// Run 'poetry install'
	_, err = executeCommand("poetry", "install")
	return restoreEnv, err
}

func installPipenvDeps(auditPython *AuditPython) (restoreEnv func() error, err error) {
	// Set virtualenv path to venv dir
	err = os.Setenv("WORKON_HOME", ".jfrog")
	if err != nil {
		return
	}
	restoreEnv = func() error {
		return os.Unsetenv("WORKON_HOME")
	}
	if auditPython.RemotePypiRepo != "" {
		return restoreEnv, runPipenvInstallFromRemoteRegistry(auditPython.Server, auditPython.RemotePypiRepo)
	}
	// Run 'pipenv install -d'
	_, err = executeCommand("pipenv", "install", "-d")
	return restoreEnv, err
}

func installPipDeps(auditPython *AuditPython) (restoreEnv func() error, err error) {
	restoreEnv, err = SetPipVirtualEnvPath()
	if err != nil {
		return
	}

	remoteUrl := ""
	if auditPython.RemotePypiRepo != "" {
		remoteUrl, err = utils.GetPypiRepoUrl(auditPython.Server, auditPython.RemotePypiRepo, auditPython.IsCurationCmd)
		if err != nil {
			return
		}
	}

	var curationCachePip string
	var reportFileName string
	if auditPython.IsCurationCmd {
		// upgrade pip version to 23.0.0, as it is required for the curation command.
		if err = upgradePipVersion(CurationPipMinimumVersion); err != nil {
			log.Warn(fmt.Sprintf("Failed to upgrade pip version, err: %v", err))
		}
		if curationCachePip, err = xrayutils2.GetCurationPipCacheFolder(); err != nil {
			return
		}
		reportFileName = pythonReportFile
	}

	pipInstallArgs := getPipInstallArgs(auditPython.PipRequirementsFile, remoteUrl, curationCachePip, reportFileName, auditPython.InstallCommandArgs...)
	var reqErr error
	_, err = executeCommand("python", pipInstallArgs...)
	if err != nil && auditPython.PipRequirementsFile == "" {
		pipInstallArgs = getPipInstallArgs("requirements.txt", remoteUrl, curationCachePip, reportFileName, auditPython.InstallCommandArgs...)
		_, reqErr = executeCommand("python", pipInstallArgs...)
		if reqErr != nil {
			// Return Pip install error and log the requirements fallback error.
			log.Debug(reqErr.Error())
		} else {
			err = nil
		}
	}
	if err != nil || reqErr != nil {
		if msgToUser := sca.GetMsgToUserForCurationBlock(auditPython.IsCurationCmd, techutils.Pip, errors.Join(err, reqErr).Error()); msgToUser != "" {
			err = errors.Join(err, errors.New(msgToUser))
		}
	}
	return
}

func upgradePipVersion(atLeastVersion string) (err error) {
	output, err := executeCommand("python", "-m", "pip", "--version")
	if err != nil {
		return
	}
	outputVersion := ""
	if splitVersion := strings.Split(output, " "); len(splitVersion) > 1 {
		outputVersion = splitVersion[1]
	}
	log.Debug("Current pip version in virtual env:", outputVersion)
	if version.NewVersion(outputVersion).AtLeast(atLeastVersion) {
		return
	}
	_, err = executeCommand("python", "-m", "pip", "install", "--upgrade", "pip")
	return
}

func executeCommand(executable string, args ...string) (string, error) {
	installCmd := exec.Command(executable, args...)
	maskedCmdString := coreutils.GetMaskedCommandString(installCmd)
	log.Debug("Running", maskedCmdString)
	output, err := installCmd.CombinedOutput()
	if err != nil {
		sca.LogExecutableVersion(executable)
		return string(output), errorutils.CheckErrorf("%q command failed: %s - %s", maskedCmdString, err.Error(), output)
	}
	return string(output), nil
}

func getPipInstallArgs(requirementsFile, remoteUrl, cacheFolder, reportFileName string, customArgs ...string) []string {
	args := []string{"-m", "pip", "install"}
	if requirementsFile == "" {
		// Run 'pip install .'
		args = append(args, ".")
	} else {
		// Run pip 'install -r requirements <requirementsFile>'
		args = append(args, "-r", requirementsFile)
	}
	if remoteUrl != "" {
		args = append(args, utils.GetPypiRemoteRegistryFlag(pythonutils.Pip), remoteUrl)
	}
	if cacheFolder != "" {
		args = append(args, "--cache-dir", cacheFolder)
	}
	if reportFileName != "" {
		// For report to include download urls, pip should ignore installed packages.
		args = append(args, "--ignore-installed")
		args = append(args, "--report", reportFileName)
	}
	args = append(args, parseCustomArgs(remoteUrl, cacheFolder, reportFileName, customArgs...)...)
	return args
}

func parseCustomArgs(remoteUrl, cacheFolder, reportFileName string, customArgs ...string) (args []string) {
	for i := 0; i < len(customArgs); i++ {
		if strings.Contains(customArgs[i], "-r") {
			log.Warn("The -r flag is not supported in the custom arguments list. use the 'PipRequirementsFile' instead.")
			i++
			continue
		}
		if strings.Contains(customArgs[i], "--cache-dir") {
			if cacheFolder != "" {
				log.Warn("The --cache-dir flag is not supported in the custom arguments list. skipping...")
			} else if i+1 < len(customArgs) {
				args = append(args, customArgs[i], customArgs[i+1])
			}
			i++
			continue
		}
		if reportFileName != "" {
			if strings.Contains(customArgs[i], "--report") {
				log.Warn("The --report flag is not supported in the custom arguments list. skipping...")
				i++
				continue
			}
			if strings.Contains(customArgs[i], "--ignore-installed") {
				// will be added by default
				continue
			}
		}
		if remoteUrl != "" && strings.Contains(customArgs[i], utils.GetPypiRemoteRegistryFlag(pythonutils.Pip)) {
			log.Warn("The remote registry flag is not supported in the custom arguments list. skipping...")
			i++
			continue
		}
		args = append(args, customArgs[i])
	}
	return
}

func runPipenvInstallFromRemoteRegistry(server *config.ServerDetails, depsRepoName string) (err error) {
	rtUrl, err := utils.GetPypiRepoUrl(server, depsRepoName, false)
	if err != nil {
		return err
	}
	args := []string{"install", "-d", utils.GetPypiRemoteRegistryFlag(pythonutils.Pipenv), rtUrl}
	_, err = executeCommand("pipenv", args...)
	return err
}

// Execute virtualenv command: "virtualenv venvdir" / "python3 -m venv venvdir" and set path
func SetPipVirtualEnvPath() (restoreEnv func() error, err error) {
	restoreEnv = func() error {
		return nil
	}
	venvdirName := "venvdir"
	var cmdArgs []string
	pythonPath, windowsPyArg := pythonutils.GetPython3Executable()
	if windowsPyArg != "" {
		// Add '-3' arg for windows 'py -3' command
		cmdArgs = append(cmdArgs, windowsPyArg)
	}
	cmdArgs = append(cmdArgs, "-m", "venv", venvdirName)
	_, err = executeCommand(pythonPath, cmdArgs...)
	if err != nil {
		// Failed running 'python -m venv', trying to run 'virtualenv'
		log.Debug("Failed running python venv:", err.Error())
		_, err = executeCommand("virtualenv", "-p", pythonPath, venvdirName)
		if err != nil {
			return
		}
	}

	// Keep original value of 'PATH'.
	origPathValue := os.Getenv("PATH")
	venvPath, err := filepath.Abs(venvdirName)
	if err != nil {
		return
	}
	var venvBinPath string
	if runtime.GOOS == "windows" {
		venvBinPath = filepath.Join(venvPath, "Scripts")
	} else {
		venvBinPath = filepath.Join(venvPath, "bin")
	}
	err = os.Setenv("PATH", fmt.Sprintf("%s%c%s", venvBinPath, os.PathListSeparator, origPathValue))
	if err != nil {
		return
	}
	restoreEnv = func() error {
		return os.Setenv("PATH", origPathValue)
	}
	return
}

func populatePythonDependencyTree(currNode *xrayUtils.GraphNode, dependenciesGraph map[string][]string, uniqueDepsSet *datastructures.Set[string]) {
	if currNode.NodeHasLoop() {
		return
	}
	uniqueDepsSet.Add(currNode.Id)
	currDepChildren := dependenciesGraph[strings.TrimPrefix(currNode.Id, PythonPackageTypeIdentifier)]
	// Recursively create & append all node's dependencies.
	for _, dependency := range currDepChildren {
		childNode := &xrayUtils.GraphNode{
			Id:     PythonPackageTypeIdentifier + dependency,
			Nodes:  []*xrayUtils.GraphNode{},
			Parent: currNode,
		}
		currNode.Nodes = append(currNode.Nodes, childNode)
		populatePythonDependencyTree(childNode, dependenciesGraph, uniqueDepsSet)
	}
}
