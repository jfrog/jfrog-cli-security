package python

import (
	"encoding/json"
	"errors"
	"fmt"
	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/build-info-go/utils/pythonutils"
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	utils "github.com/jfrog/jfrog-cli-core/v2/utils/python"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca"
	xrayutils2 "github.com/jfrog/jfrog-cli-security/utils"
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
)

type AuditPython struct {
	Server              *config.ServerDetails
	Tool                pythonutils.PythonTool
	RemotePypiRepo      string
	PipRequirementsFile string
	IsCurationCmd       bool
}

func BuildDependencyTree(serverDetails *config.ServerDetails, tech coreutils.Technology, params xrayutils2.AuditParams) (dependencyTree []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	dependenciesGraph, directDependenciesList, err := getDependencies(serverDetails, tech, params)
	if err != nil {
		return
	}
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

func getDependencies(serverDetails *config.ServerDetails, tech coreutils.Technology,
	params xrayutils2.AuditParams) (dependenciesGraph map[string][]string, directDependencies []string, err error) {
	auditPython := &AuditPython{
		Server:              serverDetails,
		Tool:                pythonutils.PythonTool(tech),
		RemotePypiRepo:      params.DepsRepo(),
		PipRequirementsFile: params.PipRequirementsFile(),
		IsCurationCmd:       params.IsCurationCmd(),
	}
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

	err = biutils.CopyDir(wd, tempDirPath, true, nil)
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
	dependenciesGraph, directDependencies, err = pythonutils.GetPythonDependencies(auditPython.Tool, tempDirPath, localDependenciesPath)
	if err != nil {
		sca.LogExecutableVersion("python")
		sca.LogExecutableVersion(string(auditPython.Tool))
	}
	if auditPython.IsCurationCmd {
		pipUrls, errProcessed := processPipDownloadsUrlsFromReportFile()
		if errProcessed != nil {
			err = errProcessed
			return
		}
		params.SetDownloadUrls(pipUrls)
	}
	return
}

func processPipDownloadsUrlsFromReportFile() (map[string]string, error) {
	exist, err := fileutils.IsFileExists("report.json", false)
	if err != nil {
		return nil, err
	}
	if !exist {
		err = errors.New("process failed, report file wasn't found, cant processed with curation command")
		return nil, err
	}
	var reportBytes []byte
	reportBytes, err = fileutils.ReadFile("report.json")
	if err != nil {
		return nil, err
	}
	pipReport := &pypiReport{}
	if err = json.Unmarshal(reportBytes, pipReport); err != nil {
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

type pypiReport struct {
	Install []pypiReportInfo
}

type pypiReportInfo struct {
	DownloadInfo pypiDwonloadInfo `json:"download_info"`
	MetaData     pypiMetaData     `json:"metadata"`
}

type pypiDwonloadInfo struct {
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
	return restoreEnv, executeCommand("poetry", "install")
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
	return restoreEnv, executeCommand("pipenv", "install", "-d")
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
		curationCachePip, err = xrayutils2.GetCurationPipCacheFolder()
		if err != nil {
			return
		}
		reportFileName = "report.json"
	}

	pipInstallArgs := getPipInstallArgs(auditPython.PipRequirementsFile, remoteUrl, curationCachePip, reportFileName)
	err = executeCommand("python", pipInstallArgs...)
	if err != nil && auditPython.PipRequirementsFile == "" {
		pipInstallArgs = getPipInstallArgs("requirements.txt", remoteUrl, curationCachePip, reportFileName)
		reqErr := executeCommand("python", pipInstallArgs...)
		if reqErr != nil {
			// Return Pip install error and log the requirements fallback error.
			log.Debug(reqErr.Error())
		} else {
			err = nil
		}
	}
	return
}

func executeCommand(executable string, args ...string) error {
	installCmd := exec.Command(executable, args...)
	maskedCmdString := coreutils.GetMaskedCommandString(installCmd)
	log.Debug("Running", maskedCmdString)
	output, err := installCmd.CombinedOutput()
	if err != nil {
		sca.LogExecutableVersion(executable)
		return errorutils.CheckErrorf("%q command failed: %s - %s", maskedCmdString, err.Error(), output)
	}
	return nil
}

func getPipInstallArgs(requirementsFile string, remoteUrl string, cacheFolder string, reportFileName string) []string {
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
	return args
}

func runPipenvInstallFromRemoteRegistry(server *config.ServerDetails, depsRepoName string) (err error) {
	rtUrl, err := utils.GetPypiRepoUrl(server, depsRepoName, false)
	if err != nil {
		return err
	}
	args := []string{"install", "-d", utils.GetPypiRemoteRegistryFlag(pythonutils.Pipenv), rtUrl}
	return executeCommand("pipenv", args...)
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
	err = executeCommand(pythonPath, cmdArgs...)
	if err != nil {
		// Failed running 'python -m venv', trying to run 'virtualenv'
		log.Debug("Failed running python venv:", err.Error())
		err = executeCommand("virtualenv", "-p", pythonPath, venvdirName)
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
