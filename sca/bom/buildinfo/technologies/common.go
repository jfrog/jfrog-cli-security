package technologies

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	buildInfoUtils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-client-go/artifactory/services/fspatterns"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	ioUtils "github.com/jfrog/jfrog-client-go/utils/io"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
)

const (
	// Visual Studio inner directory.
	DotVsRepoSuffix = ".vs"
)

var CurationErrorMsgToUserTemplate = "Failed to retrieve the dependencies tree for the %s project. Please contact your " +
	"Artifactory administrator to verify pass-through for Curation audit is enabled for your project"

type BuildInfoBomGeneratorParams struct {
	XrayVersion         string
	Progress            ioUtils.ProgressMgr
	ExclusionPattern    string
	AllowPartialResults bool
	// Artifactory Repository params
	ServerDetails          *config.ServerDetails
	DependenciesRepository string
	IgnoreConfigFile       bool
	InsecureTls            bool
	// Install params
	SkipAutoInstall    bool
	InstallCommandName string
	Args               []string
	InstallCommandArgs []string
	// Curation params
	IsCurationCmd bool
	// Java params
	IsMavenDepTreeInstalled bool
	UseWrapper              bool
	UseIncludedBuilds       bool
	// Python params
	PipRequirementsFile string
	// Npm params
	NpmIgnoreNodeModules    bool
	NpmOverwritePackageLock bool
	// Pnpm params
	MaxTreeDepth string
	// Docker params
	DockerImageName string
	// NuGet params
	SolutionFilePath string
}

func (bbp *BuildInfoBomGeneratorParams) SetNpmScope(depType string) *BuildInfoBomGeneratorParams {
	switch depType {
	case "devOnly":
		bbp.Args = []string{"--dev"}
	case "prodOnly":
		bbp.Args = []string{"--prod"}
	}
	return bbp
}

func (bbp *BuildInfoBomGeneratorParams) SetConanProfile(file string) *BuildInfoBomGeneratorParams {
	bbp.Args = append(bbp.Args, "--profile:build", file)
	return bbp
}

func GetExcludePattern(configProfile *xscservices.ConfigProfile, isRecursive bool, exclusions ...string) string {
	if configProfile != nil {
		exclusions = append(exclusions, configProfile.Modules[0].ScanConfig.ScaScannerConfig.ExcludePatterns...)
	}

	if len(exclusions) == 0 {
		exclusions = append(exclusions, utils.DefaultScaExcludePatterns...)
	}
	return fspatterns.PrepareExcludePathPattern(exclusions, clientutils.WildCardPattern, isRecursive)
}

func RunXrayDependenciesTreeScanGraph(scanGraphParams *scangraph.ScanGraphParams) (results []services.ScanResponse, err error) {
	var scanResults *services.ScanResponse
	technology := scanGraphParams.Technology()
	xrayManager, err := xray.CreateXrayServiceManager(scanGraphParams.ServerDetails(), xray.WithScopedProjectKey(scanGraphParams.XrayGraphScanParams().ProjectKey))
	if err != nil {
		return nil, err
	}
	scanResults, err = scangraph.RunScanGraphAndGetResults(scanGraphParams, xrayManager)
	if err != nil {
		err = errorutils.CheckErrorf("scanning %s dependencies failed with error: %s", technology.ToFormal(), err.Error())
		return
	}
	for i := range scanResults.Vulnerabilities {
		if scanResults.Vulnerabilities[i].Technology == "" {
			scanResults.Vulnerabilities[i].Technology = technology.String()
		}
	}
	for i := range scanResults.Violations {
		if scanResults.Violations[i].Technology == "" {
			scanResults.Violations[i].Technology = technology.String()
		}
	}
	results = append(results, *scanResults)
	return
}

func CreateTestWorkspace(t *testing.T, sourceDir string) (string, func()) {
	return tests.CreateTestWorkspace(t, filepath.Join("..", "..", "..", "..", "..", "tests", "testdata", sourceDir))
}

// GetExecutableVersion gets an executable version and prints to the debug log if possible.
// Only supported for package managers that use "--version".
func LogExecutableVersion(executable string) {
	verBytes, err := exec.Command(executable, "--version").CombinedOutput()
	if err != nil {
		log.Debug(fmt.Sprintf("'%q --version' command received an error: %s", executable, err.Error()))
		return
	}
	if len(verBytes) == 0 {
		log.Debug(fmt.Sprintf("'%q --version' command received an empty response", executable))
		return
	}
	version := strings.TrimSpace(string(verBytes))
	log.Debug(fmt.Sprintf("Used %q version: %s", executable, version))
}

func GetMsgToUserForCurationBlock(isCurationCmd bool, tech techutils.Technology, cmdOutput string) (msgToUser string) {
	if isCurationCmd && buildInfoUtils.IsForbiddenOutput(buildInfoUtils.PackageManager(tech.String()), cmdOutput) {
		msgToUser = fmt.Sprintf(CurationErrorMsgToUserTemplate, tech)
	}
	return
}
