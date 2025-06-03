package technologies

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	buildInfoUtils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
	"github.com/jfrog/jfrog-client-go/artifactory/services/fspatterns"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
)

const (
	// Visual Studio inner directory.
	DotVsRepoSuffix = ".vs"
)

var CurationErrorMsgToUserTemplate = "Failed to retrieve the dependencies tree for the %s project. Please contact your " +
	"Artifactory administrator to verify pass-through for Curation audit is enabled for your project"

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

// Infer the status code of SCA Xray scan, must have at least one result, if err occurred or any of the results is `failed` return 1, otherwise return 0.
func GetScaScansStatusCode(err error, results ...services.ScanResponse) int {
	if err != nil || len(results) == 0 {
		return 1
	}
	for _, result := range results {
		if result.ScannedStatus == "Failed" {
			return 1
		}
	}
	return 0
}

func CreateTestWorkspace(t *testing.T, sourceDir string) (string, func()) {
	return tests.CreateTestWorkspace(t, filepath.Join("..", "..", "..", "..", "tests", "testdata", sourceDir))
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
