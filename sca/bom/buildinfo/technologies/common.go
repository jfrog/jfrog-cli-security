package technologies

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	buildInfoUtils "github.com/jfrog/build-info-go/utils"
	outFormat "github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-client-go/artifactory/services/fspatterns"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	ioUtils "github.com/jfrog/jfrog-client-go/utils/io"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"

	xrayUtils "github.com/jfrog/jfrog-cli-core/v2/utils/xray"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
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
	// AuditId is the curation run's audit ID, forwarded to probes that make their own HTTP requests (e.g. npm/yarn direct-dep probing) so they tag those requests the same way as the main audit flow.
	AuditId              string
	MvnIncludePluginDeps bool
	ParallelRequests     int
	// OutputFormat is the --format flag value forwarded from the curation command.
	// The zero value is treated as outFormat.Table by all renderers.
	// Set by curation commands only; generic audit/scan commands leave this unset.
	OutputFormat outFormat.OutputFormat
	// Java params
	IsMavenDepTreeInstalled       bool
	UseWrapper                    bool
	UseIncludedBuilds             bool
	GradleExcludeTestDependencies bool
	// Python params
	PipRequirementsFile string
	// Npm params
	NpmIgnoreNodeModules    bool
	NpmOverwritePackageLock bool
	NpmRunNative            bool
	NpmLegacyPeerDeps       bool
	// NpmForceLogsMax, when non-empty, is appended as --logs-max <value> to the install command.
	// Leave empty unless ambient logs-max is known to be 0 — never override a nonzero setting.
	NpmForceLogsMax string
	// Yarn params
	// YarnOverwriteYarnLock refreshes yarn.lock when older than package.json (mirrors NpmOverwritePackageLock).
	// Curation sets this to true; audit/scan leave it false to trust the existing lockfile.
	YarnOverwriteYarnLock bool
	// YarnCredentialsFromFallback is true when .yarnrc.yml had no token of its own and
	// ServerDetails' credentials came from the 'jf c' server config instead. When false, the
	// same token is already in use by .yarnrc.yml's native resolution, so injecting it into
	// the subprocess env would just add a redundant network call.
	YarnCredentialsFromFallback bool
	// Pnpm params
	MaxTreeDepth string
	// Docker params
	DockerImageName string
	// Hugging Face params
	// HuggingFaceModel is the model/dataset reference to audit, e.g. "mcpotato/42-eicar-street:main".
	// Set by the curation command's --hugging-face-model flag.
	// When empty, BuildDependencyTree auto-discovers references from HFWorkingDirectory.
	HuggingFaceModel string
	// HFWorkingDirectory is the project root used for Hugging Face auto-discovery.
	// Defaults to "." when empty.
	HFWorkingDirectory string
	// HFProjectName overrides the HF root-node name (falls back to the working
	// directory basename when empty). Set by the curation command to a collision-free
	// name when auditing multiple --working-dirs entries that share a basename.
	HFProjectName string
	// NuGet params
	SolutionFilePath string
	// Uv params
	ScriptPath string
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

func GetScaExcludePattern(configProfile *xscservices.ConfigProfile, isRecursive bool, exclusions ...string) string {
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
	xrayManager, err := xrayUtils.CreateXrayServiceManager(scanGraphParams.ServerDetails(), xrayUtils.WithScopedProjectKey(scanGraphParams.XrayGraphScanParams().ProjectKey))
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

// windowsBatchForwarderSource: tiny helper EnsureWindowsExeShim compiles and places next to
// each fake poetry/uv/pipenv ".bat", forwarding to it by explicit path via cmd.exe.
const windowsBatchForwarderSource = `package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "winbatforward: cannot resolve own path:", err)
		os.Exit(1)
	}
	script := strings.TrimSuffix(self, filepath.Ext(self)) + ".bat"
	cmd := exec.Command("cmd.exe", append([]string{"/c", script}, os.Args[1:]...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	runErr := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		os.Exit(exitErr.ExitCode())
	}
	if runErr != nil {
		fmt.Fprintln(os.Stderr, "winbatforward:", runErr)
		os.Exit(1)
	}
}
`

var (
	windowsBatchForwarderMu   sync.Mutex
	windowsBatchForwarderPath string
)

// EnsureWindowsExeShim drops a real bareName+".exe" next to a fake bareName+".bat" in
// dir, so Windows launches it reliably. No-op on other platforms.
func EnsureWindowsExeShim(t *testing.T, dir, bareName string) {
	t.Helper()
	if runtime.GOOS != "windows" {
		return
	}
	forwarder, err := buildWindowsBatchForwarder()
	if err != nil {
		t.Fatalf("building windows batch forwarder shim: %s", err)
	}
	data, err := os.ReadFile(forwarder)
	if err != nil {
		t.Fatalf("reading windows batch forwarder shim: %s", err)
	}
	if err = os.WriteFile(filepath.Join(dir, bareName+".exe"), data, 0755); err != nil { // #nosec G703 -- dir is a test-controlled t.TempDir(), bareName a hardcoded literal from the caller
		t.Fatalf("writing windows batch forwarder shim: %s", err)
	}
}

// buildWindowsBatchForwarder compiles the forwarder once per process (pid-scoped path)
// and caches it only on success, so a transient build failure is retried, not permanent.
func buildWindowsBatchForwarder() (string, error) {
	windowsBatchForwarderMu.Lock()
	defer windowsBatchForwarderMu.Unlock()
	if windowsBatchForwarderPath != "" {
		return windowsBatchForwarderPath, nil
	}
	srcFile, err := os.CreateTemp("", "winbatforward-*.go")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(srcFile.Name()) }()
	if _, err = srcFile.WriteString(windowsBatchForwarderSource); err != nil {
		_ = srcFile.Close()
		return "", err
	}
	if err = srcFile.Close(); err != nil {
		return "", err
	}
	outPath := filepath.Join(os.TempDir(), fmt.Sprintf("jfrog-cli-sec-winbatforward-%d.exe", os.Getpid()))
	cmd := exec.Command("go", "build", "-o", outPath, srcFile.Name())
	if out, buildErr := cmd.CombinedOutput(); buildErr != nil {
		return "", fmt.Errorf("go build failed: %w: %s", buildErr, out)
	}
	windowsBatchForwarderPath = outPath
	return windowsBatchForwarderPath, nil
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
