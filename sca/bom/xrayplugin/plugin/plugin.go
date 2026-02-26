package plugin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/rpc"
	"os"
	"os/exec"
	"path"
	"path/filepath"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/utils"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	xrayLibPluginVersionEnvVariable = "JFROG_CLI_XRAY_LIB_PLUGIN_VERSION"
	defaultXrayLibPluginVersion     = "0.0.3-54"

	SnippetDetectionEnvVariable = "JFROG_XRAY_SNIPPET_SCAN_ENABLE"

	xrayLibPluginRtRepository   = "xray-scan-lib"
	XrayLibPluginExecutableName = "xray-scan-plugin"

	pluginName                  = "scang"
	xrayLibPluginMagicCookieKey = "SCANG_PLUGIN_MAGIC_COOKIE"
	xrayPluginLogsName          = "xrayPluginLogs"
)

// Injected at build so needs to be variable
var xrayLibMagicCookie = "scang-plugin-v1"

// Implementation of plugin
type Plugin struct {
	goplugin.NetRPCUnsupportedPlugin
	Impl Scanner
}

var PluginHandshakeConfig = goplugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   xrayLibPluginMagicCookieKey,
	MagicCookieValue: xrayLibMagicCookie,
}

type Scanner interface {
	Scan(path string, config Config) (*cyclonedx.BOM, error)
}

// Plugin Implementation that talks over rpc
type ScannerRPCScanRequest struct {
	Path       string
	ConfigJSON string
}

type ScannerRPCScanResponse struct {
	BOM   *cyclonedx.BOM
	Error error
}

type ScannerRPCClient struct {
	client *rpc.Client
}

// RPC Server that ScanPluginRPC talks to
type ScannerRPCServer struct {
	Impl Scanner
}

// CreateScannerPluginClient creates a plugin client. When not in CI and log level is DEBUG, plugin stderr is written
// to a log file under JFrog home (logs/xrayPluginLogs/)
func CreateScannerPluginClient(scangBinary string, envVars map[string]string) (scanner Scanner, logPath string, err error) {
	stderrWriter, logPath, err := getPluginLogger()
	if err != nil {
		return nil, "", err
	}
	clientConfig := &goplugin.ClientConfig{
		HandshakeConfig: PluginHandshakeConfig,
		Plugins:         map[string]goplugin.Plugin{pluginName: &Plugin{}},
		Cmd:             &exec.Cmd{Path: scangBinary, Env: utils.ToCommandEnvVars(envVars)},
		Managed:         true,
		Logger: hclog.New(&hclog.LoggerOptions{
			Output: stderrWriter,
			Level:  hclog.Trace,
			Name:   "plugin",
		}),
		Stderr:     stderrWriter,
		SyncStderr: stderrWriter,
	}
	client := goplugin.NewClient(clientConfig)
	defer func() {
		if err != nil {
			client.Kill()
		}
	}()
	rpcClient, err := client.Client()
	if err != nil {
		return nil, "", err
	}
	// Wait for the plugin to complete the handshake
	raw, err := rpcClient.Dispense(pluginName)
	if err != nil {
		return nil, "", err
	}
	// Assert that the plugin is of type Scanner
	scanPlugin, ok := raw.(Scanner)
	if !ok {
		return nil, "", fmt.Errorf("plugin is not of type of Xray-Lib plugin, expected Scanner, got %T", raw)
	}
	return scanPlugin, logPath, nil
}

func getPluginLogger() (writer io.Writer, logPath string, err error) {
	if shouldOutputPluginLogs() {
		writer = utils.NewLineDecoratorWriter(os.Stderr, "{", "}")
		return
	}
	logDir, dirErr := coreutils.CreateDirInJfrogHome(filepath.Join(coreutils.JfrogLogsDirName, xrayPluginLogsName))
	if dirErr != nil {
		err = fmt.Errorf("failed to create plugin log directory: %w", dirErr)
		return
	}
	writer, logPath, err = createPluginStderrLogFile(logDir)
	if err != nil {
		err = fmt.Errorf("failed to create plugin stderr log file: %w", err)
		return
	}
	return
}

func shouldOutputPluginLogs() bool {
	return utils.IsCI() && log.Logger.GetLogLevel() == log.DEBUG
}

func createPluginStderrLogFile(logDir string) (io.Writer, string, error) {
	p := filepath.Join(logDir, fmt.Sprintf("%s-%s.log", xrayPluginLogsName, utils.GetCurrentTimeUnix()))
	f, err := os.Create(p)
	if err != nil {
		return nil, "", err
	}
	return f, p, nil
}

func (g *ScannerRPCClient) Scan(path string, config Config) (*cyclonedx.BOM, error) {
	// Prepare the configuration for the scan
	configJSONBytes, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	args := ScannerRPCScanRequest{
		Path:       path,
		ConfigJSON: string(configJSONBytes),
	}
	// Call the Scan method on the RPC server
	resp := ScannerRPCScanResponse{}
	rpcErr := g.client.Call("Plugin.Scan", args, &resp)
	if rpcErr != nil {
		return nil, rpcErr
	}
	return resp.BOM, resp.Error
}

func (s *ScannerRPCServer) Scan(args ScannerRPCScanRequest, resp *ScannerRPCScanResponse) error {
	var cfg Config
	if err := json.Unmarshal([]byte(args.ConfigJSON), &cfg); err != nil {
		*resp = ScannerRPCScanResponse{BOM: nil, Error: err}
		return err
	}
	// Call the Scan method on the plugin implementation with the provided path and configuration from the request
	bom, scanErr := s.Impl.Scan(args.Path, cfg)
	*resp = ScannerRPCScanResponse{BOM: bom, Error: scanErr}
	return nil
}

func (p *Plugin) Server(broker *goplugin.MuxBroker) (any, error) {
	return &ScannerRPCServer{Impl: p.Impl}, nil
}

func (p *Plugin) Client(broker *goplugin.MuxBroker, client *rpc.Client) (any, error) {
	return &ScannerRPCClient{client: client}, nil
}

func DownloadXrayLibPluginIfNeeded() error {
	downloadPath, err := GetXrayLibPluginDownloadPath()
	if err != nil {
		return err
	}
	xrayLibPluginDirPath, err := getXrayLibDirPathAtJfrogDependenciesDir()
	if err != nil {
		return err
	}
	return utils.DownloadResourceFromPlatformIfNeeded("Xray-Lib Plugin", downloadPath, xrayLibPluginDirPath, path.Base(downloadPath), true, 0)
}

func getXrayLibPluginFullName() (string, error) {
	osAndArc, err := coreutils.GetOSAndArc()
	if err != nil {
		return "", err
	}
	if coreutils.IsMac() {
		// At the Releases, the plugin name convention is "darwin-<arch>" and not "mac-<arch>".
		osAndArc = "darwin-" + osAndArc[len("mac-"):]
	}
	return fmt.Sprintf("%s-%s-%s", xrayLibPluginRtRepository, getXrayLibPluginVersion(), osAndArc), nil
}

func GetXrayLibPluginDownloadPath() (string, error) {
	fullName, err := getXrayLibPluginFullName()
	if err != nil {
		return "", err
	}
	return path.Join(xrayLibPluginRtRepository, fmt.Sprintf("%s.tar.gz", fullName)), nil
}

func getXrayLibPluginVersion() string {
	if versionEnv := os.Getenv(xrayLibPluginVersionEnvVariable); versionEnv != "" {
		return versionEnv
	}
	return defaultXrayLibPluginVersion
}

func getXrayLibExecutableName() string {
	if coreutils.IsWindows() {
		return XrayLibPluginExecutableName + ".exe"
	}
	return XrayLibPluginExecutableName
}

func GetLocalXrayLibExecutablePath() (xrayLibPath string, err error) {
	// Check if the xray-lib-plugin binary path is set in the PATH environment variable
	if xrayLibPath, err = exec.LookPath(XrayLibPluginExecutableName); err != nil || xrayLibPath == "" {
		log.Debug(fmt.Sprintf("Xray-Lib plugin not found in system PATH: %s", err.Error()))
	} else if xrayLibPath != "" {
		// If found in PATH, return the path
		log.Debug(fmt.Sprintf("Xray-Lib plugin found in system PATH: %s", xrayLibPath))
		return xrayLibPath, nil
	}
	// Check if exists in JFrog CLI directory
	xrayLibDir, err := getXrayLibDirPathAtJfrogDependenciesDir()
	if err != nil {
		return
	}
	libFullName, err := getXrayLibPluginFullName()
	if err != nil {
		return "", err
	}
	xrayLibPath = filepath.Join(xrayLibDir, libFullName, getXrayLibExecutableName())
	exists, err := fileutils.IsFileExists(xrayLibPath, false)
	if err != nil || exists {
		return
	}
	return "", fmt.Errorf("Xray-Lib plugin not found at %s", xrayLibPath)
}

func getXrayLibDirPathAtJfrogDependenciesDir() (string, error) {
	jfrogDir, err := config.GetJfrogDependenciesPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(jfrogDir, XrayLibPluginExecutableName), nil
}
