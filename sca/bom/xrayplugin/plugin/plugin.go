package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/rpc"
	"os"
	"os/exec"
	"path"
	"path/filepath"

	"github.com/CycloneDX/cyclonedx-go"
	goplugin "github.com/hashicorp/go-plugin"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/dependencies"
	"github.com/jfrog/jfrog-cli-security/utils"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	xrayLibPluginVersionEnvVariable = "JFROG_CLI_XRAY_LIB_PLUGIN_VERSION"
	defaultXrayLibPluginVersion     = "0.0.3-14"

	xrayLibPluginRtRepository   = "xray-scan-lib"
	XrayLibPluginExecutableName = "xray-scan-plugin"

	pluginName                  = "scang"
	xrayLibPluginMagicCookieKey = "SCANG_PLUGIN_MAGIC_COOKIE"
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

func CreateScannerPluginClient(scangBinary string) (scanner Scanner, err error) {
	// Create the plugin client with JFrog logger adapter
	// This will align the plugin's logging with JFrog CLI's logging
	var logStdErr io.Writer
	if jfrogLog, ok := log.GetLogger().(log.JfrogLogger); ok {
		logStdErr = jfrogLog.ErrorLog.Writer()
	}
	client := goplugin.NewClient(&goplugin.ClientConfig{
		HandshakeConfig: PluginHandshakeConfig,
		Plugins:         map[string]goplugin.Plugin{pluginName: &Plugin{}},
		Cmd:             &exec.Cmd{Path: scangBinary},
		Managed:         true,
		Stderr:          logStdErr,
		Logger:          NewHclogToJfrogAdapter(),
	})
	defer func() {
		if err != nil {
			client.Kill()
		}
	}()
	rpcClient, err := client.Client()
	if err != nil {
		return nil, err
	}
	// Wait for the plugin to complete the handshake
	raw, err := rpcClient.Dispense(pluginName)
	if err != nil {
		return nil, err
	}
	// Assert that the plugin is of type Scanner
	scanPlugin, ok := raw.(Scanner)
	if !ok {
		return nil, fmt.Errorf("plugin is not of type of Xray-Lib plugin, expected Scanner, got %T", raw)
	}
	return scanPlugin, nil
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
	artDetails, remotePath, err := utils.GetReleasesRemoteDetails("Xray-Scan-Lib Plugin", downloadPath)
	if err != nil {
		return err
	}
	// Check if the xray-lib-plugin should be downloaded by comparing the checksum of the local file with the remote file
	client, httpClientDetails, err := dependencies.CreateHttpClient(artDetails)
	if err != nil {
		return err
	}
	downloadUrl := artDetails.ArtifactoryUrl + remotePath
	remoteFileDetails, _, err := client.GetRemoteFileDetails(downloadUrl, &httpClientDetails)
	if err != nil {
		return fmt.Errorf("couldn't get remote file details for %s: %s", downloadUrl, err.Error())
	}
	xrayLibPluginPath, err := getXrayLibPathAtJfrogDependenciesDir()
	if err != nil {
		return err
	}
	if match, err := isLocalPluginMatchesRemote(xrayLibPluginPath, remoteFileDetails); err != nil || match {
		return err
	}
	log.Info("The 'Xray-Lib Plugin' app is not cached locally. Downloading it now...")
	// Download the xray-lib-plugin file
	return dependencies.DownloadDependency(artDetails, remotePath, xrayLibPluginPath, true)
}

func GetXrayLibPluginDownloadPath() (string, error) {
	osAndArc, err := coreutils.GetOSAndArc()
	if err != nil {
		return "", err
	}
	if coreutils.IsMac() {
		// At the Releases, the plugin name convention is "darwin-<arch>" and not "mac-<arch>".
		osAndArc = "darwin-" + osAndArc[len("mac-"):]
	}
	return path.Join(xrayLibPluginRtRepository, fmt.Sprintf("%s-%s-%s.tar.gz", xrayLibPluginRtRepository, getXrayLibPluginVersion(), osAndArc)), nil
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
	if xrayLibPath, err = getXrayLibPathAtJfrogDependenciesDir(); err != nil {
		return
	}
	exists, err := fileutils.IsFileExists(xrayLibPath, false)
	if err != nil || exists {
		return
	}
	return "", errors.New("Xray-Lib plugin executable not found in JFrog CLI dependencies directory")
}

func getXrayLibPathAtJfrogDependenciesDir() (string, error) {
	jfrogDir, err := config.GetJfrogDependenciesPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(jfrogDir, xrayLibPluginRtRepository, getXrayLibExecutableName()), nil
}

func isLocalPluginMatchesRemote(xrayLibPath string, remoteFileDetails *fileutils.FileDetails) (match bool, err error) {
	// Find current Xray-Lib checksum.
	exist, err := fileutils.IsFileExists(xrayLibPath, false)
	if err != nil || !exist {
		return false, err
	}
	sha256, err := utils.FileSha256(xrayLibPath)
	if err != nil {
		return false, fmt.Errorf("failed to calculate the local Xray-Lib plugin checksum: %w", err)
	}
	// If the checksums are identical, there's no need to download.
	return remoteFileDetails.Checksum.Sha256 == sha256, nil
}
