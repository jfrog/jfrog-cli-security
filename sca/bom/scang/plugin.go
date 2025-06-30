package scang

import (
	"encoding/json"
	"errors"
	"fmt"
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
	defaultScangPluginVersion     = "1.0.0"
	scangPluginVersionEnvVariable = "JFROG_CLI_SCANG_PLUGIN_VERSION"
	scangPluginRtRepository       = "scang/v1"

	scangPluginDirName        = "scang"
	scangPluginExecutableName = "scangplugin"
	pluginName                = "scang"

	scangPluginMagicCookieKey = "SCANG_PLUGIN_MAGIC_COOKIE"
)

// Injected at build so needs to be variable
var ScangMagicCookie = "scang-plugin-v1"

// Implementation of plugin
type Plugin struct {
	goplugin.NetRPCUnsupportedPlugin
	Impl Scanner
}

var PluginHandshakeConfig = goplugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   scangPluginMagicCookieKey,
	MagicCookieValue: ScangMagicCookie,
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
	// Create the plugin client
	client := goplugin.NewClient(&goplugin.ClientConfig{
		HandshakeConfig: PluginHandshakeConfig,
		Plugins:         map[string]goplugin.Plugin{pluginName: &Plugin{}},
		Cmd:             &exec.Cmd{Path: scangBinary},
		Managed:         true,
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
		return nil, fmt.Errorf("plugin is not of type of SCANG plugin, expected Scanner, got %T", raw)
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

func DownloadScangPluginIfNeeded() error {
	downloadPath, err := GetScangPluginDownloadPath()
	if err != nil {
		return err
	}
	artDetails, remotePath, err := utils.GetReleasesRemoteDetails("SCANG plugin", downloadPath)
	if err != nil {
		return err
	}
	// Check if the scang should be downloaded by comparing the checksum of the local file with the remote file
	client, httpClientDetails, err := dependencies.CreateHttpClient(artDetails)
	if err != nil {
		return err
	}
	downloadUrl := artDetails.ArtifactoryUrl + remotePath
	remoteFileDetails, _, err := client.GetRemoteFileDetails(downloadUrl, &httpClientDetails)
	if err != nil {
		return fmt.Errorf("couldn't get remote file details for %s: %s", downloadUrl, err.Error())
	}
	scangPluginPath, err := getScangPathAtJfrogDependenciesDir()
	if err != nil {
		return err
	}
	if match, err := isLocalPluginMatchesRemote(scangPluginPath, remoteFileDetails); err != nil || match {
		return err
	}
	log.Info("The 'SCANG Plugin' app is not cached locally. Downloading it now...")
	// Download the scang plugin file
	return dependencies.DownloadDependency(artDetails, remotePath, scangPluginPath, false)
}

func GetScangPluginDownloadPath() (string, error) {
	osAndArc, err := coreutils.GetOSAndArc()
	if err != nil {
		return "", err
	}
	return path.Join(scangPluginRtRepository, getScangPluginVersion(), osAndArc, getScangExecutableName()), nil
}

func getScangPluginVersion() string {
	if versionEnv := os.Getenv(scangPluginVersionEnvVariable); versionEnv != "" {
		return versionEnv
	}
	return defaultScangPluginVersion
}

func getScangExecutableName() string {
	if coreutils.IsWindows() {
		return scangPluginExecutableName + ".exe"
	}
	return scangPluginExecutableName
}

func getLocalScangExecutablePath() (scangPath string, err error) {
	// Check if the scang plugin binary path is set in the PATH environment variable
	if scangPath, err = exec.LookPath(scangPluginExecutableName); err != nil || scangPath == "" {
		log.Debug(fmt.Sprintf("SCANG plugin not found in system PATH: %s", err.Error()))
	}
	// Check if exists in JFrog CLI directory
	if scangPath, err = getScangPathAtJfrogDependenciesDir(); err != nil {
		return
	}
	exists, err := fileutils.IsFileExists(scangPath, false)
	if err != nil || exists {
		return
	}
	return "", errors.New("SCANG plugin executable not found in JFrog CLI dependencies directory")
}

func getScangPathAtJfrogDependenciesDir() (string, error) {
	jfrogDir, err := config.GetJfrogDependenciesPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(jfrogDir, scangPluginDirName, getScangExecutableName()), nil
}

func isLocalPluginMatchesRemote(scangPluginPath string, remoteFileDetails *fileutils.FileDetails) (match bool, err error) {
	// Find current SCANG checksum.
	exist, err := fileutils.IsFileExists(scangPluginPath, false)
	if err != nil || !exist {
		return false, err
	}
	sha256, err := utils.FileSha256(scangPluginPath)
	if err != nil {
		return false, fmt.Errorf("failed to calculate the local SCANG plugin checksum: %w", err)
	}
	// If the checksums are identical, there's no need to download.
	return remoteFileDetails.Checksum.Sha256 == sha256, nil
}
