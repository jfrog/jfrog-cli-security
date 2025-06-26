package scang

import (
	"encoding/json"
	"fmt"
	"net/rpc"
	"os/exec"

	"github.com/CycloneDX/cyclonedx-go"
	goplugin "github.com/hashicorp/go-plugin"
)

const pluginName = "scang"

var ScagnMagicCookie = "scang-plugin-v1"

// Implementation of plugin
type Plugin struct {
	goplugin.NetRPCUnsupportedPlugin
	Impl Scanner
}

var PluginHandshakeConfig = goplugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "SCANG_PLUGIN_MAGIC_COOKIE",
	MagicCookieValue: ScagnMagicCookie,
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
		return nil, fmt.Errorf("plugin is not of type of scang plugin, expected Scanner, got %T", raw)
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
