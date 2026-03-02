package source_mcp

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/tests/validations"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/stretchr/testify/assert"
)

func TestRunSourceMcpHappyFlow(t *testing.T) {
	assert.NoError(t, jas.DownloadAnalyzerManagerIfNeeded(0))
	mockServer, serverDetails, _ := validations.XrayServer(t, validations.MockServerParams{XrayVersion: utils.EntitlementsMinVersion})
	defer mockServer.Close()
	scanner, initError := jas.NewJasScanner(serverDetails)
	assert.NoError(t, initError)
	scanned_path := filepath.Join("..", "..", "tests", "testdata", "projects", "jas", "jas")
	query := "{\"jsonrpc\": \"2.0\",  \"id\": 1, \"method\": \"initialize\", \"params\": {\"protocolVersion\": \"2024-11-05\", \"capabilities\": {}, \"clientInfo\": {\"name\": \"ExampleClient\",  \"version\": \"1.0.0\" }}}"
	inputBuffer := *bytes.NewBufferString(query)
	outputBuffer := *bytes.NewBuffer(make([]byte, 0, 500))
	errorBuffer := *bytes.NewBuffer(make([]byte, 0, 500))
	amEnv, _ := jas.GetAnalyzerManagerEnvVariables(scanner.ServerDetails)

	mcp_cmd := McpCommand{
		ServerDetails: serverDetails,
		Arguments:     []string{scanned_path},
		InputPipe:     &inputBuffer,
		OutputPipe:    &outputBuffer,
		ErrorPipe:     &errorBuffer,
	}

	err := mcp_cmd.runWithTimeout(5, "mcp-sast", amEnv)
	assert.NoError(t, err) // returns error because it was terminated upon timeout
	if !assert.Contains(t, errorBuffer.String(), "Generated IR") {
		t.Error(errorBuffer.String())
	}

	if !assert.Contains(t, outputBuffer.String(), "\"serverInfo\":{\"name\":\"jfrog_sast\"") {
		t.Error(outputBuffer.String())
	}
}

func TestRunSourceMcpScannerError(t *testing.T) {
	assert.NoError(t, jas.DownloadAnalyzerManagerIfNeeded(0))
	mockServer, serverDetails, _ := validations.XrayServer(t, validations.MockServerParams{XrayVersion: utils.EntitlementsMinVersion})
	defer mockServer.Close()
	scanner, initError := jas.NewJasScanner(serverDetails)
	assert.NoError(t, initError)

	// no such path
	scanned_path := ""
	inputBuffer := *bytes.NewBufferString("")
	outputBuffer := *bytes.NewBuffer(make([]byte, 0, 500))
	errorBuffer := *bytes.NewBuffer(make([]byte, 0, 500))
	amEnv, _ := jas.GetAnalyzerManagerEnvVariables(scanner.ServerDetails)
	mcpCmd := McpCommand{
		ServerDetails: serverDetails,
		Arguments:     []string{scanned_path},
		InputPipe:     &inputBuffer,
		OutputPipe:    &outputBuffer,
		ErrorPipe:     &errorBuffer,
	}
	err := mcpCmd.runWithTimeout(0, "mcp-sast1", amEnv) // no such command
	assert.ErrorContains(t, err, "exit status 99")
}
