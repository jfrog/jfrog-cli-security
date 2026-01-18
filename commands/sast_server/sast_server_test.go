package sast_server

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/commands/source_mcp"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/tests/validations"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/stretchr/testify/assert"
)

func TestRunSastServerHappyFlow(t *testing.T) {
	assert.NoError(t, jas.DownloadAnalyzerManagerIfNeeded(0))
	mockServer, serverDetails, _ := validations.XrayServer(t, validations.MockServerParams{XrayVersion: utils.EntitlementsMinVersion})
	defer mockServer.Close()
	scanner, init_error := jas.NewJasScanner(serverDetails)
	assert.NoError(t, init_error)
	scanned_path := filepath.Join("..", "..", "tests", "testdata", "projects", "jas", "jas")
	query := "{\"jsonrpc\": \"2.0\",  \"id\": 1, \"method\": \"initialize\", \"params\": {\"protocolVersion\": \"2024-11-05\", \"capabilities\": {}, \"clientInfo\": {\"name\": \"ExampleClient\",  \"version\": \"1.0.0\" }}}"
	input_buffer := *bytes.NewBufferString(query)
	output_buffer := *bytes.NewBuffer(make([]byte, 0, 500))
	error_buffer := *bytes.NewBuffer(make([]byte, 0, 500))
	am_env, _ := jas.GetAnalyzerManagerEnvVariables(scanner.ServerDetails)

	sast_cmd := SastServerCommand{
		ServerDetails: serverDetails,
		Arguments:     []string{scanned_path},
		InputPipe:     &input_buffer,
		OutputPipe:    &output_buffer,
		ErrorPipe:     &error_buffer,
	}

	err := sast_cmd.runWithTimeout(5, "sast-server", am_env)
	assert.NoError(t, err) // returns error because it was terminated upon timeout
	if !assert.Contains(t, error_buffer.String(), "Generated IR") {
		t.Error(error_buffer.String())
	}

	if !assert.Contains(t, output_buffer.String(), "\"serverInfo\":{\"name\":\"jfrog_sast\"") {
		t.Error(output_buffer.String())
	}
}

func TestRunSastServerScannerError(t *testing.T) {
	assert.NoError(t, jas.DownloadAnalyzerManagerIfNeeded(0))
	mockServer, serverDetails, _ := validations.XrayServer(t, validations.MockServerParams{XrayVersion: utils.EntitlementsMinVersion})
	defer mockServer.Close()
	scanner, init_error := jas.NewJasScanner(serverDetails)
	assert.NoError(t, init_error)

	// no such path
	scanned_path := ""
	input_buffer := *bytes.NewBufferString("")
	output_buffer := *bytes.NewBuffer(make([]byte, 0, 500))
	error_buffer := *bytes.NewBuffer(make([]byte, 0, 500))
	am_env, _ := jas.GetAnalyzerManagerEnvVariables(scanner.ServerDetails)
	sast_cmd := SastServerCommand{
		ServerDetails: serverDetails,
		Arguments:     []string{scanned_path},
		InputPipe:     &input_buffer,
		OutputPipe:    &output_buffer,
		ErrorPipe:     &error_buffer,
	}
	err := source_mcp.RunAmWithPipesAndTimeout(am_env, "sast-server-nonexistent", sast_cmd.InputPipe, sast_cmd.OutputPipe, sast_cmd.ErrorPipe, 0, sast_cmd.Arguments...) // no such command
	assert.ErrorContains(t, err, "exit status 99")
}
