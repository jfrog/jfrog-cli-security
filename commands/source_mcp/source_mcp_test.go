package source_mcp

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/stretchr/testify/assert"
)

func TestRunSourceMcpHappyFlow(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	scanned_path := filepath.Join("..", "..", "tests", "testdata", "projects", "jas", "jas")
	query := "{\"jsonrpc\": \"2.0\",  \"id\": 1, \"method\": \"initialize\", \"params\": {\"protocolVersion\": \"2024-11-05\", \"capabilities\": {}, \"clientInfo\": {\"name\": \"ExampleClient\",  \"version\": \"1.0.0\" }}}"
	input_buffer := *bytes.NewBufferString(query)
	output_buffer := *bytes.NewBuffer(make([]byte, 0, 500))
	error_buffer := *bytes.NewBuffer(make([]byte, 0, 500))
	am_env, _ := jas.GetAnalyzerManagerEnvVariables(scanner.ServerDetails)

	mcp_cmd := McpCommand{
		Env:        am_env,
		Arguments:  []string{scanned_path},
		InputPipe:  &input_buffer,
		OutputPipe: &output_buffer,
		ErrorPipe:  &error_buffer,
	}

	err := mcp_cmd.runWithTimeout(5)

	assert.NoError(t, err)
	if !assert.Contains(t, error_buffer.String(), "Generated IR") {
		t.Error(error_buffer.String())
	}

	if !assert.Contains(t, output_buffer.String(), "\"serverInfo\":{\"name\":\"jfrog_sast\"") {
		t.Error(output_buffer.String())
	}
}

func TestRunSourceMcpScannerError(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	// no such path
	scanned_path := filepath.Join("..", "..", "tests", "testdata", "projects", "jas2", "jas")
	input_buffer := *bytes.NewBufferString("")
	output_buffer := *bytes.NewBuffer(make([]byte, 0, 500))
	error_buffer := *bytes.NewBuffer(make([]byte, 0, 500))
	am_env, _ := jas.GetAnalyzerManagerEnvVariables(scanner.ServerDetails)
	mcp_cmd := McpCommand{
		Env:        am_env,
		Arguments:  []string{scanned_path},
		InputPipe:  &input_buffer,
		OutputPipe: &output_buffer,
		ErrorPipe:  &error_buffer,
	}
	err := mcp_cmd.Run()

	assert.Error(t, err)

}
