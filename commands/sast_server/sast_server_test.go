package sast_server

import (
	"bytes"
	"net"
	"strconv"
	"testing"

	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/tests/validations"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getFreePort() (int, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func TestRunSastServerHappyFlow(t *testing.T) {
	assert.NoError(t, jas.DownloadAnalyzerManagerIfNeeded(0))
	mockServer, serverDetails, _ := validations.XrayServer(t, validations.MockServerParams{XrayVersion: utils.EntitlementsMinVersion})
	defer mockServer.Close()
	scanner, init_error := jas.NewJasScanner(serverDetails)
	assert.NoError(t, init_error)
	query := "{\"jsonrpc\": \"2.0\",  \"id\": 1, \"method\": \"initialize\", \"params\": {\"protocolVersion\": \"2024-11-05\", \"capabilities\": {}, \"clientInfo\": {\"name\": \"ExampleClient\",  \"version\": \"1.0.0\" }}}"
	input_buffer := *bytes.NewBufferString(query)
	output_buffer := *bytes.NewBuffer(make([]byte, 0, 500))
	error_buffer := *bytes.NewBuffer(make([]byte, 0, 500))
	am_env, _ := jas.GetAnalyzerManagerEnvVariables(scanner.ServerDetails)

	port, err := getFreePort()
	require.NoError(t, err)
	sast_cmd := SastServerCommand{
		ServerDetails: serverDetails,
		Arguments:     []string{"--port", strconv.Itoa(port)},
		InputPipe:     &input_buffer,
		OutputPipe:    &output_buffer,
		ErrorPipe:     &error_buffer,
	}

	err = sast_cmd.runWithTimeout(5, "sast-server", am_env)
	require.NoError(t, err)
	require.Contains(t, error_buffer.String(), "serving at port")
	require.Contains(t, output_buffer.String(), "")
}
