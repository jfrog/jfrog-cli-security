package sast_server

import (
	"bytes"
	"errors"
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
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}

	port := 0
	if tcpaddr, ok := listener.Addr().(*net.TCPAddr); ok {
		port = tcpaddr.Port
	}
	if err = listener.Close(); err != nil {
		return 0, err
	}
	if port == 0 {
		return 0, errors.New("failed to get port from listener address")
	}
	return port, nil
}

func TestRunSastServerHappyFlow(t *testing.T) {
	assert.NoError(t, jas.DownloadAnalyzerManagerIfNeeded(0))
	mockServer, serverDetails, _ := validations.XrayServer(t, validations.MockServerParams{XrayVersion: utils.EntitlementsMinVersion})
	defer mockServer.Close()
	scanner, initError := jas.NewJasScanner(serverDetails)
	assert.NoError(t, initError)
	query := "{\"jsonrpc\": \"2.0\",  \"id\": 1, \"method\": \"initialize\", \"params\": {\"protocolVersion\": \"2024-11-05\", \"capabilities\": {}, \"clientInfo\": {\"name\": \"ExampleClient\",  \"version\": \"1.0.0\" }}}"
	inputBuffer := *bytes.NewBufferString(query)
	outputBuffer := *bytes.NewBuffer(make([]byte, 0, 500))
	errorBuffer := *bytes.NewBuffer(make([]byte, 0, 500))
	amEnv, _ := jas.GetAnalyzerManagerEnvVariables(scanner.ServerDetails)

	port, err := getFreePort()
	require.NoError(t, err)
	sastCmd := SastServerCommand{
		ServerDetails: serverDetails,
		Arguments:     []string{"--port", strconv.Itoa(port)},
		InputPipe:     &inputBuffer,
		OutputPipe:    &outputBuffer,
		ErrorPipe:     &errorBuffer,
	}

	err = sastCmd.runWithTimeout(5, amEnv)
	require.NoError(t, err)
	require.Contains(t, errorBuffer.String(), "serving at port")
}
