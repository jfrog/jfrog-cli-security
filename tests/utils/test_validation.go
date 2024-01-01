package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"

	clientUtils "github.com/jfrog/jfrog-client-go/utils"
)

func ValidateXrayVersion(t *testing.T, minVersion string) {
	xrayVersion, err := getXrayVersion()
	if err != nil {
		assert.NoError(t, err)
		return
	}
	err = clientUtils.ValidateMinimumVersion(clientUtils.Xray, xrayVersion.GetVersion(), minVersion)
	if err != nil {
		t.Skip(err)
	}
}
