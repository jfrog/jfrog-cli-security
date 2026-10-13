package jas

import (
	"encoding/hex"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/xray"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
)

const analyzerManagerKeysVulnerabilityId = "XRAY-1103252"

// The keys are published as the applicability explanation of a dedicated vulnerability, which Xray serves only to JAS entitled platforms.
// The explanation holds one hex key per line; the first one encrypts the current Analyzer Manager bundles.
func getAnalyzerManagerKey(serverDetails *config.ServerDetails, projectKey string) ([]byte, error) {
	if serverDetails == nil {
		return nil, errorutils.CheckErrorf("the Analyzer Manager key can only be fetched from a configured JFrog Platform")
	}
	xrayManager, err := xray.CreateXrayServiceManager(serverDetails, xray.WithScopedProjectKey(projectKey))
	if err != nil {
		return nil, err
	}
	applicabilityInput, err := xrayManager.GetApplicabilityInput([]string{analyzerManagerKeysVulnerabilityId})
	if err != nil {
		return nil, err
	}
	keys := strings.Fields(applicabilityInput.Explanation[analyzerManagerKeysVulnerabilityId])
	if len(keys) == 0 {
		return nil, errorutils.CheckErrorf("the Analyzer Manager key was not found in Xray")
	}
	key, err := hex.DecodeString(keys[0])
	return key, errorutils.CheckError(err)
}
