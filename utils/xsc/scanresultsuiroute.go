package xsc

import (
	"fmt"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"

	xrayutils "github.com/jfrog/jfrog-cli-security/utils/xray"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xscServices "github.com/jfrog/jfrog-client-go/xsc/services"
)

type ScanResultsUiRouteParams struct {
	XrayVersion            string
	ServerDetails          *config.ServerDetails
	ProjectKey             string
	GitContext             *xscServices.XscGitInfoContext
	ScanResultArtifactPath string
}

func GetScanResultsUiRoute(params *ScanResultsUiRouteParams) (string, error) {
	if err := clientutils.ValidateMinimumVersion(clientutils.Xray, params.XrayVersion, xscServices.GetUIRouteAPIMinXrayVersion); err != nil {
		log.Debug(fmt.Sprintf("Minimal Xray version required to use a configProfile is by name '%s'. All configurations will be induced from provided Env vars and files", xscServices.GetUIRouteAPIMinXrayVersion))
		return "", nil
	}
	if params.GitContext == nil || params.ServerDetails == nil {
		log.Verbose("No git context or server details provided, skipping getting scan results UI route")
		return "", nil
	}

	xscService, err := CreateXscService(params.ServerDetails, xrayutils.WithScopedProjectKey(params.ProjectKey))
	if err != nil {
		return "", fmt.Errorf("failed to create XSC service: %w", err)
	}

	resp, err := xscService.GetScanResultsUIRoute(params.GitContext)
	if err != nil {
		return "", fmt.Errorf("failed to get scan results UI route: %w", err)
	}

	if params.ScanResultArtifactPath != "" && resp.Path != params.ScanResultArtifactPath {
		return "", fmt.Errorf("scan result artifact path '%s' does not match the expected path '%s'", params.ScanResultArtifactPath, resp.Path)
	}

	return resp.Url, nil
}
