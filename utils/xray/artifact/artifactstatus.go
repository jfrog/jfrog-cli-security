package artifact

// import (
// 	"fmt"

// 	"github.com/jfrog/jfrog-cli-security/utils"
// 	"github.com/jfrog/jfrog-client-go/utils/io/httputils"
// 	"github.com/jfrog/jfrog-client-go/xray"
// 	"github.com/jfrog/jfrog-client-go/xray/services"
// )

// const (
// 	XrayScanStepSca                = "SCA Scan"
// 	XrayScanStepContextualAnalysis = "Contextual Analysis Enrichment"
// 	XrayScanStepIaC                = "IaC Scan"
// 	XrayScanStepSecrets            = "Secret Detection Scan"
// 	XrayScanStepServices           = "Services Scan"
// 	XrayScanStepApplication        = "Application Scan"
// 	XrayScanStepViolations         = "Violations Reporting"
// )

// type XrayScanStep string

// const (
// 	ArtifactStatusFetchingInterval = 5   // seconds
// 	ArtifactStatusFetchTimeout     = 600 // seconds
// )

// func GetArtifactScanStatus(xrayManager *xray.XrayServicesManager, repo, path string) (*services.ArtifactStatusResponse, error) {
// 	return xrayManager.GetArtifactStatus(repo, path)
// }

// type ScanCompleteParams struct {
// 	Overall bool
// 	Steps   []XrayScanStep
// }

// type ScanCompleteOption func(params *ScanCompleteParams)

// func WithOverallScanCompletion(overall bool) ScanCompleteOption {
// 	return func(params *ScanCompleteParams) {
// 		params.Overall = overall
// 	}
// }

// func WithStepsScanCompletion(steps ...XrayScanStep) ScanCompleteOption {
// 	return func(params *ScanCompleteParams) {
// 		params.Steps = steps
// 	}
// }

// func NewScanCompleteParams(options ...ScanCompleteOption) *ScanCompleteParams {
// 	params := &ScanCompleteParams{}
// 	for _, option := range options {
// 		option(params)
// 	}
// 	return params
// }
// func WaitForArtifactScanCompletion(xrayManager *xray.XrayServicesManager, repo, path string, options ...ScanCompleteOption) error {
// 	params := NewScanCompleteParams(options...)
// 	pollingExecutor := &httputils.PollingExecutor{
// 		PollingInterval: ArtifactStatusFetchingInterval,
// 		Timeout:         ArtifactStatusFetchTimeout,
// 		MsgPrefix:       fmt.Sprintf("Waiting for artifact scan to complete the step(s): %v", params.Steps),
// 		PollingAction: func() (shouldStop bool, responseBody []byte, err error) {
// 			status, err := GetArtifactScanStatus(xrayManager, repo, path)
// 			if err != nil {
// 				shouldStop = true
// 				return
// 			}
// 			if !IsScanNotStarted(status.Overall.Status) {
// 				return
// 			}
// 			if !IsScanCompleted(status.Overall.Status) {
// 				return
// 			}
// 			// Marshal the status to JSON format to return it as responseBody
// 			shouldStop = true
// 			responseBody, err = utils.GetAsJsonBytes(status, false, false)
// 			return
// 		},
// 	}
// 	_, err := pollingExecutor.Execute()
// 	return err
// }

// func IsScanCompleted(status services.ArtifactStatus) bool {
// 	return status == services.ArtifactStatusDone || status == services.ArtifactStatusFailed || status == services.ArtifactStatusPartial || status == services.ArtifactStatusNotSupported
// }

// func IsScanInProgress(status services.ArtifactStatus) bool {
// 	return status == services.ArtifactStatusPending || status == services.ArtifactStatusScanning
// }

// func IsScanNotStarted(status services.ArtifactStatus) bool {
// 	return status == services.ArtifactStatusNotScanned || status == ""
// }
