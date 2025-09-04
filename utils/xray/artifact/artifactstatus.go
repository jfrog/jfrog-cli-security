package artifact

import (
	"fmt"

	"github.com/jfrog/jfrog-client-go/utils/io/httputils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

const (
	XrayScanStepSca                = "SCA Scan"
	XrayScanStepContextualAnalysis = "Contextual Analysis Enrichment"
	XrayScanStepIaC                = "IaC Scan"
	XrayScanStepSecrets            = "Secret Detection Scan"
	XrayScanStepServices           = "Services Scan"
	XrayScanStepApplication        = "Application Scan"
	XrayScanStepViolations         = "Violations Reporting"
)

type XrayScanStep string

const (
	ArtifactStatusFetchingInterval = 5   // seconds
	ArtifactStatusFetchTimeout     = 600 // seconds
)

func GetArtifactScanStatus(xrayManager *xray.XrayServicesManager, repo, path string) (*services.ArtifactStatusResponse, error) {
	return xrayManager.GetArtifactStatus(repo, path)
}

type ScanCompleteParams struct {
	Overall bool
	Steps   []XrayScanStep
}

type ScanCompleteOption func(params *ScanCompleteParams)

func OverallCompletion() ScanCompleteOption {
	return func(params *ScanCompleteParams) {
		params.Overall = true
	}
}

func Steps(steps ...XrayScanStep) ScanCompleteOption {
	return func(params *ScanCompleteParams) {
		params.Steps = steps
	}
}

func NewScanCompleteParams(options ...ScanCompleteOption) *ScanCompleteParams {
	params := &ScanCompleteParams{}
	for _, option := range options {
		option(params)
	}
	return params
}

func WaitForArtifactScanCompletion(xrayManager *xray.XrayServicesManager, repo, path string, options ...ScanCompleteOption) error {
	params := NewScanCompleteParams(options...)
	pollingExecutor := &httputils.PollingExecutor{
		PollingInterval: ArtifactStatusFetchingInterval,
		Timeout:         ArtifactStatusFetchTimeout,
		MsgPrefix:       fmt.Sprintf("Waiting for artifact scan to complete the step(s): %v", params.Steps),
		PollingAction: func() (shouldStop bool, responseBody []byte, err error) {
			status, err := GetArtifactScanStatus(xrayManager, repo, path)
			if err != nil {
				shouldStop = true
				return
			}
			if !IsScanNotStarted(status.Overall.Status) {
				log.Debug("Artifact scan not started yet.")
				return
			}
			log.Debug(fmt.Sprintf("Current scan status: %v", status))
			if params.Overall {
				if !IsScanCompleted(status.Overall.Status) {
					return
				}
			} else if len(params.Steps) > 0 {
				if !CheckStepsCompletion(status.Details, params.Steps) {
					return
				}
			} else {
				err = fmt.Errorf("no scan completion criteria were provided")
				shouldStop = true
				return
			}
			log.Debug("Artifact scan completed.")
			// We don't need to return any response body, as we don't use it.
			// We just need to stop the polling executor.
			shouldStop = true
			return
		},
	}
	_, err := pollingExecutor.Execute()
	return err
}

func CheckStepsCompletion(details services.ArtifactDetailedStatus, steps []XrayScanStep) bool {
	for _, step := range steps {
		switch step {
		case XrayScanStepSca:
			if !IsScanCompleted(details.Sca.Status) {
				return false
			}
		case XrayScanStepContextualAnalysis:
			if !IsScanCompleted(details.ContextualAnalysis.Status) {
				return false
			}
		case XrayScanStepIaC:
			if !IsScanCompleted(details.Exposures.Status) {
				return false
			}
		case XrayScanStepSecrets:
			if !IsScanCompleted(details.Exposures.Status) {
				return false
			}
		case XrayScanStepServices:
			if !IsScanCompleted(details.Exposures.Status) {
				return false
			}
		case XrayScanStepApplication:
			if !IsScanCompleted(details.Exposures.Status) {
				return false
			}
		case XrayScanStepViolations:
			if !IsScanCompleted(details.Violations.Status) {
				return false
			}
		default:
			log.Warn(fmt.Sprintf("Unknown scan step: %s", step))
			return false
		}
	}
	return true
}

func IsScanCompleted(status services.ArtifactStatus) bool {
	return status == services.ArtifactStatusDone || status == services.ArtifactStatusFailed || status == services.ArtifactStatusPartial || status == services.ArtifactStatusNotSupported
}

func IsScanNotStarted(status services.ArtifactStatus) bool {
	return status == services.ArtifactStatusNotScanned || status == ""
}
