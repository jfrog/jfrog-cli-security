package artifact

import (
	"fmt"
	"strings"

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
	ArtifactStatusFetchingInterval = 10 * 1e9      // nanoseconds converted to 10 seconds
	ArtifactStatusFetchTimeout     = 10 * 60 * 1e9 // nanoseconds converted to 10 minutes
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
	if !params.Overall && len(params.Steps) == 0 {
		return fmt.Errorf("no scan completion criteria were provided")
	}
	log.Debug(fmt.Sprintf("Waiting for artifact scan completion. Overall: %t, Steps: %v", params.Overall, params.Steps))
	pollingExecutor := &httputils.PollingExecutor{
		PollingInterval: ArtifactStatusFetchingInterval,
		Timeout:         ArtifactStatusFetchTimeout,
		MsgPrefix:       "Getting artifact scans status...",
		PollingAction: func() (shouldStop bool, responseBody []byte, err error) {
			status, err := GetArtifactScanStatus(xrayManager, repo, path)
			if err != nil {
				shouldStop = true
				return
			}
			// If the scan hasn't started yet, continue polling
			if IsScanNotStarted(status.Overall.Status) {
				log.Debug(fmt.Sprintf("Artifact scan not started. (%s)", status.Overall.Status))
				return
			}
			// Check if the scan is completed according to the provided criteria
			if params.Overall && !IsScanCompleted(status.Overall.Status) {
				log.Debug(fmt.Sprintf("Current scan status: %s", status.Overall.Status))
				return
			} else if len(params.Steps) > 0 && !CheckStepsCompletion(status.Details, params.Steps) {
				log.Debug(getNotCompletedStepsStatus(status.Details, params.Steps))
				return
			}
			// We don't need to return any response body, as we don't use it.
			// We just need to stop the polling executor.
			shouldStop = true
			return
		},
	}
	_, err := pollingExecutor.Execute()
	return err
}

func getNotCompletedStepsStatus(details services.ArtifactDetailedStatus, steps []XrayScanStep) string {
	statusMap := make(map[XrayScanStep]services.ArtifactStatus)
	for _, step := range steps {
		if !IsScanCompleted(statusMap[step]) {
			switch step {
			case XrayScanStepSca:
				statusMap[step] = details.Sca.Status
			case XrayScanStepContextualAnalysis:
				statusMap[step] = details.ContextualAnalysis.Status
			case XrayScanStepIaC:
				statusMap[step] = details.Exposures.Status
			case XrayScanStepSecrets:
				statusMap[step] = details.Exposures.Status
			case XrayScanStepServices:
				statusMap[step] = details.Exposures.Status
			case XrayScanStepApplication:
				statusMap[step] = details.Exposures.Status
			case XrayScanStepViolations:
				statusMap[step] = details.Violations.Status
			default:
				log.Warn(fmt.Sprintf("Unknown scan step: %s", step))
				statusMap[step] = services.ArtifactStatusFailed
			}
		}
	}
	notCompleted := []string{}
	for step, status := range statusMap {
		notCompleted = append(notCompleted, fmt.Sprintf("%s (%s)", step, status))
	}
	if len(steps) == 1 {
		return fmt.Sprintf("Waiting for: %s (%s)", steps[0], statusMap[steps[0]])
	}
	return fmt.Sprintf("Completed %d/%d, waiting for: [%s]", len(steps)-len(notCompleted), len(steps), strings.Join(notCompleted, ", "))
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
	return status == services.ArtifactStatusNotScanned || status == services.ArtifactStatusPending || status == ""
}
