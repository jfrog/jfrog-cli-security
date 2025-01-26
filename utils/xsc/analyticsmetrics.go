package xsc

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-security/utils"
	"strings"
	"time"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/usage"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
)

func CreateAnalyticsEvent(product xscservices.ProductName, eventType xscservices.EventType, serviceDetails *config.ServerDetails) *xscservices.XscAnalyticsGeneralEvent {
	curOs, curArch := getOsAndArch()
	event := xscservices.XscAnalyticsGeneralEvent{
		XscAnalyticsBasicGeneralEvent: xscservices.XscAnalyticsBasicGeneralEvent{
			EventType:              eventType,
			EventStatus:            xscservices.Started,
			Product:                product,
			JfrogUser:              serviceDetails.GetUser(),
			OsPlatform:             curOs,
			OsArchitecture:         curArch,
			JpdVersion:             serviceDetails.ServerId,
			AnalyzerManagerVersion: jas.GetAnalyzerManagerVersion(),
		},
	}
	return &event
}

func SendNewScanEvent(xrayVersion, xscVersion string, serviceDetails *config.ServerDetails, event *xscservices.XscAnalyticsGeneralEvent) (multiScanId string, startTime time.Time) {
	if !shouldReportEvents(xscVersion) {
		log.Debug("Analytics metrics are disabled, skip sending event request to XSC")
		return
	}
	xscService, err := CreateXscServiceBackwardCompatible(xrayVersion, serviceDetails)
	if err != nil {
		log.Debug(fmt.Sprintf("failed to create xsc manager for analytics metrics service, error: %s ", err.Error()))
		return
	}
	if multiScanId, err = xscService.AddAnalyticsGeneralEvent(*event); err != nil {
		log.Debug(fmt.Sprintf("failed sending general event request to XSC service, error: %s ", err.Error()))
		return
	}
	startTime = time.Now()
	return
}

func SendScanEndedEvent(xrayVersion, xscVersion string, serviceDetails *config.ServerDetails, multiScanId string, startTime time.Time, totalFindings int, resultsContext *results.ResultContext, scanError error) {
	if !shouldReportEvents(xscVersion) {
		return
	}
	if multiScanId == "" {
		log.Debug("MultiScanId is empty, skip sending command finalize event.")
		return
	}
	// Generate the finalize event.
	xscService, err := CreateXscServiceBackwardCompatible(xrayVersion, serviceDetails)
	if err != nil {
		log.Debug(fmt.Sprintf("failed to create xsc manager for analytics metrics service, skip sending command finalize event, error: %s ", err.Error()))
		return
	}

	event := CreateFinalizedEvent(multiScanId, startTime, totalFindings, resultsContext, scanError)

	if err = xscService.UpdateAnalyticsGeneralEvent(event); err != nil {
		log.Debug(fmt.Sprintf("failed updating general event in XSC service for multi_scan_id %s, error: %s \"", multiScanId, err.Error()))
		return
	}
	log.Debug(fmt.Sprintf("Command event:\n%v", event))
}

func SendScanEndedWithResults(serviceDetails *config.ServerDetails, cmdResults *results.SecurityCommandResults) {
	if cmdResults == nil || serviceDetails == nil {
		return
	}
	SendScanEndedEvent(
		cmdResults.XrayVersion,
		cmdResults.XscVersion,
		serviceDetails,
		cmdResults.MultiScanId,
		cmdResults.StartTime,
		getTotalFindings(cmdResults),
		&cmdResults.ResultContext,
		cmdResults.GetErrors(),
	)
}

func CreateFinalizedEvent(multiScanId string, startTime time.Time, totalFindings int, resultsContext *results.ResultContext, err error) xscservices.XscAnalyticsGeneralEventFinalize {
	totalDuration := time.Since(startTime)
	eventStatus := xscservices.Completed
	if err != nil {
		eventStatus = xscservices.Failed
	}

	var gitRepoUrlKey string
	if resultsContext != nil {
		gitRepoUrlKey = utils.GetGitRepoUrlKey(resultsContext.GitRepoHttpsCloneUrl)
	}

	return xscservices.XscAnalyticsGeneralEventFinalize{
		MultiScanId: multiScanId,
		GitRepoUrl:  gitRepoUrlKey,
		XscAnalyticsBasicGeneralEvent: xscservices.XscAnalyticsBasicGeneralEvent{
			EventStatus:       eventStatus,
			TotalFindings:     totalFindings,
			TotalScanDuration: totalDuration.String(),
		},
	}
}

func createFinalizedEvent(cmdResults *results.SecurityCommandResults) xscservices.XscAnalyticsGeneralEventFinalize {
	return CreateFinalizedEvent(cmdResults.MultiScanId, cmdResults.StartTime, getTotalFindings(cmdResults), &cmdResults.ResultContext, cmdResults.GetErrors())
}

func GetScanEvent(xrayVersion, xscVersion, multiScanId string, serviceDetails *config.ServerDetails) (*xscservices.XscAnalyticsGeneralEvent, error) {
	if !shouldReportEvents(xscVersion) {
		log.Debug("Can't get general event from XSC - analytics metrics are disabled.")
		return nil, nil
	}
	xscService, err := CreateXscServiceBackwardCompatible(xrayVersion, serviceDetails)
	if err != nil {
		log.Debug(fmt.Sprintf("failed to create xsc manager for analytics metrics service, skip getting general event, error: %s ", err.Error()))
		return nil, err
	}
	event, err := xscService.GetAnalyticsGeneralEvent(multiScanId)
	if err != nil {
		log.Debug(fmt.Sprintf("failed getting general event from XSC service for multi_scan_id %s, error: %s \"", multiScanId, err.Error()))
	}
	return event, err
}

func shouldReportEvents(xscVersion string) bool {
	// A user who explicitly requests not to send reports will not receive XSC analytics metrics.
	if !usage.ShouldReportUsage() {
		return false
	}
	// Verify xsc version.
	if err := clientutils.ValidateMinimumVersion(clientutils.Xsc, xscVersion, xscservices.AnalyticsMetricsMinXscVersion); err != nil {
		return false
	}
	return true
}

func getOsAndArch() (os, arch string) {
	osAndArch, err := coreutils.GetOSAndArc()
	if err != nil {
		log.Debug(fmt.Errorf("failed to get os and architecture for general event request to XSC service, error: %s ", err.Error()))
		return
	}
	splitOsAndArch := strings.Split(osAndArch, "-")
	return splitOsAndArch[0], splitOsAndArch[1]
}

func getTotalFindings(cmdResults *results.SecurityCommandResults) (totalFindings int) {
	if cmdResults == nil {
		return
	}
	summary, err := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{IncludeVulnerabilities: true, HasViolationContext: true}).ConvertToSummary(cmdResults)
	if err != nil {
		log.Warn(fmt.Sprintf("Failed to convert command results to summary. %s", err.Error()))
		return
	}
	if summary.HasViolations() {
		totalFindings = summary.GetTotalViolations()
	} else {
		totalFindings = summary.GetTotalVulnerabilities()
	}
	return
}
