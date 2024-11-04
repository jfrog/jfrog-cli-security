package xsc

import (
	"fmt"
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
	"github.com/jfrog/jfrog-client-go/xsc"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
)

type AnalyticsMetricsService struct {
	xscManager *xsc.XscServicesManager
	// Should the CLI reports analytics metrics to XSC.
	shouldReportEvents bool
	msi                string
	startTime          time.Time
	// In the case of multiple scanning, aggregate all audit results into one finalize event.
	finalizeEvent *xscservices.XscAnalyticsGeneralEventFinalize
}

func NewAnalyticsMetricsService(serviceDetails *config.ServerDetails) *AnalyticsMetricsService {
	ams := AnalyticsMetricsService{}
	xscManager, err := CreateXscServiceManager(serviceDetails)
	if err != nil {
		// When an error occurs, shouldReportEvents will be false and no XscServiceManager commands will be executed.
		log.Debug(fmt.Sprintf("Failed to create xsc manager for analytics metrics service. %s", err.Error()))
		return &ams
	}
	ams.xscManager = xscManager
	ams.shouldReportEvents = ams.calcShouldReportEvents()
	return &ams
}

func (ams *AnalyticsMetricsService) calcShouldReportEvents() bool {
	// A user who explicitly requests not to send reports will not receive XSC analytics metrics.
	if !usage.ShouldReportUsage() {
		return false
	}
	// Verify xsc version.
	xscVersion, err := ams.xscManager.GetVersion()
	if err != nil {
		return false
	}
	if err = clientutils.ValidateMinimumVersion(clientutils.Xsc, xscVersion, xscservices.AnalyticsMetricsMinXscVersion); err != nil {
		return false
	}
	return true
}

func (ams *AnalyticsMetricsService) XscManager() *xsc.XscServicesManager {
	return ams.xscManager
}

func (ams *AnalyticsMetricsService) SetMsi(msi string) {
	ams.msi = msi
}

func (ams *AnalyticsMetricsService) GetMsi() string {
	return ams.msi
}

func (ams *AnalyticsMetricsService) SetStartTime() {
	ams.startTime = time.Now()
}

func (ams *AnalyticsMetricsService) GetStartTime() time.Time {
	return ams.startTime
}

func (ams *AnalyticsMetricsService) ShouldReportEvents() bool {
	return ams.shouldReportEvents
}

func (ams *AnalyticsMetricsService) FinalizeEvent() *xscservices.XscAnalyticsGeneralEventFinalize {
	return ams.finalizeEvent
}

func (ams *AnalyticsMetricsService) SetFinalizeEvent(finalizeEvent *xscservices.XscAnalyticsGeneralEventFinalize) {
	ams.finalizeEvent = finalizeEvent
}

func (ams *AnalyticsMetricsService) CreateGeneralEvent(product xscservices.ProductName, eventType xscservices.EventType) *xscservices.XscAnalyticsGeneralEvent {
	osAndArc, err := coreutils.GetOSAndArc()
	curOs, curArch := "", ""
	if err != nil {
		log.Debug(fmt.Errorf("failed to get os and arcitucture for general event request to XSC service, error: %s ", err.Error()))
	} else {
		splitOsAndArch := strings.Split(osAndArc, "-")
		curOs = splitOsAndArch[0]
		curArch = splitOsAndArch[1]
	}

	event := xscservices.XscAnalyticsGeneralEvent{
		XscAnalyticsBasicGeneralEvent: xscservices.XscAnalyticsBasicGeneralEvent{
			EventType:              eventType,
			EventStatus:            xscservices.Started,
			Product:                product,
			JfrogUser:              ams.xscManager.Config().GetServiceDetails().GetUser(),
			OsPlatform:             curOs,
			OsArchitecture:         curArch,
			AnalyzerManagerVersion: jas.GetAnalyzerManagerVersion(),
		},
	}
	return &event
}

func (ams *AnalyticsMetricsService) AddGeneralEvent(event *xscservices.XscAnalyticsGeneralEvent) {
	if !ams.ShouldReportEvents() {
		log.Debug("Analytics metrics are disabled, skipping sending event request to XSC")
		return
	}
	msi, err := ams.xscManager.AddAnalyticsGeneralEvent(*event)
	if err != nil {
		log.Debug(fmt.Errorf("failed sending general event request to XSC service, error: %s ", err.Error()))
		return
	}
	log.Debug(fmt.Sprintf("New General event added successfully. multi_scan_id %s", msi))
	// Set event's analytics data.
	ams.SetMsi(msi)
	ams.SetStartTime()
}

func (ams *AnalyticsMetricsService) UpdateGeneralEvent(event *xscservices.XscAnalyticsGeneralEventFinalize) {
	if !ams.ShouldReportEvents() {
		log.Debug("Analytics metrics are disabled, skipping sending update event request to XSC")
		return
	}
	if ams.msi == "" {
		log.Debug("MultiScanId is empty, skipping update general event.")
		return
	}
	err := ams.xscManager.UpdateAnalyticsGeneralEvent(*event)
	if err != nil {
		log.Debug(fmt.Sprintf("failed updading general event request in XSC service for multi_scan_id %s, error: %s \"", ams.GetMsi(), err.Error()))
	} else {
		log.Debug(fmt.Sprintf("General event updated\n%v", *event))
	}
}

func (ams *AnalyticsMetricsService) GetGeneralEvent(msi string) (*xscservices.XscAnalyticsGeneralEvent, error) {
	if !ams.ShouldReportEvents() {
		log.Debug("Can't get general event from XSC - analytics metrics are disabled.")
		return nil, nil
	}
	event, err := ams.xscManager.GetAnalyticsGeneralEvent(msi)
	if err != nil {
		log.Debug(fmt.Sprintf("failed getting general event from XSC service for multi_scan_id %s, error: %s \"", msi, err.Error()))
	}
	return event, err
}

func (ams *AnalyticsMetricsService) CreateXscAnalyticsGeneralEventFinalizeFromAuditResults(auditResults *results.SecurityCommandResults) *xscservices.XscAnalyticsGeneralEventFinalize {
	totalDuration := time.Since(ams.GetStartTime())
	eventStatus := xscservices.Completed
	if auditResults.GetErrors() != nil {
		eventStatus = xscservices.Failed
	}
	summary, err := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{IncludeVulnerabilities: true, HasViolationContext: true}).ConvertToSummary(auditResults)
	if err != nil {
		log.Warn(fmt.Sprintf("Failed to convert audit results to summary. %s", err.Error()))
	}
	var totalFindings int
	if summary.HasViolations() {
		totalFindings = summary.GetTotalViolations()
	} else {
		totalFindings = summary.GetTotalVulnerabilities()
	}
	// return summary.GetTotalVulnerabilities()
	basicEvent := xscservices.XscAnalyticsBasicGeneralEvent{
		EventStatus:       eventStatus,
		TotalFindings:     totalFindings,
		TotalScanDuration: totalDuration.String(),
	}
	return &xscservices.XscAnalyticsGeneralEventFinalize{
		MultiScanId:                   ams.msi,
		XscAnalyticsBasicGeneralEvent: basicEvent,
	}
}

func (ams *AnalyticsMetricsService) UpdateAndSendXscAnalyticsGeneralEventFinalize(err error) {
	if !ams.ShouldReportEvents() {
		return
	}
	if err != nil {
		ams.UpdateXscAnalyticsGeneralEventFinalizeStatus(xscservices.Failed)
	} else {
		ams.UpdateXscAnalyticsGeneralEventFinalizeWithTotalScanDuration()
		ams.UpdateXscAnalyticsGeneralEventFinalizeStatus(xscservices.Completed)
	}
	ams.UpdateGeneralEvent(ams.FinalizeEvent())
}

func (ams *AnalyticsMetricsService) UpdateXscAnalyticsGeneralEventFinalizeWithTotalScanDuration() {
	totalDuration := time.Since(ams.GetStartTime())
	ams.finalizeEvent.TotalScanDuration = totalDuration.String()
}

func (ams *AnalyticsMetricsService) UpdateXscAnalyticsGeneralEventFinalizeStatus(status xscservices.EventStatus) {
	ams.finalizeEvent.EventStatus = status
}

func (ams *AnalyticsMetricsService) AddScanFindingsToXscAnalyticsGeneralEventFinalize(findingsAmount int) {
	ams.finalizeEvent.TotalFindings += findingsAmount
}

func (ams *AnalyticsMetricsService) SetShouldReportEvents(shouldReportEvents bool) {
	ams.shouldReportEvents = shouldReportEvents
}
