package utils

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/usage"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xsc"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
	"strings"
	"time"
)

type AnalyticsMetricsService struct {
	xscManager *xsc.XscServicesManager
	// Should the CLI reports analytics metrics to XSC.
	shouldReportEvents bool
	msi                string
	startTime          time.Time
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

func (ams *AnalyticsMetricsService) SetShouldReportEvents(shouldReportEvents bool) {
	ams.shouldReportEvents = shouldReportEvents
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
			AnalyzerManagerVersion: GetAnalyzerManagerVersion(),
		},
	}
	return &event
}

func (ams *AnalyticsMetricsService) AddGeneralEvent(event *xscservices.XscAnalyticsGeneralEvent) {
	if !ams.ShouldReportEvents() {
		log.Debug("A general event request was not sent to XSC - analytics metrics are disabled.")
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

func (ams *AnalyticsMetricsService) UpdateGeneralEvent(auditResults *Results) {
	if !ams.ShouldReportEvents() {
		log.Debug("A general event update request was not sent to XSC - analytics metrics are disabled.")
		return
	}
	if ams.msi == "" {
		log.Debug("A general event update request was not sent to XSC - failed to add the starting event, and there is no valid multi-scan identifier provided.")
		return
	}
	event := xscservices.XscAnalyticsGeneralEventFinalize{
		MultiScanId:                   ams.msi,
		XscAnalyticsBasicGeneralEvent: ams.createAuditResultsFromXscAnalyticsBasicGeneralEvent(auditResults),
	}
	err := ams.xscManager.UpdateAnalyticsGeneralEvent(event)
	if err != nil {
		log.Debug(fmt.Sprintf("failed updading general event request in XSC service for multi_scan_id %s, error: %s \"", ams.GetMsi(), err.Error()))
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

func (ams *AnalyticsMetricsService) createAuditResultsFromXscAnalyticsBasicGeneralEvent(auditResults *Results) xscservices.XscAnalyticsBasicGeneralEvent {
	totalDuration := time.Since(ams.GetStartTime())
	totalFindings := len(auditResults.ScaResults)
	if auditResults.ExtendedScanResults != nil {
		totalFindings += len(auditResults.ExtendedScanResults.ApplicabilityScanResults) + len(auditResults.ExtendedScanResults.SecretsScanResults) + len(auditResults.ExtendedScanResults.IacScanResults) + len(auditResults.ExtendedScanResults.SastScanResults)
	}
	eventStatus := xscservices.Completed
	if auditResults.ScaError != nil || auditResults.JasError != nil {
		eventStatus = xscservices.Failed
	}
	return xscservices.XscAnalyticsBasicGeneralEvent{
		EventStatus:       eventStatus,
		TotalFindings:     totalFindings,
		TotalScanDuration: totalDuration.String(),
	}
}
