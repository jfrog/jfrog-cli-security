package utils

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/jfrog/jfrog-client-go/xsc"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
	"os"
	"strings"
	"time"
)

const AnalyticsMetricsMinXscVersion = "1.7.1"

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
	if os.Getenv(coreutils.ReportUsage) == "false" {
		return false
	}
	// There is no need to report the event and generate a new msi for the cli scan if the msi was provided.
	if os.Getenv(jfMsiEnvVariable) != "" {
		return false
	}
	// Verify xsc version.
	xscVersion, err := ams.xscManager.GetVersion()
	if err != nil {
		return false
	}
	if err = clientutils.ValidateMinimumVersion(clientutils.Xsc, xscVersion, AnalyticsMetricsMinXscVersion); err != nil {
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

func (ams *AnalyticsMetricsService) AddGeneralEventAndSetMsi(params *services.XrayGraphScanParams) {
	if !ams.ShouldReportEvents() {
		log.Debug("A general event request was not sent to XSC - analytics metrics are disabled.")
		return
	}
	err := ams.AddGeneralEvent()
	if err != nil {
		log.Debug(fmt.Errorf("failed sending general event request to XSC service, error: %s ", err.Error()))
		return
	}
	log.Debug(fmt.Sprintf("New General event added successfully. multi_scan_id %s", ams.GetMsi()))

	if err = os.Setenv(jfMsiEnvVariable, ams.GetMsi()); err != nil {
		// Not a fatal error, if not set the scan will not be shown at the XSC UI, should not fail the scan.
		log.Debug(fmt.Sprintf("failed setting MSI as environment variable. Cause: %s", err.Error()))
	}
	// Before running the audit command, set the msi so the sca scan will be performed on the xsc rather than on the xray server.
	params.MultiScanId = ams.GetMsi()
}
func (ams *AnalyticsMetricsService) AddGeneralEvent() error {
	osAndArc, err := coreutils.GetOSAndArc()
	if err != nil {
		return err
	}
	splitOsAndArch := strings.Split(osAndArc, "-")
	event := xscservices.XscAnalyticsBasicGeneralEvent{
		EventType:              1,
		EventStatus:            xscservices.Started,
		Product:                "cli",
		JfrogUser:              ams.xscManager.Config().GetServiceDetails().GetUser(),
		OsPlatform:             splitOsAndArch[0],
		OsArchitecture:         splitOsAndArch[1],
		AnalyzerManagerVersion: GetAnalyzerManagerVersion(),
		JpdVersion:             "", //TODO artifactory version,
	}

	msi, err := ams.xscManager.AddAnalyticsGeneralEvent(xscservices.XscAnalyticsGeneralEvent{XscAnalyticsBasicGeneralEvent: event})
	if err != nil {
		return err
	}
	// Set event's analytics data.
	ams.SetMsi(msi)
	ams.SetStartTime()
	return nil
}

func (ams *AnalyticsMetricsService) UpdateGeneralEvent(auditResults *Results) {
	if !ams.ShouldReportEvents() {
		log.Debug("A general event update request was not sent to XSC - analytics metrics are disabled.")
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

func (ams *AnalyticsMetricsService) createAuditResultsFromXscAnalyticsBasicGeneralEvent(auditResults *Results) xscservices.XscAnalyticsBasicGeneralEvent {
	totalDuration := time.Now().Sub(ams.GetStartTime())
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
