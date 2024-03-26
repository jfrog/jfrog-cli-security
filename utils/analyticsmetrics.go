package utils

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xsc"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
	"os"
	"strings"
)

// TODO VERIFY VERSION
const AnalyticsMetricsMinXscVersion = "1.7.0"

type AnalyticsMetricsService struct {
	xscManager *xsc.XscServicesManager
	// Should the CLI reports analytics metrics to XSC.
	shouldReportEvents bool
	msi                string
}

func NewAnalyticsMetricsService(serviceDetails *config.ServerDetails) (*AnalyticsMetricsService, error) {
	ams := AnalyticsMetricsService{}
	xscManager, err := CreateXscServiceManager(serviceDetails)
	if err != nil {
		return nil, err
	}
	ams.xscManager = xscManager
	ams.shouldReportEvents = ams.calcShouldReportEvents()
	return &ams, nil
}

func (ams *AnalyticsMetricsService) calcShouldReportEvents() bool {
	// A user who explicitly requests not to send reports will not receive XSC analytics metrics.
	if os.Getenv("JFROG_CLI_REPORT_USAGE") == "false" {
		return false
	}
	// There is no need to report the event and generate a new msi for the cli scan if the msi was provided.
	if os.Getenv("JF_MSI") != "" {
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

func (ams *AnalyticsMetricsService) ShouldReportEvents() bool {
	return ams.shouldReportEvents
}

func (ams *AnalyticsMetricsService) AddGeneralEvent() error {
	if !ams.ShouldReportEvents() {
		log.Info("A general event request was not sent to XSC - analytics metrics are disabled.")
		return nil
	}
	osAndArc, err := coreutils.GetOSAndArc()
	if err != nil {
		return err
	}
	splitOsAndArch := strings.Split(osAndArc, "-")
	event := xscservices.XscAnalyticsBasicGeneralEvent{
		EventType:              1,
		EventStatus:            "started",
		Product:                "cli",
		ProductVersion:         "",    // can't have it for now
		IsDefaultConfig:        false, // orz will implement it
		JfrogUser:              ams.xscManager.Config().GetServiceDetails().GetUser(),
		OsPlatform:             splitOsAndArch[0],
		OsArchitecture:         splitOsAndArch[1],
		MachineId:              "", // TODO add
		AnalyzerManagerVersion: GetAnalyzerManagerVersion(),
		JpdVersion:             "", //TODO artifactory version,
	}

	msi, err := ams.xscManager.AddAnalyticsGeneralEvent(xscservices.XscAnalyticsGeneralEvent{XscAnalyticsBasicGeneralEvent: event})
	if err != nil {
		return err
	}
	ams.SetMsi(msi)
	// Set environment variable for analyzer manager analytics.
	return os.Setenv("JF_MSI", msi)
}
