package utils

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xsc"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
	"os"
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

func (ams *AnalyticsMetricsService) SendNewGeneralEventRequestToXsc() error {
	if !ams.ShouldReportEvents() {
		log.Info("A general event request was not sent to XSC - analytics metrics are disabled.")
		return nil
	}
	event := xscservices.XscGeneralEvent{
		EventType:              0, // ?
		EventStatus:            "started",
		Product:                "cli",
		ProductVersion:         "2.53.1", // add cli version call
		IsDefaultConfig:        false,    // what is this?
		JfrogUser:              "gail",   // add cli user
		OsPlatform:             "mac",    // add
		OsArchitecture:         "arm",    // add
		MachineId:              "",       //?
		AnalyzerManagerVersion: "1.1.1",  //add
		JpdVersion:             "1.5",    //?,
	}

	msi, err := ams.xscManager.PostEvent(event)
	ams.SetMsi(msi)
	return err
}
