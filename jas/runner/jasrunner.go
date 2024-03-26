package runner

import (
	"errors"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/jas/applicability"
	"github.com/jfrog/jfrog-cli-security/jas/iac"
	"github.com/jfrog/jfrog-cli-security/jas/sast"
	"github.com/jfrog/jfrog-cli-security/jas/secrets"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/utils/io"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

func RunJasScannersAndSetResults(scanResults *utils.Results, directDependencies []string,
	serverDetails *config.ServerDetails, workingDirs []string, progress io.ProgressMgr, thirdPartyApplicabilityScan bool, scanType applicability.ApplicabilityScanType, secretsScanType secrets.SecretsScanType) (err error) {
	if serverDetails == nil || len(serverDetails.Url) == 0 {
		log.Warn("To include 'Advanced Security' scan as part of the audit output, please run the 'jf c add' command before running this command.")
		return
	}
	scanner, err := jas.NewJasScanner(workingDirs, serverDetails)
	if err != nil {
		return
	}
	defer func() {
		cleanup := scanner.ScannerDirCleanupFunc
		err = errors.Join(err, cleanup())
	}()
	if progress != nil {
		progress.SetHeadlineMsg("Running applicability scanning")
	}
	scanResults.ExtendedScanResults.ApplicabilityScanResults, err = applicability.RunApplicabilityScan(scanResults.GetScaScansXrayResults(), directDependencies, scanResults.GetScaScannedTechnologies(), scanner, thirdPartyApplicabilityScan, scanType)
	if err != nil {
		return
	}
	// Don't execute other scanners when scanning third party dependencies.
	if thirdPartyApplicabilityScan {
		return
	}
	if progress != nil {
		progress.SetHeadlineMsg("Running secrets scanning")
	}
	scanResults.ExtendedScanResults.SecretsScanResults, err = secrets.RunSecretsScan(scanner, secretsScanType)
	if err != nil {
		return
	}
	if scanType == applicability.ApplicabilityScannerType || secretsScanType == secrets.SecretsScannerType {
		if progress != nil {
			progress.SetHeadlineMsg("Running IaC scanning")
		}
		scanResults.ExtendedScanResults.IacScanResults, err = iac.RunIacScan(scanner)
		if err != nil {
			return
		}
		if progress != nil {
			progress.SetHeadlineMsg("Running SAST scanning")
		}
		scanResults.ExtendedScanResults.SastScanResults, err = sast.RunSastScan(scanner)
	}
	return
}
