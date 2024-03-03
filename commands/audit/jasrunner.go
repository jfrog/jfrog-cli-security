package audit

import (
	"errors"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/commands/audit/jas"
	"github.com/jfrog/jfrog-cli-security/commands/audit/jas/applicability"
	"github.com/jfrog/jfrog-cli-security/commands/audit/jas/iac"
	"github.com/jfrog/jfrog-cli-security/commands/audit/jas/sast"
	"github.com/jfrog/jfrog-cli-security/commands/audit/jas/secrets"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/utils/io"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"golang.org/x/sync/errgroup"
)

func runJasScannersAndSetResults(scanResults *utils.Results, directDependencies []string,
	serverDetails *config.ServerDetails, workingDirs []string, progress io.ProgressMgr, thirdPartyApplicabilityScan bool) (err error) {
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

	errGroup := new(errgroup.Group)
	errGroup.Go(func() error {
		if progress != nil {
			progress.SetHeadlineMsg("Running applicability scanning")
		}
		err = applicability.RunApplicabilityScan(scanResults.GetScaScansXrayResults(), directDependencies, scanResults.GetScaScannedTechnologies(), scanner, thirdPartyApplicabilityScan, scanResults.ExtendedScanResults)
		if err != nil {
			return err
		}
		return nil
	})
	// Don't execute other scanners when scanning third party dependencies.
	if thirdPartyApplicabilityScan {
		if err = errGroup.Wait(); err != nil {
			return err
		}
		return
	}
	errGroup.Go(func() error {
		if progress != nil {
			progress.SetHeadlineMsg("Running secrets scanning")
		}
		err = secrets.RunSecretsScan(scanner, scanResults.ExtendedScanResults)
		if err != nil {
			return err
		}
		return nil
	})
	errGroup.Go(func() error {
		if progress != nil {
			progress.SetHeadlineMsg("Running IaC scanning")
		}
		err = iac.RunIacScan(scanner, scanResults.ExtendedScanResults)
		if err != nil {
			return err
		}
		return nil
	})
	errGroup.Go(func() error {
		if progress != nil {
			progress.SetHeadlineMsg("Running SAST scanning")
		}
		err = sast.RunSastScan(scanner, scanResults.ExtendedScanResults)
		if err != nil {
			return err
		}
		return nil
	})
	if err = errGroup.Wait(); err != nil {
		return err
	}
	return err
}
