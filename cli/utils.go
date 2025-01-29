package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/common/cliutils"
	pluginsCommon "github.com/jfrog/jfrog-cli-core/v2/plugins/common"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	coreConfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/usage"

	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"

	flags "github.com/jfrog/jfrog-cli-security/cli/docs"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"
)

func createServerDetailsWithConfigOffer(c *components.Context) (*coreConfig.ServerDetails, error) {
	return pluginsCommon.CreateServerDetailsWithConfigOffer(c, true, cliutils.Xr)
}

func validateConnectionAndViolationContextInputs(c *components.Context, serverDetails *coreConfig.ServerDetails) error {
	if serverDetails.XrayUrl == "" {
		return errorutils.CheckErrorf("JFrog Xray URL must be provided in order run this command. Use the 'jf c add' command to set the Xray server details.")
	}
	contextFlag := 0
	if c.GetStringFlagValue(flags.Watches) != "" {
		contextFlag++
	}
	if isProjectProvided(c) {
		contextFlag++
	}
	if c.GetStringFlagValue(flags.RepoPath) != "" {
		contextFlag++
	}
	if contextFlag > 1 {
		return errorutils.CheckErrorf("only one of the following flags can be supplied: --watches, --project or --repo-path")
	}
	return nil
}

func isProjectProvided(c *components.Context) bool {
	return getProject(c) != ""
}

func getProject(c *components.Context) string {
	if c.IsFlagSet(flags.Project) {
		return c.GetStringFlagValue(flags.Project)
	}
	return os.Getenv(coreutils.Project)
}

func getSubScansToPreform(c *components.Context) (subScans []utils.SubScanType, err error) {
	if c.GetBoolFlagValue(flags.WithoutCA) && !c.GetBoolFlagValue(flags.Sca) {
		// No CA flag provided but sca flag is not provided, error
		err = pluginsCommon.PrintHelpAndReturnError(fmt.Sprintf("flag '--%s' cannot be used without '--%s'", flags.WithoutCA, flags.Sca), c)
		return
	}

	if c.GetBoolFlagValue(flags.SecretValidation) && !c.GetBoolFlagValue(flags.Secrets) {
		// No secrets flag but secret validation is provided, error
		err = pluginsCommon.PrintHelpAndReturnError(fmt.Sprintf("flag '--%s' cannot be used without '--%s'", flags.SecretValidation, flags.Secrets), c)
		return
	}

	allSubScans := utils.GetAllSupportedScans()
	for _, subScan := range allSubScans {
		if shouldAddSubScan(subScan, c) {
			subScans = append(subScans, subScan)
		}
	}
	return
}

func shouldAddSubScan(subScan utils.SubScanType, c *components.Context) bool {
	return c.GetBoolFlagValue(subScan.String()) ||
		(subScan == utils.ContextualAnalysisScan && c.GetBoolFlagValue(flags.Sca) && !c.GetBoolFlagValue(flags.WithoutCA)) || (subScan == utils.SecretTokenValidationScan && c.GetBoolFlagValue(flags.Secrets) && c.GetBoolFlagValue(flags.SecretValidation))
}

func reportErrorIfExists(xrayVersion, xscVersion string, serverDetails *coreConfig.ServerDetails, err error) error {
	if err == nil || !usage.ShouldReportUsage() {
		return err
	}
	if reportError := xsc.ReportError(xrayVersion, xscVersion, serverDetails, err, "cli"); reportError != nil {
		log.Debug("failed to report error log:" + reportError.Error())
	}
	return err
}

func splitByCommaAndTrim(paramValue string) (res []string) {
	args := strings.Split(paramValue, ",")
	res = make([]string, len(args))
	for i, arg := range args {
		res[i] = strings.TrimSpace(arg)
	}
	return
}
