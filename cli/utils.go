package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/common/cliutils"
	outputFormat "github.com/jfrog/jfrog-cli-core/v2/common/format"
	pluginsCommon "github.com/jfrog/jfrog-cli-core/v2/plugins/common"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	coreConfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/usage"

	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/jfrog-cli-security/sca/bom"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo"
	"github.com/jfrog/jfrog-cli-security/sca/bom/xrayplugin"
	"github.com/jfrog/jfrog-cli-security/sca/scan"
	"github.com/jfrog/jfrog-cli-security/sca/scan/enrich"
	"github.com/jfrog/jfrog-cli-security/sca/scan/scangraph"

	flags "github.com/jfrog/jfrog-cli-security/cli/docs"
	"github.com/jfrog/jfrog-cli-security/policy"
	"github.com/jfrog/jfrog-cli-security/policy/enforcer"
	"github.com/jfrog/jfrog-cli-security/policy/local"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"
)

func createServerDetailsWithConfigOffer(c *components.Context) (*coreConfig.ServerDetails, error) {
	return pluginsCommon.CreateServerDetailsWithConfigOffer(c, true, cliutils.Xr)
}

func validateConnectionAndViolationContextInputs(c *components.Context, serverDetails *coreConfig.ServerDetails, format outputFormat.OutputFormat) error {
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
	if contextFlag > 0 && format == outputFormat.CycloneDx {
		return errorutils.CheckErrorf("Violations are not supported in CycloneDX format.")
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

// Get the dynamic logic for the scan based on the provided flags to support backward compatibility
func getScanDynamicLogic(c *components.Context) (bomGenerator bom.SbomGenerator, scanStrategy scan.SbomScanStrategy, violationGenerator policy.PolicyHandler, uploadResults bool) {
	bomGenerator = buildinfo.NewBuildInfoBomGenerator()
	scanStrategy = scangraph.NewScanGraphStrategy()
	violationGenerator = local.NewDeprecatedViolationGenerator()
	// New flow - static SCA scan
	if c.GetBoolFlagValue(flags.StaticSca) {
		bomGenerator = xrayplugin.NewXrayLibBomGenerator()
		scanStrategy = enrich.NewEnrichScanStrategy()
		violationGenerator = enforcer.NewPolicyEnforcerViolationGenerator()
		uploadResults = true
	}
	return
}

func getAndValidateOutputDirExistsIfProvided(c *components.Context) (string, error) {
	scansOutputDir := c.GetStringFlagValue(flags.OutputDir)
	if scansOutputDir == "" {
		return "", nil
	}
	exists, err := fileutils.IsDirExists(scansOutputDir, false)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", fmt.Errorf("output directory path for saving scans results was provided, but the directory doesn't exist: '%s'", scansOutputDir)
	}
	return scansOutputDir, nil
}
