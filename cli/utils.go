package cli

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/common/cliutils"
	outputFormat "github.com/jfrog/jfrog-cli-core/v2/common/format"
	pluginsCommon "github.com/jfrog/jfrog-cli-core/v2/plugins/common"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	coreConfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/usage"

	clientutils "github.com/jfrog/jfrog-client-go/utils"
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

func CreateServerDetailsFromFlags(c *components.Context) (details *coreConfig.ServerDetails, err error) {
	details, err = cliutils.CreateServerDetailsWithConfigOffer(func() (*coreConfig.ServerDetails, error) { return pluginsCommon.CreateServerDetailsFromFlags(c) }, true)
	if err != nil {
		return nil, err
	}
	// Make sure URL and Xray URL are set. (at least one must be set, but both can be set as well)
	if details.Url == "" && details.XrayUrl == "" {
		return nil, errorutils.CheckErrorf("At least one of the following must be set: --%s or --%s", flags.Url, flags.XrayUrl)
	}
	// If only URL is set, set Xray URL based on it.
	if details.XrayUrl == "" {
		details.XrayUrl = clientutils.AddTrailingSlashIfNeeded(details.Url) + "xray/"
	}
	// If only Xray URL is set, set URL based on it.
	if details.Url == "" {
		details.Url = strings.TrimSuffix(clientutils.AddTrailingSlashIfNeeded(details.XrayUrl), "xray/")
	}
	// Set Catalog URL if not set.
	if details.CatalogUrl == "" {
		details.CatalogUrl = clientutils.AddTrailingSlashIfNeeded(details.Url) + "catalog/"
	}
	// Set Artifactory URL if not set.
	if details.ArtifactoryUrl == "" {
		details.ArtifactoryUrl = clientutils.AddTrailingSlashIfNeeded(details.Url) + "artifactory/"
	}
	return details, nil
}

func validateConnectionInputs(serverDetails *coreConfig.ServerDetails) error {
	if serverDetails.XrayUrl == "" {
		return errorutils.CheckErrorf("JFrog Xray URL must be provided in order run this command. Use the 'jf c add' command to set the Xray server details.")
	}
	return nil
}

func getWatches(c *components.Context) (watches []string, err error) {
	if !c.IsFlagSet(flags.Watches) {
		return []string{}, nil
	}
	watches = splitByCommaAndTrim(c.GetStringFlagValue(flags.Watches))
	if c.GetBoolFlagValue(flags.StaticSca) && len(watches) > 1 {
		return nil, errorutils.CheckErrorf("the --%s option supports a single watch when used with the --%s option", flags.Watches, flags.StaticSca)
	}
	return watches, nil
}

func validateConnectionAndViolationContextInputs(c *components.Context, serverDetails *coreConfig.ServerDetails, format outputFormat.OutputFormat) error {
	// Validate connection inputs
	if err := validateConnectionInputs(serverDetails); err != nil {
		return err
	}
	// Validate violation context inputs
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

func reportErrorIfExists(xrayVersion, xscVersion string, serverDetails *coreConfig.ServerDetails, projectKey string, err error) error {
	if err == nil || !usage.ShouldReportUsage() {
		return err
	}
	if reportError := xsc.ReportError(xrayVersion, xscVersion, serverDetails, err, "cli", projectKey); reportError != nil {
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
func getScanDynamicLogic(c *components.Context, xrayVersion string) (bomGenerator bom.SbomGenerator, scanStrategy scan.SbomScanStrategy, violationGenerator policy.PolicyHandler, uploadResults bool, err error) {
	bomGenerator = buildinfo.NewBuildInfoBomGenerator()
	scanStrategy = scangraph.NewScanGraphStrategy()
	violationGenerator = local.NewDeprecatedViolationGenerator()
	// New flow - static SCA scan
	if c.GetBoolFlagValue(flags.StaticSca) {
		// Validate minimum Xray version for static SCA scan (require for getViolations + remediation APIs)
		if err = clientutils.ValidateMinimumVersion(clientutils.Xray, xrayVersion, utils.StaticScanMinVersion); err != nil {
			log.Warn("Static SCA scan is not supported on the current Xray version. " + err.Error())
			// return
		}
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

func getCommandUsedFlagsString(c *components.Context, flags []components.Flag) (out string) {
	out = "Command flags: ["
	flagSet := 0
	for _, flag := range flags {
		// Only if set and not default value
		if isFlagSetAndNotDefault(c, flag) {
			if flagSet != 0 {
				out += " "
			}
			out += fmt.Sprintf("--%s=%s", flag.GetName(), getFlagValueAsString(c, flag))
			flagSet++
		}
	}
	return out + "]"
}

func isFlagSetAndNotDefault(c *components.Context, flag components.Flag) bool {
	if !c.IsFlagSet(flag.GetName()) {
		return false
	}
	if strFlag, ok := flag.(components.StringFlag); ok {
		return c.GetStringFlagValue(flag.GetName()) != strFlag.DefaultValue
	}
	if boolFlag, ok := flag.(components.BoolFlag); ok {
		return c.GetBoolFlagValue(flag.GetName()) != boolFlag.DefaultValue
	}
	return false
}

func getFlagValueAsString(c *components.Context, flag components.Flag) string {
	if !isFlagSetAndNotDefault(c, flag) {
		return ""
	}
	flagName := flag.GetName()
	if _, ok := flag.(components.StringFlag); ok {
		return MaskSensitiveData(flagName, c.GetStringFlagValue(flagName))
	}
	if _, ok := flag.(components.BoolFlag); ok {
		return fmt.Sprintf("%t", c.GetBoolFlagValue(flagName))
	}
	return ""
}

func MaskSensitiveData(flagName, flagValue string) (masked string) {
	// Mask url if required
	if strings.Contains(strings.ToLower(flagName), "url") {
		// Regex to match credentials in URL: http(s)://username:password@host...
		re := regexp.MustCompile(`(https?://)([^:/\s]+):([^@/\s]+)@`)
		masked = re.ReplaceAllString(flagValue, `${1}${2}:****@`)
		return masked
	}
	// Mask password, token, key, passphrase flags
	lowerFlagName := strings.ToLower(flagName)
	if strings.Contains(lowerFlagName, "password") || strings.Contains(lowerFlagName, "passphrase") ||
		strings.Contains(lowerFlagName, "token") || strings.Contains(lowerFlagName, "key") {
		return "****"
	}
	// Return original input if no masking required
	return flagValue
}

func shouldIncludeSbom(c *components.Context, format outputFormat.OutputFormat) bool {
	// Make sure include SBOM is only set if the output format supports it
	includeSbom := c.GetBoolFlagValue(flags.Sbom)
	if includeSbom && format != outputFormat.Table && format != outputFormat.CycloneDx {
		log.Warn(fmt.Sprintf("The '--%s' flag is only supported with the 'table' or 'cyclonedx' output format. The SBOM will not be included in the output.", flags.Sbom))
	}
	return includeSbom
}
