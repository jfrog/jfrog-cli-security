package flags

import (
	"os"
	"strings"

	"github.com/jfrog/jfrog-client-go/utils/errorutils"

	"github.com/jfrog/jfrog-cli-core/v2/common/cliutils"
	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/common/spec"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	pluginsCommon "github.com/jfrog/jfrog-cli-core/v2/plugins/common"
	coreConfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
)

// Expecting flags: --server-id, --url, --user, --password, --access-token (optional --insecure-tls)
func ParsePlatformConnectionFlags(context *components.Context) (serverDetails *coreConfig.ServerDetails, err error) {
	if serverDetails, err = pluginsCommon.CreateServerDetailsWithConfigOffer(context, true, cliutils.Xr); err != nil {
		return
	}
	if serverDetails.XrayUrl == "" {
		err = errorutils.CheckErrorf("JFrog Xray URL must be provided in order run this command. Use the 'jf c add' command to set the Xray server details.")
	}
	return
}

// Expecting flags: --working-dirs, --exclusions
func ParseSourceCodeTargetFlags(context *components.Context) (requestedWorkingDirs []string, pathExclusions []string) {
	pathExclusions = pluginsCommon.GetStringsArrFlagValue(context, Exclusions)
	if context.GetStringFlagValue(WorkingDirs) != "" {
		requestedWorkingDirs = utils.SplitAndTrim(context.GetStringFlagValue(WorkingDirs), ",")
	}
	return
}

// Expecting: spec file path (--spec) or a given pattern (in Arg) and flags
// Arguments: (First) the spec file pattern
// Flags: --spec, --recursive, --exclusions, --regexp, --ant, --include-dirs, --repo-path
func ParseSpecFileScanFlags(context *components.Context) (specFile *spec.SpecFiles, err error) {
	if context.IsFlagSet(SpecFlag) && len(context.GetStringFlagValue(SpecFlag)) > 0 {
		if specFile, err = pluginsCommon.GetFileSystemSpec(context); err != nil {
			return
		}
	} else {
		specFile = createDefaultScanSpec(context, addTrailingSlashToRepoPathIfNeeded(context))
	}
	if err = spec.ValidateSpec(specFile.Files, false, false); err != nil {
		return
	}
	pluginsCommon.FixWinPathsForFileSystemSourcedCmds(specFile, context)
	return
}

func createDefaultScanSpec(c *components.Context, defaultTarget string) *spec.SpecFiles {
	return spec.NewBuilder().
		Pattern(c.Arguments[0]).
		Target(defaultTarget).
		Recursive(c.GetBoolFlagValue(Recursive)).
		Exclusions(pluginsCommon.GetStringsArrFlagValue(c, Exclusions)).
		Regexp(c.GetBoolFlagValue(RegexpFlag)).
		Ant(c.GetBoolFlagValue(AntFlag)).
		IncludeDirs(c.GetBoolFlagValue(IncludeDirs)).
		BuildSpec()
}

func addTrailingSlashToRepoPathIfNeeded(c *components.Context) string {
	repoPath := c.GetStringFlagValue(RepoPath)
	if repoPath != "" && !strings.Contains(repoPath, "/") {
		// In case only repo name was provided (no path) we are adding a trailing slash.
		repoPath += "/"
	}
	return repoPath
}

// Expecting flags: --watches, --project, --repo-path, --fail
func ParseViolationContext(context *components.Context) (watches []string, project, repoPath string, fail bool) {
	if context.GetStringFlagValue(Watches) != "" {
		watches = utils.SplitAndTrim(context.GetStringFlagValue(Watches), ",")
	}
	repoPath = addTrailingSlashToRepoPathIfNeeded(context)
	project = context.GetStringFlagValue(Project)
	fail = context.GetBoolFlagValue(Fail)
	ValidateViolationContext(context)
	return
}

func IsViolationContextProvided(context *components.Context) bool {
	return context.GetStringFlagValue(Watches) != "" || isProjectProvided(context) || context.GetStringFlagValue(RepoPath) != ""
}

// refactor to, isViolationsContextProvided
func shouldIncludeVulnerabilities(c *components.Context) bool {
	// If no context was provided by the user, no Violations will be triggered by Xray, so include general vulnerabilities in the command output
	return c.GetStringFlagValue(flags.Watches) == "" && !isProjectProvided(c) && c.GetStringFlagValue(flags.RepoPath) == ""
}

func ValidateViolationContext(context *components.Context) error {
	// if serverDetails.XrayUrl == "" {
	// 	return errorutils.CheckErrorf("JFrog Xray URL must be provided in order run this command. Use the 'jf c add' command to set the Xray server details.")
	// }
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
	if c.IsFlagSet(flags.Project) {
		return c.GetStringFlagValue(flags.Project) != ""
	}
	return os.Getenv(coreutils.Project) != ""
}

func ParseRequestedScanTypesFlags(context *components.Context) (requestedSubScans []utils.SubScanType) {
	if c.GetBoolFlagValue(flags.WithoutCA) && !c.GetBoolFlagValue(flags.Sca) {
		// No CA flag provided but sca flag is not provided, error
		return pluginsCommon.PrintHelpAndReturnError(fmt.Sprintf("flag '--%s' cannot be used without '--%s'", flags.WithoutCA, flags.Sca), c)
	}

	allSubScans := utils.GetAllSupportedScans()
	subScans := []utils.SubScanType{}
	for _, subScan := range allSubScans {
		if shouldAddSubScan(subScan, c) {
			subScans = append(subScans, subScan)
		}
	}
	if len(subScans) > 0 {
		auditCmd.SetScansToPerform(subScans)
	}
}

func shouldAddSubScan(subScan utils.SubScanType, c *components.Context) bool {
	return c.GetBoolFlagValue(subScan.String()) ||
		(subScan == utils.ContextualAnalysisScan && c.GetBoolFlagValue(flags.Sca) && !c.GetBoolFlagValue(flags.WithoutCA))
}

func ParseRequestedPackageManagersFlags(context *components.Context) (requestedPackageManagers []string) {
	// Check if user used specific technologies flags
	allTechnologies := techutils.GetAllTechnologiesList()
	technologies := []string{}
	for _, tech := range allTechnologies {
		var techExists bool
		if tech == techutils.Maven {
			// On Maven we use '--mvn' flag
			techExists = c.GetBoolFlagValue(flags.Mvn)
		} else {
			techExists = c.GetBoolFlagValue(tech.String())
		}
		if techExists {
			technologies = append(technologies, tech.String())
		}
	}
}

func ParseOutputDisplayFlags(context *components.Context) (outputFormat format.OutputFormat, extendedTable bool, err error) {
	extendedTable = context.GetBoolFlagValue(ExtendedTable)
	outputFormat, err = format.GetOutputFormat(context.GetStringFlagValue(OutputFormat))
	return
}

func ParseFilterContentFlags(context *components.Context) (minSeverity severityutils.Severity, fixableOnly bool, err error) {
	fixableOnly = context.GetBoolFlagValue(FixableOnly)
	minSeverity, err = getMinimumSeverity(context)
	return
}

func getMinimumSeverity(c *components.Context) (severity severityutils.Severity, err error) {
	flagSeverity := c.GetStringFlagValue(MinSeverity)
	if flagSeverity == "" {
		return
	}
	severity, err = severityutils.ParseSeverity(flagSeverity, false)
	if err != nil {
		return
	}
	return
}
