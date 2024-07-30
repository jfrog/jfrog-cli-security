package flags

import (
	"fmt"
	"os"
	"strings"

	"github.com/jfrog/jfrog-client-go/utils/errorutils"

	"github.com/jfrog/jfrog-cli-core/v2/common/cliutils"
	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/common/spec"
	pluginsCommon "github.com/jfrog/jfrog-cli-core/v2/plugins/common"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	coreConfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
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
func ParseViolationContext(context *components.Context) (watches []string, project, repoPath string, failOnViolation bool, err error) {
	contextFlag := 0
	if context.GetStringFlagValue(Watches) != "" {
		watches = utils.SplitAndTrim(context.GetStringFlagValue(Watches), ",")
		contextFlag++
	}
	if repoPath = addTrailingSlashToRepoPathIfNeeded(context); repoPath != "" {
		contextFlag++
	}
	if project = getProjectContext(context); project != "" {
		contextFlag++
	}
	failOnViolation = context.GetBoolFlagValue(Fail)
	if contextFlag > 1 {
		err = errorutils.CheckErrorf(fmt.Sprintf("only one of the following flags can be supplied: --%s, --%s or --%s", Watches, Project, RepoPath))
	} else if failOnViolation && contextFlag == 0 {
		err = errorutils.CheckErrorf("the --%s flag can only be used with --%s, --%s or --%s", Fail, Watches, Project, RepoPath)
	}
	return
}

func getProjectContext(context *components.Context) string {
	if context.IsFlagSet(Project) {
		return context.GetStringFlagValue(Project)
	}
	return os.Getenv(coreutils.Project)
}

// If no context was provided by the user, no Violations will be triggered by Xray, so should include general vulnerabilities in the command output
func IsViolationContextProvided(context *components.Context) bool {
	return context.GetStringFlagValue(Watches) != "" || isProjectProvided(context) || context.GetStringFlagValue(RepoPath) != ""
}

func isProjectProvided(c *components.Context) bool {
	return getProjectContext(c) != ""
}

// Expecting flags: --sca, --without-contextual-analysis, --iac, --secrets, --sast
func ParseRequestedScanTypesFlags(context *components.Context) (requestedSubScans []utils.SubScanType, err error) {
	if context.GetBoolFlagValue(WithoutCA) && !context.GetBoolFlagValue(Sca) {
		// No CA flag provided but sca flag is not provided, error
		err = pluginsCommon.PrintHelpAndReturnError(fmt.Sprintf("flag '--%s' cannot be used without '--%s'", WithoutCA, Sca), context)
		return
	}
	for _, subScan := range utils.GetAllSupportedScans() {
		if context.GetBoolFlagValue(subScan.String()) || (subScan == utils.ContextualAnalysisScan && context.GetBoolFlagValue(Sca) && !context.GetBoolFlagValue(WithoutCA)) {
			requestedSubScans = append(requestedSubScans, subScan)
		}
	}
	return
}

func ParseTechnologyConfigurationFlags(context *components.Context) string {
	// curationAuditCommand.SetExcludeTestDependencies(c.GetBoolFlagValue(flags.ExcludeTestDeps)).
	// 	SetUseWrapper(c.GetBoolFlagValue(flags.UseWrapper)).
	// 	SetNpmScope(c.GetStringFlagValue(flags.DepType)).
	// 	SetPipRequirementsFile(c.GetStringFlagValue(flags.RequirementsFile))

	// auditCmd.SetUseWrapper(c.GetBoolFlagValue(flags.UseWrapper)).
	// 	SetNpmScope(c.GetStringFlagValue(flags.DepType)).
	// 	SetExcludeTestDependencies(c.GetBoolFlagValue(flags.ExcludeTestDeps)).
	// 	SetPipRequirementsFile(c.GetStringFlagValue(flags.RequirementsFile))
	return ""
}

// Expecting flags: values from techutils.Technology enum
func ParseRequestedTechnologiesFlags(context *components.Context) (requestedTechnologies []string) {
	for _, tech := range techutils.GetAllTechnologiesList() {
		var techExists bool
		if tech == techutils.Maven {
			// On Maven we use '--mvn' flag
			techExists = context.GetBoolFlagValue(Mvn)
		} else {
			techExists = context.GetBoolFlagValue(tech.String())
		}
		if techExists {
			requestedTechnologies = append(requestedTechnologies, tech.String())
		}
	}
	return
}

func ParseOutputDisplayFlags(context *components.Context) (outputFormat format.OutputFormat, extendedTable, includeLicenses bool, err error) {
	extendedTable = context.GetBoolFlagValue(ExtendedTable)
	includeLicenses = context.GetBoolFlagValue(Licenses)
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
