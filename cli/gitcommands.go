package cli

import (
	"os"
	"strings"

	"github.com/jfrog/froggit-go/vcsutils"
	outputFormat "github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/common/progressbar"
	pluginsCommon "github.com/jfrog/jfrog-cli-core/v2/plugins/common"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	flags "github.com/jfrog/jfrog-cli-security/cli/docs"
	gitAuditDocs "github.com/jfrog/jfrog-cli-security/cli/docs/git/audit"
	gitContributorsDocs "github.com/jfrog/jfrog-cli-security/cli/docs/git/contributors"
	"github.com/jfrog/jfrog-cli-security/commands/git/audit"
	"github.com/jfrog/jfrog-cli-security/commands/git/contributors"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

func getGitNameSpaceCommands() []components.Command {
	return []components.Command{
		{
			Name:        "audit",
			Aliases:     []string{"a"},
			Description: gitAuditDocs.GetDescription(),
			Flags:       flags.GetCommandFlags(flags.GitAudit),
			Hidden:      true,
			Action:      GitAuditCmd,
		},
		// TODO: Move cc cmd to Frogbot/Script
		{
			Name:        "count-contributors",
			Aliases:     []string{"cc"},
			Flags:       flags.GetCommandFlags(flags.GitCountContributors),
			Description: gitContributorsDocs.GetContContributorsDescription(),
			Hidden:      true,
			Action:      GitCountContributorsCmd,
		},
	}
}

func GitAuditCmd(c *components.Context) error {
	log.Info("####### Starting jf git audit Scan #######")
	log.Info(getCommandUsedFlagsString(c, flags.GetCommandFlags(flags.GitAudit)))
	gitAuditCmd := audit.NewGitAuditCommand()
	// Set connection params
	serverDetails, err := CreateServerDetailsFromFlags(c)
	if err != nil {
		return err
	}
	xrayVersion, xscVersion, err := xsc.GetJfrogServicesVersion(serverDetails)
	if err != nil {
		return err
	}
	gitAuditCmd.SetServerDetails(serverDetails).SetXrayVersion(xrayVersion).SetXscVersion(xscVersion)
	// Set violations params
	format, err := outputFormat.GetOutputFormat(c.GetStringFlagValue(flags.OutputFormat))
	if err != nil {
		return err
	}
	if err = validateConnectionAndViolationContextInputs(c, serverDetails, format); err != nil {
		return err
	}
	if watches, err := getWatches(c); err != nil {
		return err
	} else {
		gitAuditCmd.SetWatches(watches)
	}
	gitAuditCmd.SetProjectKey(getProject(c)).SetIncludeVulnerabilities(c.GetBoolFlagValue(flags.Vuln))
	// Set Scan params
	if subScans, err := getSubScansToPreform(c); err != nil {
		return err
	} else if len(subScans) > 0 {
		gitAuditCmd.SetScansToPerform(subScans)
	}
	if err := validateAnalyzerManagerRequirements(gitAuditCmd.GetScansToPerform()); err != nil {
		return err
	}
	gitAuditCmd.SetIncludeSbom(shouldIncludeSbom(c, format))
	if threads, err := pluginsCommon.GetThreadsCount(c); err != nil {
		return err
	} else {
		gitAuditCmd.SetThreads(threads)
	}
	gitAuditCmd.SetExclusions(pluginsCommon.GetStringsArrFlagValue(c, flags.Exclusions))
	// Set output params
	gitAuditCmd.SetOutputFormat(format).SetIncludeLicenses(c.GetBoolFlagValue(flags.Licenses)).SetFailBuild(c.GetBoolFlagValue(flags.Fail))
	scansOutputDir, err := getAndValidateOutputDirExistsIfProvided(c)
	if err != nil {
		return err
	}
	gitAuditCmd.SetOutputDir(scansOutputDir).SetExtendedTable(c.GetBoolFlagValue(flags.ExtendedTable))
	// Set the dynamic logic for SBOM generation and SCA scan strategy
	sbomGenerator, scaScanStrategy, violationGenerator, uploadResults, err := getScanDynamicLogic(c, xrayVersion)
	if err != nil {
		return err
	}
	gitAuditCmd.SetSbomGenerator(sbomGenerator).SetScaScanStrategy(scaScanStrategy)
	gitAuditCmd.SetViolationGenerator(violationGenerator)
	gitAuditCmd.SetUploadCdxResults(uploadResults).SetRtResultRepository(c.GetStringFlagValue(flags.UploadRtRepoPath))
	// Run the command with progress bar if needed, Reporting error if Xsc service is enabled
	err = reportErrorIfExists(xrayVersion, xscVersion, serverDetails, gitAuditCmd.GetProjectKey(), progressbar.ExecWithProgress(gitAuditCmd))
	return err
}

func GetCountContributorsParams(c *components.Context) (*contributors.CountContributorsParams, error) {
	params := contributors.CountContributorsParams{}
	params.InputFile = c.GetStringFlagValue(flags.InputFile)
	if params.InputFile == "" {
		// Mandatory flags in case no input file was provided.
		scmTypes := contributors.NewScmType()
		// ScmType
		scmType := c.GetStringFlagValue(flags.ScmType)
		if scmType == "" {
			return nil, errorutils.CheckErrorf("The --%s option is mandatory", flags.ScmType)
		} else {
			if scmTypeVal, ok := scmTypes.ScmTypeMap[scmType]; ok {
				params.ScmType = scmTypeVal
			} else {
				return nil, errorutils.CheckErrorf("Unsupported SCM type: %s, Possible values are: %v", scmType, scmTypes.GetValidScmTypeString())
			}
		}
		// Token
		params.Token = c.GetStringFlagValue(flags.Token)
		if params.Token == "" {
			var envVarToken string
			switch params.ScmType {
			case vcsutils.BitbucketServer:
				envVarToken = os.Getenv(contributors.BitbucketTokenEnvVar)
			case vcsutils.GitLab:
				envVarToken = os.Getenv(contributors.GitlabTokenEnvVar)
			case vcsutils.GitHub:
				envVarToken = os.Getenv(contributors.GithubTokenEnvVar)
			default:
				return nil, errorutils.CheckErrorf("Unsupported SCM type: %s, Possible values are: %v", scmType, scmTypes.GetValidScmTypeString())
			}
			if envVarToken != "" {
				params.Token = envVarToken
			} else {
				envVarToken = os.Getenv(contributors.GenericGitTokenEnvVar)
				if envVarToken != "" {
					params.Token = envVarToken
				} else {
					return nil, errorutils.CheckErrorf("Providing a token is mandatory. should use --%s flag, the token environment variable %s, or corresponding provider environment variable %s.", flags.Token, contributors.GenericGitTokenEnvVar, scmTypes.GetOptionalScmTypeTokenEnvVars())
				}
			}
		}
		// Owner
		params.Owner = c.GetStringFlagValue(flags.Owner)
		if params.Owner == "" {
			return nil, errorutils.CheckErrorf("The --%s option is mandatory", flags.Owner)
		}
		// ScmApiUrl
		params.ScmApiUrl = c.GetStringFlagValue(flags.ScmApiUrl)
		if params.ScmApiUrl == "" {
			return nil, errorutils.CheckErrorf("The --%s option is mandatory", flags.ScmApiUrl)
		}
		// Repositories names
		params.Repositories = getRepositoriesList(c.GetStringFlagValue(flags.RepoName))
	}

	// Optional flags
	// Months
	if !c.IsFlagSet(flags.Months) {
		params.MonthsNum = contributors.DefaultContContributorsMonths
	} else {
		months, err := c.GetIntFlagValue(flags.Months)
		if err != nil {
			return nil, err
		}
		if months <= 0 {
			return nil, errorutils.CheckErrorf("Invalid value for '--%s=%d'. If set, should be positive number.", flags.Months, months)
		}
		params.MonthsNum = months
	}
	// DetailedSummery
	params.DetailedSummery = c.GetBoolFlagValue(flags.DetailedSummary)
	return &params, nil
}

func getRepositoriesList(reposStr string) []string {
	reposSlice := strings.Split(reposStr, ";")
	// Trim spaces and create a clean list of repo names
	repos := []string{}
	for _, repo := range reposSlice {
		trimmedRepo := strings.TrimSpace(repo)
		if trimmedRepo != "" {
			repos = append(repos, trimmedRepo)
		}
	}
	return repos
}

func GitCountContributorsCmd(c *components.Context) error {
	gitContrParams, err := GetCountContributorsParams(c)
	if err != nil {
		return err
	}
	gitContributionCommand, err := contributors.NewCountContributorsCommand(gitContrParams)
	if err != nil {
		return err
	}
	return progressbar.ExecWithProgress(gitContributionCommand)
}
