package cli

import (
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/common/progressbar"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	flags "github.com/jfrog/jfrog-cli-security/cli/docs"
	gitContributorsDocs "github.com/jfrog/jfrog-cli-security/cli/docs/git/contributors"
	gitAuditDocs "github.com/jfrog/jfrog-cli-security/cli/docs/git/audit"
	"github.com/jfrog/jfrog-cli-security/commands/git/contributors"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"os"
	"strings"
)

func getGitNameSpaceCommands() []components.Command {
	return []components.Command{
		{
			Name: 	  "audit",
			Aliases: []string{"a"},
			Description: gitAuditDocs.GetDescription(),
			Flags: flags.GetCommandFlags(flags.Audit),
		},
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
