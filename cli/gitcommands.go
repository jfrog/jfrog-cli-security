package cli

import (
	"github.com/jfrog/jfrog-cli-core/v2/common/progressbar"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	flags "github.com/jfrog/jfrog-cli-security/cli/docs"
	gitDocs "github.com/jfrog/jfrog-cli-security/cli/docs/git"
	"github.com/jfrog/jfrog-cli-security/commands/git"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
)

const defaultContributionMonths = 1

func getGitNameSpaceCommands() []components.Command {
	return []components.Command{
		{
			Name:        "contributing",
			Aliases:     []string{"cont"},
			Flags:       flags.GetCommandFlags(flags.GitContributing),
			Description: gitDocs.GetContributingDescription(),
			Hidden:      true,
			Action:      GitContributingCmd,
		},
	}
}

func GetGitCountParams(c *components.Context) (*git.GitCountParams, error) {
	params := git.GitCountParams{}
	// Mandatory flags
	scmTypes := git.NewScmType()
	// ScmType
	scmType := c.GetStringFlagValue(flags.ScmType)
	if scmType == "" {
		return nil, errorutils.CheckErrorf("the --%s option is mandatory", flags.ScmType)
	} else {
		if scmTypeVal, ok := scmTypes.ScmTypeMap[scmType]; ok {
			params.ScmType = scmTypeVal
		} else {
			return nil, errorutils.CheckErrorf("Unsupported scm type: %s, Possible values are: %v", scmType, scmTypes.GetValidScmTypeString())
		}
	}
	// Token
	params.Token = c.GetStringFlagValue(flags.Token)
	if params.Token == "" {
		return nil, errorutils.CheckErrorf("the --%s option is mandatory", flags.Token)
	}
	// Owner
	params.Owner = c.GetStringFlagValue(flags.Owner)
	if params.Owner == "" {
		return nil, errorutils.CheckErrorf("the --%s option is mandatory", flags.Owner)
	}

	// Optional flags
	// ScmApiUrl
	params.ScamApiUrl = c.GetStringFlagValue(flags.ScmApiUrl)
	if params.ScamApiUrl == "" {
		params.ScamApiUrl = scmTypes.DefaultScmApiUrlMap[params.ScmType]
	}
	// Repository
	params.Repository = c.GetStringFlagValue(flags.RepoName)
	// Months
	months, err := c.GetIntFlagValue(flags.Months)
	if err != nil {
		return nil, err
	}
	if months <= 0 {
		months = defaultContributionMonths
	}
	params.MonthsNum = months
	return &params, nil
}

func GitContributingCmd(c *components.Context) error {
	gitContrParams, err := GetGitCountParams(c)
	if err != nil {
		return err
	}
	gitContributionCommand, err := git.NewGitContributingCommand(gitContrParams)
	if err != nil {
		return err
	}
	return progressbar.ExecWithProgress(gitContributionCommand)
}
