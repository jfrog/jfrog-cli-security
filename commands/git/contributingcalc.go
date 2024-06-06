package git

import (
	"context"
	"fmt"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	ioUtils "github.com/jfrog/jfrog-client-go/utils/io"
	"golang.org/x/exp/maps"
	"sort"
	"strings"
	"time"
)

type scmTypeName string

const (
	Github          = scmTypeName("github")
	Gitlab          = scmTypeName("gitlab")
	BitbucketServer = scmTypeName("bitbucket")
	Azure           = scmTypeName("azure")
)

type GitContributingCommand struct {
	vcsClient vcsclient.VcsClient
	GitCountParams
}

type GitCountParams struct {
	ScmType         vcsutils.VcsProvider
	ScamApiUrl      string
	Token           string
	Owner           string
	Repository      string
	MonthsNum       int
	DetailedSummery bool
	Progress        ioUtils.ProgressMgr
}

func NewGitContributingCommand(params *GitCountParams) (*GitContributingCommand, error) {
	client, err := vcsclient.NewClientBuilder(params.ScmType).Build()
	if err != nil {
		return nil, err
	}
	return &GitContributingCommand{
		vcsClient: client,
		GitCountParams: GitCountParams{
			ScmType:         params.ScmType,
			ScamApiUrl:      params.ScamApiUrl,
			Token:           params.Token,
			Owner:           params.Owner,
			Repository:      params.Repository,
			MonthsNum:       params.MonthsNum,
			DetailedSummery: params.DetailedSummery,
			Progress:        params.Progress,
		},
	}, nil
}

func (g *GitCountParams) SetProgress(progress ioUtils.ProgressMgr) {
	g.Progress = progress
}

// ScmType represents the valid values that can be provided to the 'scmTypeName' flag.
type ScmType struct {
	ScmTypeMap          map[string]vcsutils.VcsProvider
	DefaultScmApiUrlMap map[vcsutils.VcsProvider]string
}

func NewScmType() *ScmType {
	scmType := &ScmType{ScmTypeMap: map[string]vcsutils.VcsProvider{}, DefaultScmApiUrlMap: map[vcsutils.VcsProvider]string{}}

	scmType.ScmTypeMap[string(Github)] = vcsutils.GitHub
	scmType.ScmTypeMap[string(Gitlab)] = vcsutils.GitLab
	scmType.ScmTypeMap[string(BitbucketServer)] = vcsutils.BitbucketServer
	scmType.ScmTypeMap[string(Azure)] = vcsutils.AzureRepos

	scmType.DefaultScmApiUrlMap[vcsutils.GitHub] = "https://api.github.com"
	scmType.DefaultScmApiUrlMap[vcsutils.GitLab] = "https://gitlab.com/api/v4"
	scmType.DefaultScmApiUrlMap[vcsutils.BitbucketServer] = "https://api.bitbucket.org/2.0"
	scmType.DefaultScmApiUrlMap[vcsutils.AzureRepos] = "https://dev.azure.com"

	return scmType
}

func (vs *ScmType) GetValidScmTypeString() string {
	scmTypes := maps.Keys(vs.ScmTypeMap)
	sort.Sort(sort.Reverse(sort.StringSlice(scmTypes)))
	streamsStr := strings.Join(scmTypes[0:len(scmTypes)-1], ", ")
	return fmt.Sprintf("%s and %s", streamsStr, scmTypes[len(scmTypes)-1])
}

func (gc *GitContributingCommand) Run() error {
	gc.MonthsNum = 10
	commitsListOptions := vcsclient.GitCommitsQueryOptions{
		Since: time.Now().AddDate(0, -1*gc.MonthsNum, 0),
	}
	gc.Owner = "gailazar300"
	gc.Repository = "jfrog-cli-security"
	commits, err := gc.vcsClient.GetCommitsWithQueryOptions(context.Background(), gc.Owner, gc.Repository, commitsListOptions)
	if err != nil {
		return err
	}
	for _, commit := range commits {
		fmt.Println(commit.Message)
	}
	return nil
}

// Returns the Server details. The usage report is sent to this server.
func (gc *GitContributingCommand) ServerDetails() (*config.ServerDetails, error) {
	return nil, nil
}

// The command name for the usage report.
func (gc *GitContributingCommand) CommandName() string {
	return ""
}
