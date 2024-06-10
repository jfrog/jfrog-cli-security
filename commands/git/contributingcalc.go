package git

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/go-github/v56/github"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	ioUtils "github.com/jfrog/jfrog-client-go/utils/io"
	"golang.org/x/exp/maps"
	"log"
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

type Contributor struct {
	Name       string `json:"name"`
	Email      string `json:"email"`
	LastCommit string `json:"last_commit_date"`
}

type ContributorDetailedSummary struct {
	RepoPath   string `json:"repo_path"`
	LastCommit string `json:"last_commit_date"`
}

type RepositoryDetailedSummary struct {
	Email      string `json:"email"`
	LastCommit string `json:"last_commit_date"`
}

type Report struct {
	TotalUniqueContributors  int                                     `json:"total_unique_contributors"`
	ReportDate               string                                  `json:"report_date"`
	NumberOfMonths           string                                  `json:"number_of_months"`
	UniqueContributorsList   []Contributor                           `json:"unique_contributors_list"`
	DetailedContributorsList map[string][]ContributorDetailedSummary `json:"detailed_contributors_list,omitempty"`
	DetailedReposList        map[string][]RepositoryDetailedSummary  `json:"detailed_repos_list,omitempty"`
}

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
	commitsListOptions := vcsclient.GitCommitsQueryOptions{
		Since: time.Now().AddDate(0, -1*gc.MonthsNum, 0),
		ListOptions: vcsclient.ListOptions{
			Page: 1,
		},
	}

	uniqueContributors := make(map[string]Contributor)
	detailedContributors := make(map[string]map[string]ContributorDetailedSummary)
	detailedRepos := make(map[string]map[string]RepositoryDetailedSummary)

	for {
		// Get repository's commits using pagination until there are no more commits.
		commits, err := gc.vcsClient.GetCommitsWithQueryOptions(context.Background(), gc.Owner, gc.Repository, commitsListOptions)
		if err != nil {
			if rateLimitError, ok := err.(*github.RateLimitError); ok {
				log.Printf("Rate limit exceeded, sleeping for %v seconds", rateLimitError.Rate.Reset.Sub(time.Now()).Seconds())
				time.Sleep(rateLimitError.Rate.Reset.Sub(time.Now()))
				continue
			}
			log.Fatalf("Error getting commits: %v", err)
			return err
		}
		if len(commits) == 0 {
			break
		}
		commitsListOptions.Page++
		for _, commit := range commits {
			gc.saveCommitInfoInMaps(commit, uniqueContributors, detailedContributors, detailedRepos)
		}
	}

	report, err := gc.createJsonReport(uniqueContributors, detailedContributors, detailedRepos)
	if err != nil {
		return err
	}
	fmt.Println(string(report))
	return nil
}

func (gc *GitContributingCommand) saveCommitInfoInMaps(commit vcsclient.CommitInfo, uniqueContributors map[string]Contributor, detailedContributors map[string]map[string]ContributorDetailedSummary, detailedRepos map[string]map[string]RepositoryDetailedSummary) {
	authorName := commit.AuthorName
	authorEmail := commit.AuthorEmail
	lastCommit := time.Unix(commit.Timestamp, 0).Format(time.RFC3339)

	// Save author's first commit information in the contributors map.
	if _, exists := uniqueContributors[authorEmail]; !exists {
		uniqueContributors[authorEmail] = Contributor{
			Name:       authorName,
			Email:      authorEmail,
			LastCommit: lastCommit,
		}
	}

	if gc.DetailedSummery {
		// Save the last commit of every contributor in every repository where he has contributed.
		if detailedContributors[authorEmail] == nil {
			detailedContributors[authorEmail] = make(map[string]ContributorDetailedSummary)
		}
		detailedContributors[authorEmail][gc.Repository] = ContributorDetailedSummary{
			RepoPath:   gc.Repository,
			LastCommit: lastCommit,
		}
		// Make a list of the repository's contributors and their most recent commits for each repository.
		if detailedRepos[gc.Repository] == nil {
			detailedRepos[gc.Repository] = make(map[string]RepositoryDetailedSummary)
		}
		detailedRepos[gc.Repository][authorEmail] = RepositoryDetailedSummary{
			Email:      authorEmail,
			LastCommit: lastCommit,
		}
	}
}

func (gc *GitContributingCommand) createJsonReport(uniqueContributors map[string]Contributor, detailedContributors map[string]map[string]ContributorDetailedSummary, detailedRepos map[string]map[string]RepositoryDetailedSummary) ([]byte, error) {
	// Convert maps to lists.
	var uniqueContributorsList []Contributor
	for _, contributor := range uniqueContributors {
		uniqueContributorsList = append(uniqueContributorsList, contributor)
	}
	// example: “List of users”: { (repo path, last commit date), (repo path, last commit date), …}
	detailedContributorsList := make(map[string][]ContributorDetailedSummary)
	for email, repos := range detailedContributors {
		for _, detail := range repos {
			detailedContributorsList[email] = append(detailedContributorsList[email], detail)
		}
	}
	// example: “list of repo path”: { (user, last commit date), (user, last commit date), …}
	detailedReposList := make(map[string][]RepositoryDetailedSummary)
	for repo, authors := range detailedRepos {
		for _, detail := range authors {
			detailedReposList[repo] = append(detailedReposList[repo], detail)
		}
	}

	report := Report{
		TotalUniqueContributors: len(uniqueContributors),
		ReportDate:              time.Now().Format(time.RFC3339),
		NumberOfMonths:          fmt.Sprintf("%d", gc.MonthsNum),
		UniqueContributorsList:  uniqueContributorsList,
	}

	if gc.DetailedSummery {
		report.DetailedContributorsList = detailedContributorsList
		report.DetailedReposList = detailedReposList
	}

	reportJSON, err := json.MarshalIndent(report, "", "  ")
	return reportJSON, err
}

// Returns the Server details. The usage report is sent to this server.
func (gc *GitContributingCommand) ServerDetails() (*config.ServerDetails, error) {
	return nil, nil
}

// The command name for the usage report.
func (gc *GitContributingCommand) CommandName() string {
	return ""
}
