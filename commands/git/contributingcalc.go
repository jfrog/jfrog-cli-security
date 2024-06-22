package git

import (
	"context"
	"encoding/json"
	"errors"
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

type LastCommit struct {
	Date string `json:"date"`
	Hash string `json:"hash"`
}

type RepoLastCommit struct {
	LastCommit
	Repo string `json:"repo,omitempty"`
}

type BasicContributor struct {
	Email string `json:"email"`
	Repo  string `json:"repo,omitempty"`
}

type Contributor struct {
	BasicContributor
	Name           string         `json:"name"`
	RepoLastCommit RepoLastCommit `json:"last_commit"`
}

type ContributorDetailedSummary struct {
	RepoPath   string     `json:"repo_path"`
	LastCommit LastCommit `json:"last_commit"`
}

type RepositoryDetailedSummary struct {
	Email      string     `json:"email"`
	LastCommit LastCommit `json:"last_commit"`
}

type Report struct {
	TotalUniqueContributors  int                                     `json:"total_unique_contributors"`
	TotalCommits             int                                     `json:"total_commits"`
	ScannedRepos             []string                                `json:"scanned_repos"`
	SkippedRepos             []string                                `json:"skipped_repos"`
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
	client, err := vcsclient.NewClientBuilder(params.ScmType).ApiEndpoint(params.ScamApiUrl).Token(params.Token).Build()
	if err != nil {
		return nil, err
	}
	return &GitContributingCommand{
		vcsClient:      client,
		GitCountParams: *params,
	}, nil
}

func (g *GitCountParams) SetProgress(progress ioUtils.ProgressMgr) {
	g.Progress = progress
}

// ScmType represents the valid values that can be provided to the 'scmTypeName' flag.
type ScmType struct {
	ScmTypeMap map[string]vcsutils.VcsProvider
}

func NewScmType() *ScmType {
	scmType := &ScmType{ScmTypeMap: map[string]vcsutils.VcsProvider{}}
	scmType.ScmTypeMap[string(Github)] = vcsutils.GitHub
	scmType.ScmTypeMap[string(Gitlab)] = vcsutils.GitLab
	scmType.ScmTypeMap[string(BitbucketServer)] = vcsutils.BitbucketServer
	scmType.ScmTypeMap[string(Azure)] = vcsutils.AzureRepos
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
		Until: time.Now(),
		ListOptions: vcsclient.ListOptions{
			Page: 1,
		},
	}

	uniqueContributors := make(map[BasicContributor]Contributor)
	detailedContributors := make(map[string]map[string]ContributorDetailedSummary)
	detailedRepos := make(map[string]map[string]RepositoryDetailedSummary)

	repositories, err := gc.getRepositoriesListToScan()
	if err != nil {
		return err
	}
	scannedRepos, skippedRepos, totalCommits := gc.scanAndCollectCommitsInfo(repositories, commitsListOptions, &uniqueContributors, &detailedContributors, &detailedRepos)

	report := gc.aggregateReportResults(uniqueContributors, detailedContributors, detailedRepos)
	report.TotalCommits = totalCommits
	report.ScannedRepos = scannedRepos
	report.SkippedRepos = skippedRepos

	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(reportJSON))
	return nil
}

func (gc *GitContributingCommand) scanAndCollectCommitsInfo(repositories []string, commitsListOptions vcsclient.GitCommitsQueryOptions, uniqueContributors *map[BasicContributor]Contributor, detailedContributors *map[string]map[string]ContributorDetailedSummary, detailedRepos *map[string]map[string]RepositoryDetailedSummary) (scannedRepos, skippedRepos []string, totalCommits int) {
	for _, repo := range repositories {
		// Get repository's commits using pagination until there are no more commits.
		commits, getCommitsErr := gc.GetCommitsWithQueryOptions(repo, commitsListOptions)
		for {
			if getCommitsErr != nil {
				skippedRepos = append(skippedRepos, repo)
				break
			}
			if len(commits) == 0 {
				break
			}
			gc.saveCommitsInfoInMaps(repo, commits, *uniqueContributors, *detailedContributors, *detailedRepos)

			commitsListOptions.Page++
			totalCommits += len(commits)
			commits, getCommitsErr = gc.GetCommitsWithQueryOptions(repo, commitsListOptions)
		}
		if getCommitsErr == nil {
			scannedRepos = append(scannedRepos, repo)
		}
	}
	return
}

// getRepositoriesListToScan returns a list of repositories to scan.
// If a specific repository was provided by the user, return it.
// otherwise, return the list of all the repositories related to the group/project.
func (gc *GitContributingCommand) getRepositoriesListToScan() ([]string, error) {
	if gc.Repository != "" {
		return []string{gc.Repository}, nil
	}
	reposMap, err := gc.vcsClient.ListRepositories(context.Background())
	if err != nil {
		return nil, err
	}
	return reposMap[gc.Owner], nil
}

func (gc *GitContributingCommand) GetCommitsWithQueryOptions(repo string, options vcsclient.GitCommitsQueryOptions) ([]vcsclient.CommitInfo, error) {
	retries := 5
	for retries > 0 {
		commits, err := gc.vcsClient.GetCommitsWithQueryOptions(context.Background(), gc.Owner, repo, options)
		if err != nil {
			var rateLimitError *github.RateLimitError
			if errors.As(err, &rateLimitError) {
				sleepDuration := time.Until(rateLimitError.Rate.Reset.Time)
				log.Printf("Rate limit exceeded, sleeping for %v seconds", sleepDuration)
				time.Sleep(sleepDuration)
				retries--
				continue
			}
			log.Printf("Error getting commits: %v", err)
			return nil, err
		} else {
			return commits, nil
		}
	}
	return nil, errors.New("GetCommitsWithQueryOptions retries exceeded")
}

func (gc *GitContributingCommand) saveCommitsInfoInMaps(repoName string, commits []vcsclient.CommitInfo, uniqueContributors map[BasicContributor]Contributor, detailedContributors map[string]map[string]ContributorDetailedSummary, detailedRepos map[string]map[string]RepositoryDetailedSummary) {
	for _, commit := range commits {
		gc.saveCommitInfoInMaps(repoName, commit, uniqueContributors, detailedContributors, detailedRepos)
	}
}

func (gc *GitContributingCommand) saveCommitInfoInMaps(repoName string, commit vcsclient.CommitInfo, uniqueContributors map[BasicContributor]Contributor, detailedContributors map[string]map[string]ContributorDetailedSummary, detailedRepos map[string]map[string]RepositoryDetailedSummary) {
	authorName := commit.AuthorName
	authorEmail := commit.AuthorEmail
	lastCommit := LastCommit{
		Date: time.Unix(commit.Timestamp, 0).UTC().Format(time.RFC3339),
		Hash: commit.Hash,
	}

	contributorId := BasicContributor{Email: authorEmail, Repo: repoName}
	// Save author's first commit information in the contributors map.
	if _, exists := uniqueContributors[contributorId]; !exists {
		uniqueContributors[contributorId] = Contributor{
			BasicContributor: BasicContributor{
				Email: authorEmail,
			},
			Name:           authorName,
			RepoLastCommit: RepoLastCommit{LastCommit: lastCommit, Repo: repoName},
		}
	}

	if gc.DetailedSummery {
		// Save the last commit of every contributor in every repository where he has contributed.
		if detailedContributors[authorEmail] == nil {
			detailedContributors[authorEmail] = make(map[string]ContributorDetailedSummary)
		}
		if _, exist := detailedContributors[authorEmail][repoName]; !exist {
			detailedContributors[authorEmail][repoName] = ContributorDetailedSummary{
				RepoPath:   repoName,
				LastCommit: lastCommit,
			}
		}
		// Make a list of the repository's contributors and their most recent commits for each repository.
		if detailedRepos[repoName] == nil {
			detailedRepos[repoName] = make(map[string]RepositoryDetailedSummary)
		}
		if _, exist := detailedRepos[repoName][authorEmail]; !exist {
			detailedRepos[repoName][authorEmail] = RepositoryDetailedSummary{
				Email:      authorEmail,
				LastCommit: lastCommit,
			}
		}
	}
}

// aggregateUniqueContributors returns a list of unique contributors.
// If a contributor has committed to multiple repositories, the contributor with the most recent commit is chosen.
func (gc *GitContributingCommand) aggregateUniqueContributors(uniqueContributors map[BasicContributor]Contributor) []Contributor {
	// Choose the contributor with the most recent commit.
	contributorsMap := make(map[string]Contributor)
	for _, contributor := range uniqueContributors {
		if _, exist := contributorsMap[contributor.Email]; !exist {
			contributorsMap[contributor.Email] = contributor
		} else if contributorsMap[contributor.Email].RepoLastCommit.Date < contributor.RepoLastCommit.Date {
			contributorsMap[contributor.Email] = contributor
		}
	}
	// Convert map to array.
	var uniqueContributorsList []Contributor
	for _, contributor := range contributorsMap {
		uniqueContributorsList = append(uniqueContributorsList, contributor)
	}
	return uniqueContributorsList
}

func (gc *GitContributingCommand) aggregateDetailedContributors(detailedContributors map[string]map[string]ContributorDetailedSummary) map[string][]ContributorDetailedSummary {
	detailedContributorsList := make(map[string][]ContributorDetailedSummary)
	for email, repos := range detailedContributors {
		for _, detail := range repos {
			detailedContributorsList[email] = append(detailedContributorsList[email], detail)
		}
	}
	return detailedContributorsList
}

func (gc *GitContributingCommand) aggregateDetailedRepos(detailedRepos map[string]map[string]RepositoryDetailedSummary) map[string][]RepositoryDetailedSummary {
	detailedReposList := make(map[string][]RepositoryDetailedSummary)
	for repo, authors := range detailedRepos {
		for _, detail := range authors {
			detailedReposList[repo] = append(detailedReposList[repo], detail)
		}
	}
	return detailedReposList
}

func (gc *GitContributingCommand) aggregateReportResults(uniqueContributors map[BasicContributor]Contributor, detailedContributors map[string]map[string]ContributorDetailedSummary, detailedRepos map[string]map[string]RepositoryDetailedSummary) Report {
	report := Report{
		TotalUniqueContributors: len(uniqueContributors),
		ReportDate:              time.Now().Format(time.RFC3339),
		NumberOfMonths:          fmt.Sprintf("%d", gc.MonthsNum),
		UniqueContributorsList:  gc.aggregateUniqueContributors(uniqueContributors),
	}

	if gc.DetailedSummery {
		report.DetailedContributorsList = gc.aggregateDetailedContributors(detailedContributors)
		report.DetailedReposList = gc.aggregateDetailedRepos(detailedRepos)
	}

	return report
}

// Returns the Server details. The usage report is sent to this server.
func (gc *GitContributingCommand) ServerDetails() (*config.ServerDetails, error) {
	return nil, nil
}

// The command name for the usage report.
func (gc *GitContributingCommand) CommandName() string {
	return ""
}
