package contributors

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/go-github/v56/github"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/utils/results/output"
	ioUtils "github.com/jfrog/jfrog-client-go/utils/io"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"golang.org/x/exp/maps"
	"gopkg.in/yaml.v3"
	"os"
)

type scmTypeName string

const (
	Github                        = scmTypeName("github")
	Gitlab                        = scmTypeName("gitlab")
	BitbucketServer               = scmTypeName("bitbucket")
	DefaultContContributorsMonths = 1
	getCommitsRetryNumber         = 5
	GithubTokenEnvVar             = "JFROG_CLI_GITHUB_TOKEN"    // #nosec G101
	GitlabTokenEnvVar             = "JFROG_CLI_GITLAB_TOKEN"    // #nosec G101
	BitbucketTokenEnvVar          = "JFROG_CLI_BITBUCKET_TOKEN" // #nosec G101
	GenericGitTokenEnvVar         = "JF_GIT_TOKEN"              // #nosec G101
)

type BasicContributor struct {
	Email string `json:"email"`
	Repo  string `json:"repo,omitempty"`
}

type Contributor struct {
	Email          string         `json:"email"`
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

type LastCommit struct {
	Date string `json:"date"`
	Hash string `json:"hash"`
}

type RepoLastCommit struct {
	Repo string `json:"repo,omitempty"`
	LastCommit
}

type Report struct {
	TotalUniqueContributors  int                                     `json:"total_unique_contributors"`
	TotalCommits             int                                     `json:"total_commits"`
	ScannedRepos             []string                                `json:"scanned_repos"`
	SkippedRepos             []string                                `json:"skipped_repos,omitempty"`
	ReportDate               string                                  `json:"report_date"`
	NumberOfMonths           string                                  `json:"number_of_months"`
	UniqueContributorsList   []Contributor                           `json:"unique_contributors_list"`
	DetailedContributorsList map[string][]ContributorDetailedSummary `json:"detailed_contributors_list,omitempty"`
	DetailedReposList        map[string][]RepositoryDetailedSummary  `json:"detailed_repos_list,omitempty"`
}

type CountContributorsCommand struct {
	CountContributorsParams
	// Progress bar.
	Progress ioUtils.ProgressMgr
}

// VcsCountContributors combine all the count contributors functionality for one specific VCS.
type VcsCountContributors struct {
	vcsClient vcsclient.VcsClient
	params    CountContributorsParams
}

type GitServersList struct {
	ServersList []BasicGitServerParams `yaml:"git-servers-list"`
}

// BasicGitServerParams basic parameters needed for calling git providers APIs.
type BasicGitServerParams struct {
	// SCM type.
	ScmType vcsutils.VcsProvider `yaml:"scm-type"`
	// SCM API URL. For example: 'https://api.github.com'.
	ScmApiUrl string `yaml:"scm-api-url"`
	// SCM API token.
	Token string `yaml:"token"`
	// The format of the owner key depends on the Git provider:
	// - On GitHub and GitLab, the owner is typically an individual or an organization.
	// - On Bitbucket, the owner can also be a project. In the case of a private instance,
	//   the individual or organization name should be prefixed with '~'.
	Owner string `yaml:"owner"`
	// List of specific repositories names to analyze, If not provided all repositories in the project will be analyzed.
	Repositories []string `yaml:"repositories,omitempty"`
}

type CountContributorsParams struct {
	BasicGitServerParams
	// Path to a file contains multiple git providers to analyze.
	InputFile string
	// Number of months to analyze.
	MonthsNum int
	// Detailed summery flag.
	DetailedSummery bool
	// Progress bar.
	Progress ioUtils.ProgressMgr
}

func NewCountContributorsCommand(params *CountContributorsParams) (*CountContributorsCommand, error) {
	return &CountContributorsCommand{
		CountContributorsParams: *params,
	}, nil
}

func (cc *CountContributorsCommand) SetProgress(progress ioUtils.ProgressMgr) {
	cc.Progress = progress
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
	return scmType
}

func (vs *ScmType) GetValidScmTypeString() string {
	scmTypes := maps.Keys(vs.ScmTypeMap)
	sort.Sort(sort.Reverse(sort.StringSlice(scmTypes)))
	streamsStr := strings.Join(scmTypes[0:len(scmTypes)-1], ", ")
	return fmt.Sprintf("%s and %s", streamsStr, scmTypes[len(scmTypes)-1])
}

func (vs *ScmType) GetOptionalScmTypeTokenEnvVars() string {
	envVars := []string{GithubTokenEnvVar, GitlabTokenEnvVar, BitbucketTokenEnvVar}
	sort.Sort(sort.Reverse(sort.StringSlice(envVars)))
	streamsStr := strings.Join(envVars[0:len(envVars)-1], ", ")
	return fmt.Sprintf("%s or %s", streamsStr, envVars[len(envVars)-1])
}

func (cc *CountContributorsCommand) Run() error {
	log.Info("The CLI outputs may include an estimation of the contributing developers based on the input provided by the user. They may be based on third-party resources and databases and JFrog does not guarantee that the CLI outputs are accurate and/or complete. The CLI outputs are not legal advice and you are solely responsible for your use of it. CLI outputs are provided “as is” and any representation or warranty of or concerning any third-party technology is strictly between the user and the third-party owner or distributor of the third-party technology.")
	if cc.Progress != nil {
		cc.Progress.SetHeadlineMsg("Calculating Git contributors information")
	}

	uniqueContributors := make(map[BasicContributor]Contributor)
	detailedContributors := make(map[string]map[string]ContributorDetailedSummary)
	detailedRepos := make(map[string]map[string]RepositoryDetailedSummary)
	var totalScannedRepos []string
	var totalSkippedRepos []string
	totalCommitsNumber := 0
	vcsCountContributors, err := cc.getVcsCountContributors()
	if err != nil {
		return err
	}
	// Scan all repos from all provided git servers.
	for _, vcc := range vcsCountContributors {
		repositories, err := vcc.getRepositoriesListToScan()
		if err != nil {
			return err
		}
		scannedRepos, skippedRepos, commitsNumber := vcc.scanAndCollectCommitsInfo(repositories, uniqueContributors, detailedContributors, detailedRepos)
		totalScannedRepos = append(totalScannedRepos, scannedRepos...)
		totalSkippedRepos = append(totalSkippedRepos, skippedRepos...)
		totalCommitsNumber += commitsNumber
	}

	// Create the report.
	report := cc.aggregateReportResults(uniqueContributors, detailedContributors, detailedRepos)
	report.TotalCommits = totalCommitsNumber
	report.ScannedRepos = totalScannedRepos
	report.SkippedRepos = totalSkippedRepos

	return output.PrintJson(report)
}

func (cc *CountContributorsCommand) getVcsCountContributors() ([]VcsCountContributors, error) {
	if cc.InputFile == "" {
		vcsClient, err := vcsclient.NewClientBuilder(cc.ScmType).ApiEndpoint(cc.ScmApiUrl).Token(cc.Token).Build()
		if err != nil {
			return nil, err
		}
		return []VcsCountContributors{{params: cc.CountContributorsParams, vcsClient: vcsClient}}, nil
	}
	// Handle the case of provided input file.
	data, err := os.ReadFile(cc.InputFile)
	if err != nil {
		return nil, err
	}
	var gitServersList GitServersList
	err = yaml.Unmarshal(data, &gitServersList)
	if err != nil {
		return nil, err
	}
	if len(gitServersList.ServersList) == 0 {
		return nil, fmt.Errorf("no git servers data was provided in the input file %s", cc.InputFile)
	}
	var contributors []VcsCountContributors
	for _, param := range gitServersList.ServersList {
		p := CountContributorsParams{BasicGitServerParams: param, MonthsNum: cc.MonthsNum, DetailedSummery: cc.DetailedSummery}
		vcsClient, err := vcsclient.NewClientBuilder(param.ScmType).ApiEndpoint(param.ScmApiUrl).Token(param.Token).Build()
		if err != nil {
			return nil, err
		}
		contributors = append(contributors, VcsCountContributors{params: p, vcsClient: vcsClient})
	}
	return contributors, nil
}

func (cc *VcsCountContributors) scanAndCollectCommitsInfo(repositories []string, uniqueContributors map[BasicContributor]Contributor, detailedContributors map[string]map[string]ContributorDetailedSummary, detailedRepos map[string]map[string]RepositoryDetailedSummary) (scannedRepos, skippedRepos []string, totalCommits int) {
	// initialize commits query options.
	commitsListOptions := vcsclient.GitCommitsQueryOptions{
		Since: time.Now().AddDate(0, -1*cc.params.MonthsNum, 0),
		ListOptions: vcsclient.ListOptions{
			Page:    1,
			PerPage: vcsutils.NumberOfCommitsToFetch,
		},
	}
	for _, repo := range repositories {
		// Get repository's commits using pagination until there are no more commits.
		commits, getCommitsErr := cc.GetCommitsWithQueryOptions(repo, commitsListOptions)
		for {
			if getCommitsErr != nil {
				skippedRepos = append(skippedRepos, repo)
				break
			}
			if len(commits) == 0 {
				break
			}
			cc.saveCommitsInfoInMaps(repo, commits, uniqueContributors, detailedContributors, detailedRepos)

			commitsListOptions.Page++
			totalCommits += len(commits)
			commits, getCommitsErr = cc.GetCommitsWithQueryOptions(repo, commitsListOptions)
		}
		if getCommitsErr == nil {
			scannedRepos = append(scannedRepos, repo)
		}
	}
	return
}

// getRepositoriesListToScan returns a list of repositories to scan.
// If specific repositories were provided by the user, return them.
// otherwise, return the list of all the repositories related to the group/project.
func (cc *VcsCountContributors) getRepositoriesListToScan() ([]string, error) {
	if len(cc.params.Repositories) > 0 {
		return cc.params.Repositories, nil
	}
	if cc.vcsClient == nil {
		return nil, errors.New("failed to get repositories list, missing vcs client")
	}
	reposMap, err := cc.vcsClient.ListRepositories(context.Background())
	if err != nil {
		return nil, err
	}
	return cc.getOwnersMatchingRepos(reposMap)
}

// getOwnersMatchingRepos gets all projects and their repo map and look for the specific owner.
func (cc *VcsCountContributors) getOwnersMatchingRepos(reposMap map[string][]string) ([]string, error) {
	repos := reposMap[cc.params.Owner]
	if len(repos) == 0 {
		// Matching owner name without considering lower/upper cases.
		normalizedSearchKey := strings.ToUpper(cc.params.Owner)
		for owner, repoList := range reposMap {
			if strings.ToUpper(owner) == normalizedSearchKey {
				return repoList, nil
			}
		}
		return nil, fmt.Errorf("no repositories found for owner %s in %s at URL %s", cc.params.Owner, cc.params.ScmType, cc.params.ScmApiUrl)
	}
	return repos, nil
}

func (cc *VcsCountContributors) GetCommitsWithQueryOptions(repo string, options vcsclient.GitCommitsQueryOptions) ([]vcsclient.CommitInfo, error) {
	for i := 0; i < getCommitsRetryNumber; i++ {
		commits, err := cc.vcsClient.GetCommitsWithQueryOptions(context.Background(), cc.params.Owner, repo, options)
		if err != nil {
			// Handling a possible known GitHub rate limit error.
			var rateLimitError *github.RateLimitError
			if errors.As(err, &rateLimitError) {
				sleepDuration := time.Until(rateLimitError.Rate.Reset.Time)
				log.Warn("Rate limit exceeded, sleeping for %v seconds", sleepDuration)
				time.Sleep(sleepDuration)
				continue
			}
			log.Error("Error getting commits: %v", err)
			return nil, err
		} else {
			return commits, nil
		}
	}
	return nil, errors.New("GetCommitsWithQueryOptions retries exceeded")
}

func (cc *VcsCountContributors) saveCommitsInfoInMaps(repoName string, commits []vcsclient.CommitInfo, uniqueContributors map[BasicContributor]Contributor, detailedContributors map[string]map[string]ContributorDetailedSummary, detailedRepos map[string]map[string]RepositoryDetailedSummary) {
	for _, commit := range commits {
		cc.saveCommitInfoInMaps(repoName, commit, uniqueContributors, detailedContributors, detailedRepos)
	}
}

func (cc *VcsCountContributors) saveCommitInfoInMaps(repoName string, commit vcsclient.CommitInfo, uniqueContributors map[BasicContributor]Contributor, detailedContributors map[string]map[string]ContributorDetailedSummary, detailedRepos map[string]map[string]RepositoryDetailedSummary) {
	authorName := commit.AuthorName
	authorEmail := commit.AuthorEmail
	lastCommit := LastCommit{
		Date: time.Unix(commit.Timestamp, 0).UTC().Format(time.RFC3339),
		Hash: commit.Hash,
	}

	contributorId := BasicContributor{Email: authorEmail, Repo: repoName}
	// Save author's latest commit information in the contributors map for each repository.
	// All commits are in chronological order - so the first commit we get is the latest.
	if _, exists := uniqueContributors[contributorId]; !exists {
		uniqueContributors[contributorId] = Contributor{
			Email:          authorEmail,
			Name:           authorName,
			RepoLastCommit: RepoLastCommit{LastCommit: lastCommit, Repo: repoName},
		}
	}

	if cc.params.DetailedSummery {
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
		// For each repository, make a list of contributors and their most recent commits.
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
// If a contributor has committed to multiple repositories, the most recent commit will be chosen.
func (cc *CountContributorsCommand) aggregateUniqueContributors(uniqueContributors map[BasicContributor]Contributor) []Contributor {
	// Choose the contributor with the most recent commit.
	contributorsMap := make(map[string]Contributor)
	for _, contributor := range uniqueContributors {
		if _, exist := contributorsMap[contributor.Email]; !exist {
			contributorsMap[contributor.Email] = contributor
		} else if contributorsMap[contributor.Email].RepoLastCommit.Date < contributor.RepoLastCommit.Date {
			contributorsMap[contributor.Email] = contributor
		}
	}
	// Convert map into array.
	var uniqueContributorsList []Contributor
	for _, contributor := range contributorsMap {
		uniqueContributorsList = append(uniqueContributorsList, contributor)
	}
	return uniqueContributorsList
}

func (cc *CountContributorsCommand) aggregateDetailedContributors(detailedContributors map[string]map[string]ContributorDetailedSummary) map[string][]ContributorDetailedSummary {
	detailedContributorsList := make(map[string][]ContributorDetailedSummary)
	for email, repos := range detailedContributors {
		for _, detail := range repos {
			detailedContributorsList[email] = append(detailedContributorsList[email], detail)
		}
	}
	return detailedContributorsList
}

func (cc *CountContributorsCommand) aggregateDetailedRepos(detailedRepos map[string]map[string]RepositoryDetailedSummary) map[string][]RepositoryDetailedSummary {
	detailedReposList := make(map[string][]RepositoryDetailedSummary)
	for repo, authors := range detailedRepos {
		for _, detail := range authors {
			detailedReposList[repo] = append(detailedReposList[repo], detail)
		}
	}
	return detailedReposList
}

func (cc *CountContributorsCommand) aggregateReportResults(uniqueContributors map[BasicContributor]Contributor, detailedContributors map[string]map[string]ContributorDetailedSummary, detailedRepos map[string]map[string]RepositoryDetailedSummary) Report {
	report := Report{
		TotalUniqueContributors: len(uniqueContributors),
		ReportDate:              time.Now().Format(time.RFC3339),
		NumberOfMonths:          fmt.Sprintf("%d", cc.MonthsNum),
		UniqueContributorsList:  cc.aggregateUniqueContributors(uniqueContributors),
	}

	if cc.DetailedSummery {
		report.DetailedContributorsList = cc.aggregateDetailedContributors(detailedContributors)
		report.DetailedReposList = cc.aggregateDetailedRepos(detailedRepos)
	}

	return report
}

// Returns the Server details. The usage report is sent to this server.
func (cc *CountContributorsCommand) ServerDetails() (*config.ServerDetails, error) {
	return nil, nil
}

// The command name for the usage report.
func (cc *CountContributorsCommand) CommandName() string {
	return "git_count_contributors"
}
