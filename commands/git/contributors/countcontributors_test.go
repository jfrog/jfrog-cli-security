package contributors

import (
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
	"path"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func getCommitsListForTest(t *testing.T) []vcsclient.CommitInfo {
	return []vcsclient.CommitInfo{
		{
			AuthorEmail: "email1@gmail.com",
			Timestamp:   convertDateStrToTimestamp(t, "2023-05-21T10:00:00Z"),
		},
		{
			AuthorEmail: "email2@gmail.com",
			Timestamp:   convertDateStrToTimestamp(t, "2023-06-21T10:00:00Z"),
		},
		{
			AuthorEmail: "email1@gmail.com",
			Timestamp:   convertDateStrToTimestamp(t, "2023-03-21T10:00:00Z"),
		},
		{
			AuthorEmail: "email2@gmail.com",
			Timestamp:   convertDateStrToTimestamp(t, "2023-02-21T10:00:00Z"),
		},
	}
}

func GetTestDataPath() string {
	return filepath.Join("..", "..", "..", "tests", "testdata", "git")
}

func TestCountContributorsCommand_saveCommitsInfoInMaps_OneRepo(t *testing.T) {
	type args struct {
		repoName                             string
		commits                              []vcsclient.CommitInfo
		uniqueContributorsVerificationFunc   func(t *testing.T, uniqueContributors map[BasicContributor]Contributor)
		detailedContributorsVerificationFunc func(t *testing.T, detailedContributors map[string]map[string]ContributorDetailedSummary)
		detailedReposVerificationFunc        func(t *testing.T, detailedRepos map[string]map[string]RepositoryDetailedSummary)
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "no commits",
			args: args{
				repoName: "repo1",
				commits:  []vcsclient.CommitInfo{},
				uniqueContributorsVerificationFunc: func(t *testing.T, uniqueContributors map[BasicContributor]Contributor) {
					assert.Equal(t, 0, len(uniqueContributors))
				},
				detailedContributorsVerificationFunc: func(t *testing.T, detailedContributors map[string]map[string]ContributorDetailedSummary) {
					assert.Equal(t, 0, len(detailedContributors))
				},
				detailedReposVerificationFunc: func(t *testing.T, detailedRepos map[string]map[string]RepositoryDetailedSummary) {
					assert.Equal(t, 0, len(detailedRepos))
				},
			},
		},
		{"2 authors with 2 commits each",
			args{
				repoName: "repo1",
				commits:  getCommitsListForTest(t),
				uniqueContributorsVerificationFunc: func(t *testing.T, uniqueContributors map[BasicContributor]Contributor) {
					assert.Equal(t, 2, len(uniqueContributors))
					assert.Equal(t, "2023-05-21T10:00:00Z", uniqueContributors[BasicContributor{Email: "email1@gmail.com", Repo: "repo1"}].RepoLastCommit.Date)
					assert.Equal(t, "2023-06-21T10:00:00Z", uniqueContributors[BasicContributor{Email: "email2@gmail.com", Repo: "repo1"}].RepoLastCommit.Date)

				},
				detailedContributorsVerificationFunc: func(t *testing.T, detailedContributors map[string]map[string]ContributorDetailedSummary) {
					assert.Equal(t, 2, len(detailedContributors))
					assert.Equal(t, "2023-05-21T10:00:00Z", detailedContributors["email1@gmail.com"]["repo1"].LastCommit.Date)
					assert.Equal(t, "2023-06-21T10:00:00Z", detailedContributors["email2@gmail.com"]["repo1"].LastCommit.Date)
				},
				detailedReposVerificationFunc: func(t *testing.T, detailedRepos map[string]map[string]RepositoryDetailedSummary) {
					assert.Equal(t, 1, len(detailedRepos))
					assert.Equal(t, "2023-06-21T10:00:00Z", detailedRepos["repo1"]["email2@gmail.com"].LastCommit.Date)
				},
			},
		},
	}
	gc := &VcsCountContributors{params: CountContributorsParams{DetailedSummery: true}}
	uniqueContributors := make(map[BasicContributor]Contributor)
	detailedContributors := make(map[string]map[string]ContributorDetailedSummary)
	detailedRepos := make(map[string]map[string]RepositoryDetailedSummary)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gc.saveCommitsInfoInMaps(tt.args.repoName, tt.args.commits, uniqueContributors, detailedContributors, detailedRepos)
			tt.args.uniqueContributorsVerificationFunc(t, uniqueContributors)
			tt.args.detailedContributorsVerificationFunc(t, detailedContributors)
			tt.args.detailedReposVerificationFunc(t, detailedRepos)
		})
	}
}

func TestCountContributorsCommand_saveCommitsInfoInMaps_MultipleRepos(t *testing.T) {
	type commitsRepo struct {
		repoName string
		commits  []vcsclient.CommitInfo
	}
	type args struct {
		commitsRepo                          []commitsRepo
		uniqueContributorsVerificationFunc   func(t *testing.T, uniqueContributors []Contributor)
		detailedContributorsVerificationFunc func(t *testing.T, detailedContributors map[string][]ContributorDetailedSummary)
		detailedReposVerificationFunc        func(t *testing.T, detailedRepos map[string][]RepositoryDetailedSummary)
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "no commits",
			args: args{
				commitsRepo: []commitsRepo{{repoName: "repo1", commits: []vcsclient.CommitInfo{}}, {repoName: "repo2", commits: []vcsclient.CommitInfo{}}},
				uniqueContributorsVerificationFunc: func(t *testing.T, uniqueContributors []Contributor) {
					assert.Equal(t, 0, len(uniqueContributors))
				},
				detailedContributorsVerificationFunc: func(t *testing.T, detailedContributors map[string][]ContributorDetailedSummary) {
					assert.Equal(t, 0, len(detailedContributors))
				},
				detailedReposVerificationFunc: func(t *testing.T, detailedRepos map[string][]RepositoryDetailedSummary) {
					assert.Equal(t, 0, len(detailedRepos))
				},
			},
		},
		{
			name: "1 repo with commits and one without",
			args: args{
				commitsRepo: []commitsRepo{{repoName: "repo1", commits: []vcsclient.CommitInfo{}}, {repoName: "repo2", commits: getCommitsListForTest(t)}},
				uniqueContributorsVerificationFunc: func(t *testing.T, uniqueContributors []Contributor) {
					assert.Equal(t, 2, len(uniqueContributors))
					expectedContributors := []Contributor{
						{
							Email: "email1@gmail.com",
							RepoLastCommit: RepoLastCommit{
								LastCommit: LastCommit{
									Date: "2023-05-21T10:00:00Z",
								},
								Repo: "repo2",
							},
						},
						{
							Email: "email2@gmail.com",
							RepoLastCommit: RepoLastCommit{
								LastCommit: LastCommit{
									Date: "2023-06-21T10:00:00Z",
								},
								Repo: "repo2",
							},
						},
					}
					for _, expectedContributor := range expectedContributors {
						assert.Contains(t, uniqueContributors, expectedContributor)
					}

				},
				detailedContributorsVerificationFunc: func(t *testing.T, detailedContributors map[string][]ContributorDetailedSummary) {
					assert.Equal(t, 2, len(detailedContributors))
					expectedContributors := map[string]ContributorDetailedSummary{
						"email1@gmail.com": {
							RepoPath: "repo2",
							LastCommit: LastCommit{
								Date: "2023-05-21T10:00:00Z",
							},
						},
						"email2@gmail.com": {
							RepoPath: "repo2",
							LastCommit: LastCommit{
								Date: "2023-06-21T10:00:00Z",
							},
						},
					}
					for email, expectedContributor := range expectedContributors {
						assert.Contains(t, detailedContributors, email)
						assert.Contains(t, detailedContributors[email], expectedContributor)
					}
				},
				detailedReposVerificationFunc: func(t *testing.T, detailedRepos map[string][]RepositoryDetailedSummary) {
					assert.Equal(t, 1, len(detailedRepos))
					expectedRepos := map[string]RepositoryDetailedSummary{
						"email1@gmail.com": {
							Email: "email1@gmail.com",
							LastCommit: LastCommit{
								Date: "2023-05-21T10:00:00Z",
							},
						},
						"email2@gmail.com": {
							Email: "email2@gmail.com",
							LastCommit: LastCommit{
								Date: "2023-06-21T10:00:00Z",
							},
						},
					}
					for _, expectedRepo := range expectedRepos {
						assert.Contains(t, detailedRepos["repo2"], expectedRepo)
					}
				},
			},
		},
		{"2 repos with authors and commits.",
			args{
				commitsRepo: []commitsRepo{
					{repoName: "repo1", commits: getCommitsListForTest(t)},
					{repoName: "repo2", commits: []vcsclient.CommitInfo{
						{
							AuthorEmail: "email2@gmail.com",
							Timestamp:   convertDateStrToTimestamp(t, "2023-07-21T10:00:00Z"),
						},
					}},
				},
				uniqueContributorsVerificationFunc: func(t *testing.T, uniqueContributors []Contributor) {
					assert.Equal(t, 2, len(uniqueContributors))
					expectedContributors := []Contributor{
						{
							Email: "email1@gmail.com",
							RepoLastCommit: RepoLastCommit{
								LastCommit: LastCommit{
									Date: "2023-05-21T10:00:00Z",
								},
								Repo: "repo1",
							},
						},
						{
							Email: "email2@gmail.com",
							RepoLastCommit: RepoLastCommit{
								LastCommit: LastCommit{
									Date: "2023-07-21T10:00:00Z",
								},
								Repo: "repo2",
							},
						},
					}
					for _, expectedContributor := range expectedContributors {
						assert.Contains(t, uniqueContributors, expectedContributor)
					}

				},
				detailedContributorsVerificationFunc: func(t *testing.T, detailedContributors map[string][]ContributorDetailedSummary) {
					assert.Equal(t, 2, len(detailedContributors))
					expectedContributors := map[string]ContributorDetailedSummary{
						"email1@gmail.com": {
							RepoPath: "repo1",
							LastCommit: LastCommit{
								Date: "2023-05-21T10:00:00Z",
							},
						},
						"email2@gmail.com": {
							RepoPath: "repo2",
							LastCommit: LastCommit{
								Date: "2023-07-21T10:00:00Z",
							},
						},
					}
					for email, expectedContributor := range expectedContributors {
						assert.Contains(t, detailedContributors, email)
						assert.Contains(t, detailedContributors[email], expectedContributor)
					}
				},
				detailedReposVerificationFunc: func(t *testing.T, detailedRepos map[string][]RepositoryDetailedSummary) {
					assert.Equal(t, 2, len(detailedRepos))
					expectedRepos := map[string]RepositoryDetailedSummary{
						"email1@gmail.com": {
							Email: "email1@gmail.com",
							LastCommit: LastCommit{
								Date: "2023-05-21T10:00:00Z",
							},
						},
						"email2@gmail.com": {
							Email: "email2@gmail.com",
							LastCommit: LastCommit{
								Date: "2023-06-21T10:00:00Z",
							},
						},
					}
					for _, expectedRepo := range expectedRepos {
						assert.Contains(t, detailedRepos["repo1"], expectedRepo)
					}
					expectedRepos = map[string]RepositoryDetailedSummary{
						"email2@gmail.com": {
							Email: "email2@gmail.com",
							LastCommit: LastCommit{
								Date: "2023-07-21T10:00:00Z",
							},
						},
					}
					for _, expectedRepo := range expectedRepos {
						assert.Contains(t, detailedRepos["repo2"], expectedRepo)
					}
				},
			},
		},
	}

	cc := &CountContributorsCommand{CountContributorsParams: CountContributorsParams{DetailedSummery: true}}
	vcc, err := cc.getVcsCountContributors()
	assert.NoError(t, err)
	assert.Equal(t, 1, len(vcc))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uniqueContributors := make(map[BasicContributor]Contributor)
			detailedContributors := make(map[string]map[string]ContributorDetailedSummary)
			detailedRepos := make(map[string]map[string]RepositoryDetailedSummary)

			for _, it := range tt.args.commitsRepo {
				vcc[0].saveCommitsInfoInMaps(it.repoName, it.commits, uniqueContributors, detailedContributors, detailedRepos)
			}
			report := cc.aggregateReportResults(uniqueContributors, detailedContributors, detailedRepos)
			tt.args.uniqueContributorsVerificationFunc(t, report.UniqueContributorsList)
			tt.args.detailedContributorsVerificationFunc(t, report.DetailedContributorsList)
			tt.args.detailedReposVerificationFunc(t, report.DetailedReposList)
		})
	}
}

func convertDateStrToTimestamp(t *testing.T, dateStr string) int64 {
	date, err := time.Parse(time.RFC3339, dateStr)
	assert.NoError(t, err)
	return date.Unix()
}

func TestCountContributorsCommand_InputFile(t *testing.T) {
	type args struct {
		inputFile        string
		gitServersNumber int
		expectedError    string
		expectedResult   []BasicGitServerParams
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "empty list",
			args: args{
				inputFile:        "empty_list.yaml",
				gitServersNumber: 0,
				expectedError:    "no git servers data was provided in the input file",
			},
		},
		{
			name: "one git server",
			args: args{
				inputFile:        "one_server.yaml",
				gitServersNumber: 1,
				expectedError:    "",
				expectedResult:   []BasicGitServerParams{{ScmType: vcsutils.GitHub, ScmApiUrl: "https://api.github.com", Token: "token", Owner: "owner", Repositories: []string{"repo1"}}},
			},
		},
		{
			name: "multiple servers",
			args: args{
				inputFile:        "multiple_servers.yaml",
				gitServersNumber: 2,
				expectedError:    "",
				expectedResult: []BasicGitServerParams{
					{ScmType: vcsutils.BitbucketServer, ScmApiUrl: "https://api.bitbucket.url", Token: "token", Owner: "owner", Repositories: []string{"repo1", "repo2"}},
					{ScmType: vcsutils.GitLab, ScmApiUrl: "https://api.gitlab.com", Token: "token", Owner: "owner", Repositories: []string{}},
				},
			},
		},
		{
			name: "bad scm type",
			args: args{
				inputFile:        "bad_scm_type.yaml",
				gitServersNumber: 0,
				expectedError:    "invalid VcsProvider",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputFilePath := path.Join(GetTestDataPath(), "inputfiles", tt.args.inputFile)
			cc := &CountContributorsCommand{CountContributorsParams: CountContributorsParams{InputFile: inputFilePath}}
			vcc, err := cc.getVcsCountContributors()
			assert.Equal(t, tt.args.gitServersNumber, len(vcc))
			if tt.args.expectedError != "" {
				assert.ErrorContains(t, err, tt.args.expectedError)
			} else {
				reflect.DeepEqual(tt.args.expectedResult, vcc)
			}
		})
	}
}
