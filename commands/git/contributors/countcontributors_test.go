package contributors

import (
	"context"
	"sort"
	"time"

	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
	"path"
	"path/filepath"
	"reflect"
	"testing"
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

// ---- merge helpers tests ----

func TestMergeContributors(t *testing.T) {
	key1 := BasicContributor{Email: "a@example.com", Repo: "repo1"}
	key2 := BasicContributor{Email: "b@example.com", Repo: "repo1"}

	contrib1 := Contributor{Email: "a@example.com", Name: "A"}
	contrib2 := Contributor{Email: "b@example.com", Name: "B"}
	contrib1Alt := Contributor{Email: "a@example.com", Name: "A-alt"}

	t.Run("empty src", func(t *testing.T) {
		dst := map[BasicContributor]Contributor{key1: contrib1}
		mergeContributors(dst, map[BasicContributor]Contributor{})
		assert.Equal(t, contrib1, dst[key1])
		assert.Len(t, dst, 1)
	})
	t.Run("non-overlapping keys merged", func(t *testing.T) {
		dst := map[BasicContributor]Contributor{key1: contrib1}
		mergeContributors(dst, map[BasicContributor]Contributor{key2: contrib2})
		assert.Equal(t, contrib1, dst[key1])
		assert.Equal(t, contrib2, dst[key2])
	})
	t.Run("collision: dst wins", func(t *testing.T) {
		dst := map[BasicContributor]Contributor{key1: contrib1}
		mergeContributors(dst, map[BasicContributor]Contributor{key1: contrib1Alt})
		assert.Equal(t, contrib1, dst[key1], "existing entry should not be overwritten")
	})
}

func TestMergeDetailedContributors(t *testing.T) {
	detail1 := ContributorDetailedSummary{RepoPath: "repo1", LastCommit: LastCommit{Date: "2024-01-01T00:00:00Z"}}
	detail2 := ContributorDetailedSummary{RepoPath: "repo2", LastCommit: LastCommit{Date: "2024-02-01T00:00:00Z"}}
	detailAlt := ContributorDetailedSummary{RepoPath: "repo1", LastCommit: LastCommit{Date: "2024-03-01T00:00:00Z"}}

	t.Run("empty src", func(t *testing.T) {
		dst := map[string]map[string]ContributorDetailedSummary{
			"alice": {"repo1": detail1},
		}
		mergeDetailedContributors(dst, map[string]map[string]ContributorDetailedSummary{})
		assert.Equal(t, detail1, dst["alice"]["repo1"])
	})
	t.Run("new email and new repo merged", func(t *testing.T) {
		dst := map[string]map[string]ContributorDetailedSummary{
			"alice": {"repo1": detail1},
		}
		src := map[string]map[string]ContributorDetailedSummary{
			"alice": {"repo2": detail2},
			"bob":   {"repo1": detail1},
		}
		mergeDetailedContributors(dst, src)
		assert.Equal(t, detail2, dst["alice"]["repo2"])
		assert.Equal(t, detail1, dst["bob"]["repo1"])
	})
	t.Run("collision: dst wins", func(t *testing.T) {
		dst := map[string]map[string]ContributorDetailedSummary{
			"alice": {"repo1": detail1},
		}
		mergeDetailedContributors(dst, map[string]map[string]ContributorDetailedSummary{
			"alice": {"repo1": detailAlt},
		})
		assert.Equal(t, detail1, dst["alice"]["repo1"], "existing entry should not be overwritten")
	})
}

func TestMergeDetailedRepos(t *testing.T) {
	summary1 := RepositoryDetailedSummary{Email: "alice@example.com", LastCommit: LastCommit{Date: "2024-01-01T00:00:00Z"}}
	summary2 := RepositoryDetailedSummary{Email: "bob@example.com", LastCommit: LastCommit{Date: "2024-02-01T00:00:00Z"}}
	summaryAlt := RepositoryDetailedSummary{Email: "alice@example.com", LastCommit: LastCommit{Date: "2024-03-01T00:00:00Z"}}

	t.Run("empty src", func(t *testing.T) {
		dst := map[string]map[string]RepositoryDetailedSummary{
			"repo1": {"alice@example.com": summary1},
		}
		mergeDetailedRepos(dst, map[string]map[string]RepositoryDetailedSummary{})
		assert.Equal(t, summary1, dst["repo1"]["alice@example.com"])
	})
	t.Run("new repo and new author merged", func(t *testing.T) {
		dst := map[string]map[string]RepositoryDetailedSummary{
			"repo1": {"alice@example.com": summary1},
		}
		src := map[string]map[string]RepositoryDetailedSummary{
			"repo1": {"bob@example.com": summary2},
			"repo2": {"alice@example.com": summary1},
		}
		mergeDetailedRepos(dst, src)
		assert.Equal(t, summary2, dst["repo1"]["bob@example.com"])
		assert.Equal(t, summary1, dst["repo2"]["alice@example.com"])
	})
	t.Run("collision: dst wins", func(t *testing.T) {
		dst := map[string]map[string]RepositoryDetailedSummary{
			"repo1": {"alice@example.com": summary1},
		}
		mergeDetailedRepos(dst, map[string]map[string]RepositoryDetailedSummary{
			"repo1": {"alice@example.com": summaryAlt},
		})
		assert.Equal(t, summary1, dst["repo1"]["alice@example.com"], "existing entry should not be overwritten")
	})
}

// ---- parallel scan test ----

func TestScanAndCollectCommitsInfo_Parallel(t *testing.T) {
	ts1 := convertDateStrToTimestamp(t, "2024-01-10T10:00:00Z")
	ts2 := convertDateStrToTimestamp(t, "2024-02-10T10:00:00Z")
	ts3 := convertDateStrToTimestamp(t, "2024-03-10T10:00:00Z")
	ts4 := convertDateStrToTimestamp(t, "2024-04-10T10:00:00Z")

	commitsByRepo := map[string][]vcsclient.CommitInfo{
		"repo1": {
			{AuthorEmail: "email1@example.com", AuthorName: "Email1", Timestamp: ts1},
			{AuthorEmail: "email2@example.com", AuthorName: "Email2", Timestamp: ts2},
		},
		"repo2": {
			{AuthorEmail: "email2@example.com", AuthorName: "Email2", Timestamp: ts3},
			{AuthorEmail: "email3@example.com", AuthorName: "Email3", Timestamp: ts4},
		},
		"repo3": {},
	}

	mock := &mockVcsClient{
		getCommitsWithQueryOptionsFn: func(_ context.Context, _, repo string, opts vcsclient.GitCommitsQueryOptions) ([]vcsclient.CommitInfo, error) {
			// Return commits only on page 1; empty on subsequent pages to stop pagination.
			if opts.Page == 1 {
				return commitsByRepo[repo], nil
			}
			return nil, nil
		},
	}

	vcc := VcsCountContributors{
		vcsClient: mock,
		params: CountContributorsParams{
			BasicGitServerParams: BasicGitServerParams{Owner: "test-owner"},
			MonthsNum:            1,
			Threads:              3,
			CacheValidity:        -1, // disable cache
		},
	}

	baseOptions := vcsclient.GitCommitsQueryOptions{
		Since:       time.Now().AddDate(0, -1, 0),
		ListOptions: vcsclient.ListOptions{Page: 1, PerPage: vcsutils.NumberOfCommitsToFetch},
	}
	repos := []string{"repo1", "repo2", "repo3"}
	tasks := make([]repoScanTask, len(repos))
	for i, repo := range repos {
		tasks[i] = repoScanTask{vcc: vcc, repo: repo, baseOptions: baseOptions, idx: i}
	}

	repoResults, err := runRepoScanTasks(tasks, 3)
	assert.NoError(t, err)

	// Merge results the same way Run() does.
	var scannedRepos, skippedRepos []string
	uniqueContributors := make(map[BasicContributor]Contributor)
	totalCommits := 0
	for _, rr := range repoResults {
		if rr.skipped {
			skippedRepos = append(skippedRepos, rr.repo)
		} else {
			scannedRepos = append(scannedRepos, rr.repo)
			totalCommits += rr.totalCommits
			mergeContributors(uniqueContributors, rr.uniqueContributors)
		}
	}

	// All three repos should be scanned (none skipped).
	sort.Strings(scannedRepos)
	assert.Equal(t, []string{"repo1", "repo2", "repo3"}, scannedRepos)
	assert.Empty(t, skippedRepos)

	// repo1 has 2 commits, repo2 has 2, repo3 has 0.
	assert.Equal(t, 4, totalCommits)

	// 4 unique (email, repo) pairs: email1+repo1, email2+repo1, email2+repo2, email3+repo2.
	assert.Len(t, uniqueContributors, 4)
	assert.Contains(t, uniqueContributors, BasicContributor{Email: "email1@example.com", Repo: "repo1"})
	assert.Contains(t, uniqueContributors, BasicContributor{Email: "email2@example.com", Repo: "repo1"})
	assert.Contains(t, uniqueContributors, BasicContributor{Email: "email2@example.com", Repo: "repo2"})
	assert.Contains(t, uniqueContributors, BasicContributor{Email: "email3@example.com", Repo: "repo2"})
}

// ---- helpers ----

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
		{
			name: "missing owner",
			args: args{
				inputFile:        "missing_owner.yaml",
				gitServersNumber: 0,
				expectedError:    "owner is missing in the input file",
			},
		},
		{
			name: "missing token",
			args: args{
				inputFile:        "missing_token.yaml",
				gitServersNumber: 0,
				expectedError:    "token is missing in the input file",
			},
		},
		{
			name: "missing scm-api-url",
			args: args{
				inputFile:        "missing_scm_api_url.yaml",
				gitServersNumber: 0,
				expectedError:    "scm-api-url is missing in the input file",
			},
		},
		{
			name: "missing scm-type",
			args: args{
				inputFile:        "missing_scm_type.yaml",
				gitServersNumber: 0,
				expectedError:    "scm-type is missing in the input file",
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
