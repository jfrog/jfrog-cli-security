package git

import (
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/stretchr/testify/assert"
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
	gc := &CountContributorsCommand{CountContributorsParams: CountContributorsParams{DetailedSummery: true}}
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
		{name: "1 repo with commits and one without",
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
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uniqueContributors := make(map[BasicContributor]Contributor)
			detailedContributors := make(map[string]map[string]ContributorDetailedSummary)
			detailedRepos := make(map[string]map[string]RepositoryDetailedSummary)

			for _, it := range tt.args.commitsRepo {
				cc.saveCommitsInfoInMaps(it.repoName, it.commits, uniqueContributors, detailedContributors, detailedRepos)
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
