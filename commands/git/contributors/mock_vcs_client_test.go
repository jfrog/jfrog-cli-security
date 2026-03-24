package contributors

import (
	"context"

	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
)

// mockVcsClient is a test implementation of vcsclient.VcsClient.
// Only GetCommitsWithQueryOptions and ListRepositories are configurable;
// all other methods return zero values and no error.
type mockVcsClient struct {
	getCommitsWithQueryOptionsFn func(ctx context.Context, owner, repo string, opts vcsclient.GitCommitsQueryOptions) ([]vcsclient.CommitInfo, error)
	listRepositoriesFn           func(ctx context.Context) (map[string][]string, error)
	listRepositoriesByOwnerFn    func(ctx context.Context, owner string) ([]string, error)
}

func (m *mockVcsClient) GetCommitsWithQueryOptions(ctx context.Context, owner, repository string, options vcsclient.GitCommitsQueryOptions) ([]vcsclient.CommitInfo, error) {
	if m.getCommitsWithQueryOptionsFn != nil {
		return m.getCommitsWithQueryOptionsFn(ctx, owner, repository, options)
	}
	return nil, nil
}

func (m *mockVcsClient) ListRepositories(ctx context.Context) (map[string][]string, error) {
	if m.listRepositoriesFn != nil {
		return m.listRepositoriesFn(ctx)
	}
	return nil, nil
}

func (m *mockVcsClient) ListRepositoriesByOwner(ctx context.Context, owner string) ([]string, error) {
	if m.listRepositoriesByOwnerFn != nil {
		return m.listRepositoriesByOwnerFn(ctx, owner)
	}
	return nil, nil
}

// Stub implementations for the remaining VcsClient interface methods.

func (m *mockVcsClient) TestConnection(_ context.Context) error { return nil }
func (m *mockVcsClient) ListAppRepositories(_ context.Context) ([]vcsclient.AppRepositoryInfo, error) {
	return nil, nil
}
func (m *mockVcsClient) ListBranches(_ context.Context, _, _ string) ([]string, error) {
	return nil, nil
}
func (m *mockVcsClient) CreateWebhook(_ context.Context, _, _, _, _ string, _ ...vcsutils.WebhookEvent) (string, string, error) {
	return "", "", nil
}
func (m *mockVcsClient) UpdateWebhook(_ context.Context, _, _, _, _, _, _ string, _ ...vcsutils.WebhookEvent) error {
	return nil
}
func (m *mockVcsClient) DeleteWebhook(_ context.Context, _, _, _ string) error { return nil }
func (m *mockVcsClient) SetCommitStatus(_ context.Context, _ vcsclient.CommitStatus, _, _, _, _, _, _ string) error {
	return nil
}
func (m *mockVcsClient) GetCommitStatuses(_ context.Context, _, _, _ string) ([]vcsclient.CommitStatusInfo, error) {
	return nil, nil
}
func (m *mockVcsClient) DownloadRepository(_ context.Context, _, _, _, _ string) error { return nil }
func (m *mockVcsClient) CreatePullRequest(_ context.Context, _, _, _, _, _, _ string) error {
	return nil
}
func (m *mockVcsClient) CreatePullRequestDetailed(_ context.Context, _, _, _, _, _, _ string) (vcsclient.CreatedPullRequestInfo, error) {
	return vcsclient.CreatedPullRequestInfo{}, nil
}
func (m *mockVcsClient) UpdatePullRequest(_ context.Context, _, _, _, _, _ string, _ int, _ vcsutils.PullRequestState) error {
	return nil
}
func (m *mockVcsClient) AddPullRequestComment(_ context.Context, _, _, _ string, _ int) error {
	return nil
}
func (m *mockVcsClient) AddPullRequestReviewComments(_ context.Context, _ string, _ string, _ int, _ ...vcsclient.PullRequestComment) error {
	return nil
}
func (m *mockVcsClient) ListPullRequestReviews(_ context.Context, _, _ string, _ int) ([]vcsclient.PullRequestReviewDetails, error) {
	return nil, nil
}
func (m *mockVcsClient) ListPullRequestReviewComments(_ context.Context, _, _ string, _ int) ([]vcsclient.CommentInfo, error) {
	return nil, nil
}
func (m *mockVcsClient) DeletePullRequestReviewComments(_ context.Context, _, _ string, _ int, _ ...vcsclient.CommentInfo) error {
	return nil
}
func (m *mockVcsClient) ListPullRequestComments(_ context.Context, _, _ string, _ int) ([]vcsclient.CommentInfo, error) {
	return nil, nil
}
func (m *mockVcsClient) DeletePullRequestComment(_ context.Context, _, _ string, _, _ int) error {
	return nil
}
func (m *mockVcsClient) ListOpenPullRequestsWithBody(_ context.Context, _, _ string) ([]vcsclient.PullRequestInfo, error) {
	return nil, nil
}
func (m *mockVcsClient) ListOpenPullRequests(_ context.Context, _, _ string) ([]vcsclient.PullRequestInfo, error) {
	return nil, nil
}
func (m *mockVcsClient) GetPullRequestByID(_ context.Context, _, _ string, _ int) (vcsclient.PullRequestInfo, error) {
	return vcsclient.PullRequestInfo{}, nil
}
func (m *mockVcsClient) GetLatestCommit(_ context.Context, _, _, _ string) (vcsclient.CommitInfo, error) {
	return vcsclient.CommitInfo{}, nil
}
func (m *mockVcsClient) GetCommits(_ context.Context, _, _, _ string) ([]vcsclient.CommitInfo, error) {
	return nil, nil
}
func (m *mockVcsClient) ListPullRequestsAssociatedWithCommit(_ context.Context, _, _, _ string) ([]vcsclient.PullRequestInfo, error) {
	return nil, nil
}
func (m *mockVcsClient) AddSshKeyToRepository(_ context.Context, _, _, _, _ string, _ vcsclient.Permission) error {
	return nil
}
func (m *mockVcsClient) GetRepositoryInfo(_ context.Context, _, _ string) (vcsclient.RepositoryInfo, error) {
	return vcsclient.RepositoryInfo{}, nil
}
func (m *mockVcsClient) GetCommitBySha(_ context.Context, _, _, _ string) (vcsclient.CommitInfo, error) {
	return vcsclient.CommitInfo{}, nil
}
func (m *mockVcsClient) CreateLabel(_ context.Context, _, _ string, _ vcsclient.LabelInfo) error {
	return nil
}
func (m *mockVcsClient) GetLabel(_ context.Context, _, _, _ string) (*vcsclient.LabelInfo, error) {
	return nil, nil
}
func (m *mockVcsClient) ListPullRequestLabels(_ context.Context, _, _ string, _ int) ([]string, error) {
	return nil, nil
}
func (m *mockVcsClient) UnlabelPullRequest(_ context.Context, _, _, _ string, _ int) error {
	return nil
}
func (m *mockVcsClient) UploadCodeScanning(_ context.Context, _, _, _, _ string) (string, error) {
	return "", nil
}
func (m *mockVcsClient) UploadCodeScanningWithRef(_ context.Context, _, _, _, _, _ string) (string, error) {
	return "", nil
}
func (m *mockVcsClient) DownloadFileFromRepo(_ context.Context, _, _, _, _ string) ([]byte, int, error) {
	return nil, 0, nil
}
func (m *mockVcsClient) GetRepositoryEnvironmentInfo(_ context.Context, _, _, _ string) (vcsclient.RepositoryEnvironmentInfo, error) {
	return vcsclient.RepositoryEnvironmentInfo{}, nil
}
func (m *mockVcsClient) GetModifiedFiles(_ context.Context, _, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (m *mockVcsClient) GetPullRequestCommentSizeLimit() int                     { return 0 }
func (m *mockVcsClient) GetPullRequestDetailsSizeLimit() int                     { return 0 }
func (m *mockVcsClient) CreateBranch(_ context.Context, _, _, _, _ string) error { return nil }
func (m *mockVcsClient) AllowWorkflows(_ context.Context, _ string) error        { return nil }
func (m *mockVcsClient) AddOrganizationSecret(_ context.Context, _, _, _ string) error {
	return nil
}
func (m *mockVcsClient) CreateOrgVariable(_ context.Context, _, _, _ string) error { return nil }
func (m *mockVcsClient) CommitAndPushFiles(_ context.Context, _, _, _, _, _, _ string, _ []vcsclient.FileToCommit) error {
	return nil
}
func (m *mockVcsClient) GetRepoCollaborators(_ context.Context, _, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (m *mockVcsClient) GetRepoTeamsByPermissions(_ context.Context, _, _ string, _ []string) ([]int64, error) {
	return nil, nil
}
func (m *mockVcsClient) CreateOrUpdateEnvironment(_ context.Context, _, _, _ string, _ []int64, _ []string) error {
	return nil
}
func (m *mockVcsClient) MergePullRequest(_ context.Context, _, _ string, _ int, _ string) error {
	return nil
}
func (m *mockVcsClient) UploadSnapshotToDependencyGraph(_ context.Context, _, _ string, _ *vcsclient.SbomSnapshot) error {
	return nil
}
