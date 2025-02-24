package scm

import (
	"path/filepath"
	"testing"

	goGit "github.com/go-git/go-git/v5"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"

	"github.com/jfrog/jfrog-client-go/xsc/services"
)

func TestGetGitContext(t *testing.T) {
	basePath := filepath.Join("..", "..", "tests", "testdata", "git", "projects")

	testCases := []struct {
		name                  string
		testProjectZipDirPath string
		NoDotGitFolder        bool
		gitInfo               *services.XscGitInfoContext
	}{
		{
			name:                  "No Git Info",
			NoDotGitFolder:        true,
			testProjectZipDirPath: filepath.Join(basePath, "nogit"),
		},
		{
			name:                  "Clean Project (after clone)",
			testProjectZipDirPath: filepath.Join(basePath, "clean"),
			gitInfo: &services.XscGitInfoContext{
				Source: services.CommitContext{
					GitRepoHttpsCloneUrl: "https://github.com/attiasas/test-security-git.git",
					GitRepoName:          "test-security-git",
					GitProject:           "attiasas",
					BranchName:           "main",
					CommitHash:           "5fc36ff0666e5ce9dba6c0a1c539ee640cabe0b0",
					CommitMessage:        "remove json",
					CommitAuthor:         "attiasas",
				},
				GitProvider: "github",
			},
		},
		{
			name:                  "Self-Hosted Git Project (and SSO credentials)",
			testProjectZipDirPath: filepath.Join(basePath, "selfhosted"),
			gitInfo: &services.XscGitInfoContext{
				Source: services.CommitContext{
					GitRepoHttpsCloneUrl: "ssh://git@git.jfrog.info/~assafa/test-security-git.git",
					GitRepoName:          "test-security-git",
					GitProject:           "~assafa",
					BranchName:           "main",
					CommitHash:           "6abd0162f4e02e358124f74e89b30d1b1ff906bc",
					CommitMessage:        "initial commit",
					CommitAuthor:         "attiasas",
				},
				GitProvider: "bitbucket",
			},
		},
		{
			name:                  "Gitlab Project (group tree structure)",
			testProjectZipDirPath: filepath.Join(basePath, "gitlab"),
			gitInfo: &services.XscGitInfoContext{
				Source: services.CommitContext{
					GitRepoHttpsCloneUrl: "https://gitlab.com/attiasas/test-group/test-security-git.git",
					GitRepoName:          "test-security-git",
					GitProject:           "attiasas/test-group",
					BranchName:           "main",
					CommitHash:           "ada14e9f525d8cbfb3c8c31ebe345d85ec342480",
					CommitMessage:        "add npm",
					CommitAuthor:         "attiasas",
				},
				GitProvider: "gitlab",
			},
		},
		{
			name:                  "Gerrit Project (no owner)",
			testProjectZipDirPath: filepath.Join(basePath, "gerrit"),
			gitInfo: &services.XscGitInfoContext{
				Source: services.CommitContext{
					GitRepoHttpsCloneUrl: "https://gerrit.googlesource.com/git-repo",
					GitRepoName:          "git-repo",
					GitProject:           "git-repo",
					BranchName:           "main",
					CommitHash:           "a532f57a1f20623f5b9dd022493141a5b2a71009",
					CommitMessage:        `clean project`,
					CommitAuthor:         "attiasas",
				},
				GitProvider: "gerrit",
			},
		},
		{
			name:                  "Forked Project (multiple remotes)",
			testProjectZipDirPath: filepath.Join(basePath, "forked"),
			gitInfo: &services.XscGitInfoContext{
				Source: services.CommitContext{
					GitRepoHttpsCloneUrl: "https://github.com/attiasas/test-security-git.git",
					GitRepoName:          "test-security-git",
					GitProject:           "attiasas",
					BranchName:           "main",
					CommitHash:           "5fc36ff0666e5ce9dba6c0a1c539ee640cabe0b0",
					CommitMessage:        "remove json",
					CommitAuthor:         "attiasas",
				},
				GitProvider: "github",
			},
		},
		// Not supported yet
		{
			name:                  "Dirty Project (with uncommitted changes)",
			testProjectZipDirPath: filepath.Join(basePath, "dirty"),
			// gitInfo: &services.XscGitInfoContext{
			// 	GitRepoHttpsCloneUrl:        "https://github.com/attiasas/test-security-git.git",
			// 	GitRepoName:       "test-security-git",
			// 	GitProject:        "attiasas",
			// 	GitProvider:       "github",
			// 	BranchName: "dirty_branch",
			// 	LastCommitUrl:     "5fc36ff0666e5ce9dba6c0a1c539ee640cabe0b0",
			// 	LastCommitMessage: "remove json",
			// 	LastCommitAuthor:  "attiasas",
			// },
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Create the project from the zip (since we need .git folder and .gitignore file is present in the repository)
			_, cleanUp := securityTestUtils.CreateTestProjectFromZipAndChdir(t, testCase.testProjectZipDirPath)
			defer cleanUp()
			// Run the test
			gitManager, err := NewGitManager(".")
			if testCase.NoDotGitFolder {
				// Assert no git info
				assert.Error(t, err, goGit.ErrRepositoryNotExists.Error())
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, gitManager)
			gitInfo, err := gitManager.GetSourceControlContext()

			if testCase.gitInfo == nil {
				// Dirty project, we can't assert the git info
				assert.Error(t, err)
				assert.Nil(t, gitInfo)
				return
			}
			// Assert the expected git info
			require.NoError(t, err)
			assert.Equal(t, testCase.gitInfo, gitInfo)
		})
	}
}

func TestGetGitProvider(t *testing.T) {
	testCases := []struct {
		name     string
		url      string
		provider ScProvider
	}{
		{
			name:     "Github",
			url:      "https://github.com/attiasas/test-security-git.git",
			provider: Github,
		},
		{
			name:     "Bitbucket",
			url:      "https://git.id.info/scm/repo-name/repo-name.git",
			provider: Bitbucket,
		},
		{
			name:     "Bitbucket SSH",
			url:      "ssh://git@git.jfrog.info/~assafa/test-security-git.git",
			provider: Bitbucket,
		},
		{
			name:     "Gitlab",
			url:      "https://gitlab.com/attiasas/test-group/test-security-git.git",
			provider: Gitlab,
		},
		{
			name:     "Azure",
			url:      "https://dev.azure.com/attiasas/test-security-git/_git/test-security-git",
			provider: Azure,
		},
		{
			name:     "Gerrit",
			url:      "https://gerrit.googlesource.com/git-repo",
			provider: Gerrit,
		},
		{
			name:     "Gitea",
			url:      "https://gitea.com/gitea/helm-chart.git",
			provider: Gitea,
		},
		{
			name:     "AWS CodeCommit",
			url:      "https://git-codecommit.us-west-2.amazonaws.com/v1/repos/test-repo",
			provider: AWSCodeCommit,
		},
		{
			name:     "Unknown",
			url:      "ssh://git@git.jfrog.info/assafa/test-security-git.git",
			provider: Unknown,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			provider := getGitProvider(testCase.url)
			assert.Equal(t, testCase.provider, provider)
		})
	}
}

func TestGetGitProject(t *testing.T) {
	testCases := []struct {
		name    string
		url     string
		project string
	}{
		{
			name:    "Https",
			url:     "https://github.com/attiasas/test-security-git.git",
			project: "attiasas",
		},
		{
			name:    "SSH",
			url:     "git@github.com:jfrog/jfrog-cli-security.git",
			project: "jfrog-cli-security",
		},
		{
			name:    "Bitbucket Https",
			url:     "https://git.id.info/scm/repo-name/repo-name.git",
			project: "repo-name",
		},
		{
			name:    "Gitlab Project (group tree structure)",
			url:     "https://gitlab.com/attiasas/test-group/test-security-git.git",
			project: "attiasas/test-group",
		},
		{
			name:    "Bitbucket SSH",
			url:     "ssh://git@git.jfrog.info/~assafa/test-security-git.git",
			project: "~assafa",
		},
		{
			name:    "Gerrit - No project name",
			url:     "https://gerrit.googlesource.com/git-repo",
			project: "git-repo",
		},
		{
			name:    "codecommit",
			url:     "https://git-codecommit.us-west-2.amazonaws.com/v1/repos/test-repo",
			project: "test-repo",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			project := getGitProject(testCase.url)
			assert.Equal(t, testCase.project, project)
		})
	}
}
