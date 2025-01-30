package gitutils

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
				GitRepoHttpsCloneUrl: "https://github.com/attiasas/test-security-git.git",
				GitRepoName:          "test-security-git",
				GitProject:           "attiasas",
				GitProvider:          "github",
				BranchName:           "main",
				LastCommitHash:       "5fc36ff0666e5ce9dba6c0a1c539ee640cabe0b0",
				LastCommitMessage:    "remove json",
				LastCommitAuthor:     "attiasas",
			},
		},
		{
			name:                  "Self-Hosted Git Project (and SSO credentials)",
			testProjectZipDirPath: filepath.Join(basePath, "selfhosted"),
			gitInfo: &services.XscGitInfoContext{
				GitRepoHttpsCloneUrl: "ssh://git@git.jfrog.info/~assafa/test-security-git.git",
				GitRepoName:          "test-security-git",
				GitProject:           "~assafa",
				GitProvider:          "bitbucket",
				BranchName:           "main",
				LastCommitHash:       "6abd0162f4e02e358124f74e89b30d1b1ff906bc",
				LastCommitMessage:    "initial commit",
				LastCommitAuthor:     "attiasas",
			},
		},
		{
			name:                  "Gitlab Project (group tree structure)",
			testProjectZipDirPath: filepath.Join(basePath, "gitlab"),
			gitInfo: &services.XscGitInfoContext{
				GitRepoHttpsCloneUrl: "https://gitlab.com/attiasas/test-group/test-security-git.git",
				GitRepoName:          "test-security-git",
				GitProject:           "attiasas",
				GitProvider:          "gitlab",
				BranchName:           "main",
				LastCommitHash:       "ada14e9f525d8cbfb3c8c31ebe345d85ec342480",
				LastCommitMessage:    "add npm",
				LastCommitAuthor:     "attiasas",
			},
		},
		{
			name:                  "Forked Project (multiple remotes)",
			testProjectZipDirPath: filepath.Join(basePath, "forked"),
			gitInfo: &services.XscGitInfoContext{
				GitRepoHttpsCloneUrl: "https://github.com/attiasas/test-security-git.git",
				GitRepoName:          "test-security-git",
				GitProject:           "attiasas",
				GitProvider:          "github",
				BranchName:           "main",
				LastCommitHash:       "5fc36ff0666e5ce9dba6c0a1c539ee640cabe0b0",
				LastCommitMessage:    "remove json",
				LastCommitAuthor:     "attiasas",
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
			gitInfo, err := gitManager.GetGitContext()

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
		provider GitProvider
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
			name:    "Bitbucket SSH",
			url:     "ssh://git@git.jfrog.info/~assafa/test-security-git.git",
			project: "~assafa",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			project := getGitProject(testCase.url)
			assert.Equal(t, testCase.project, project)
		})
	}
}
