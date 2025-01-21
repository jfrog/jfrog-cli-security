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
				LastCommitHash:       "5fc36ff0666e5ce9dba6c0a1c539ee640cabe0b0",
				LastCommitMessage:    "remove json",
				LastCommitAuthor:     "attiasas",

				BranchName: "main",
			},
		},
		{
			name:                  "Self-Hosted Git Project (and SSO credentials)",
			testProjectZipDirPath: filepath.Join(basePath, "selfhosted"),
			gitInfo: &services.XscGitInfoContext{
				GitRepoHttpsCloneUrl: "ssh://git@git.jfrog.info/~assafa/test-security-git.git",
				GitRepoName:          "test-security-git",
				// TODO: maybe detect provider as bb if ~ in the project name
				GitProject:        "~assafa",
				BranchName:        "main",
				LastCommitHash:    "6abd0162f4e02e358124f74e89b30d1b1ff906bc",
				LastCommitMessage: "initial commit",
				LastCommitAuthor:  "attiasas",
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
			// 	LastCommitUrl:     "5fc36ff0666e5ce9dba6c0a1c539ee640cabe0b0",
			// 	LastCommitMessage: "remove json",
			// 	LastCommitAuthor:  "attiasas",

			// 	BranchName: "dirty_branch",
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
			} else if err != nil {
				// Assert multiple remotes error
				assert.Error(t, err, "multiple (2) remotes found, currently only one remote is supported, remotes: origin, upstream")
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
