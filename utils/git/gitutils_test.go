package git

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"

	"github.com/jfrog/jfrog-client-go/xray/services"
)

func TestDetectGitInfo(t *testing.T) {
	basePath := filepath.Join("..", "..", "tests", "testdata", "git", "projects")

	testCases := []struct {
		name                  string
		testProjectZipDirPath string
		gitInfo               *services.XscGitInfoContext
	}{
		{
			name:                  "No Git Info",
			testProjectZipDirPath: filepath.Join(basePath, "nogit"),
		},
		{
			name:                  "Clean Project (after clone)",
			testProjectZipDirPath: filepath.Join(basePath, "clean"),
			gitInfo: &services.XscGitInfoContext{
				GitRepoUrl:    "https://github.com/attiasas/test-security-git.git",
				GitRepoName:   "test-security-git",
				GitProject:    "attiasas",
				GitProvider:   "github",
				BranchName:    "main",
				LastCommit:    "5fc36ff0666e5ce9dba6c0a1c539ee640cabe0b0",
				CommitHash:    "5fc36ff0666e5ce9dba6c0a1c539ee640cabe0b0",
				CommitMessage: "remove json",
				CommitAuthor:  "attiasas",
			},
		},
		{
			name:                  "Dirty Project (with uncommitted changes)",
			testProjectZipDirPath: filepath.Join(basePath, "dirty"),
			gitInfo: &services.XscGitInfoContext{
				GitRepoUrl:  "https://github.com/attiasas/test-security-git.git",
				GitRepoName: "test-security-git",
				GitProject:  "attiasas",
				GitProvider: "github",
				BranchName:  "dirty_branch",
				LastCommit:  "5fc36ff0666e5ce9dba6c0a1c539ee640cabe0b0",
			},
		},
		{
			name:                  "Self-Hosted Git Project (and SSO credentials)",
			testProjectZipDirPath: filepath.Join(basePath, "selfhosted"),
			gitInfo: &services.XscGitInfoContext{
				GitRepoUrl:  "ssh://git@git.jfrog.info/~assafa/test-security-git.git",
				GitRepoName: "test-security-git",
				// TODO: maybe detect provider as bb if ~ in the project name
				GitProject:    "~assafa",
				BranchName:    "main",
				LastCommit:    "6abd0162f4e02e358124f74e89b30d1b1ff906bc",
				CommitHash:    "6abd0162f4e02e358124f74e89b30d1b1ff906bc",
				CommitMessage: "initial commit",
				CommitAuthor:  "attiasas",
			},
		},
		// {
		// 	name:                  "Forked Project (multiple remotes)",
		// },
		// {
		// 	name:                  "GitLab Project" ,
		// },
		// {
		// 	name:                  "Azure Project",
		// },
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Prepare the test environment
			// mockServer, serverDetails := validations.XrayServer(t, utils.EntitlementsMinVersion)
			// defer mockServer.Close()
			// Create the project from the zip (since we need .git folder and .gitignore file is present in the repository)
			_, cleanUp := securityTestUtils.CreateTestProjectFromZipAndChdir(t, testCase.testProjectZipDirPath)
			defer cleanUp()
			// Create the command
			// gitAuditCmd := NewGitAuditCommand(sourceAudit.NewGenericAuditCommand())
			// gitAuditCmd.SetWorkingDirs([]string{projectPath}).SetServerDetails(serverDetails)
			// Run the test
			gitManager, gitInfo, err := DetectGitInfo()
			if testCase.gitInfo == nil {
				// Assert the expected error
				assert.Error(t, err)
				assert.Nil(t, gitInfo)
				assert.Nil(t, gitManager)
				return
			}
			// Assert the expected git info
			require.NoError(t, err)
			assert.NotNil(t, gitManager)
			assert.Equal(t, testCase.gitInfo, gitInfo)
		})
	}
}
