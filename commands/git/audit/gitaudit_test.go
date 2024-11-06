package audit

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sourceAudit "github.com/jfrog/jfrog-cli-security/commands/audit"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/validations"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

func TestInferGitInfo(t *testing.T) {
	testCases := []struct {
		name                  string
		testProjectZipDirPath string
		gitInfo               *services.XscGitInfoContext
	}{
		{
			name:                  "No Git Info",
			testProjectZipDirPath: filepath.Join("..", "..", "..", "tests", "testdata", "git", "projects", "nogit"),
		},
		{
			name:                  "Clean Project (after clone)",
			testProjectZipDirPath: filepath.Join("..", "..", "..", "tests", "testdata", "git", "projects", "clean"),
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
		// {
		// 	name:                  "Forked Project (get the root remote details)",
			
		// }
		{
			name:                  "Dirty Project (with uncommitted changes)",
			testProjectZipDirPath: filepath.Join("..", "..", "..", "tests", "testdata", "git", "projects", "dirty"),
			gitInfo: &services.XscGitInfoContext{
				GitRepoUrl:   "https://github.com/attiasas/test-security-git.git",
				GitRepoName:  "test-security-git",
				GitProject:   "attiasas",
				GitProvider:  "github",
				BranchName:   "main",
				LastCommit:   "5fc36ff0666e5ce9dba6c0a1c539ee640cabe0b0",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Prepare the test environment
			mockServer, serverDetails := validations.XrayServer(t, utils.EntitlementsMinVersion)
			defer mockServer.Close()
			// Create the project from the zip (since we need .git folder and .gitignore file is present in the repository)
			projectPath, cleanUp := securityTestUtils.CreateTestProjectFromZipAndChdir(t, testCase.testProjectZipDirPath)
			defer cleanUp()
			// Create the command
			gitAuditCmd := NewGitAuditCommand(sourceAudit.NewGenericAuditCommand())
			gitAuditCmd.SetWorkingDirs([]string{projectPath}).SetServerDetails(serverDetails)
			// Run the test
			gitInfo, err := gitAuditCmd.DetectGitInfo()
			if testCase.gitInfo == nil {
				// Assert the expected error
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
