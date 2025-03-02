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

var testDir = filepath.Join("..", "..", "tests", "testdata", "git", "projects")

func TestGetGitContext(t *testing.T) {
	testCases := []struct {
		name                  string
		testProjectZipDirPath string
		NoDotGitFolder        bool
		gitInfo               *services.XscGitInfoContext
	}{
		{
			name:                  "No Git Info",
			NoDotGitFolder:        true,
			testProjectZipDirPath: filepath.Join(testDir, "nogit"),
		},
		{
			name:                  "Clean Project (after clone)",
			testProjectZipDirPath: filepath.Join(testDir, "clean"),
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
			testProjectZipDirPath: filepath.Join(testDir, "selfhosted"),
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
			testProjectZipDirPath: filepath.Join(testDir, "gitlab"),
			gitInfo: &services.XscGitInfoContext{
				GitRepoHttpsCloneUrl: "https://gitlab.com/attiasas/test-group/test-security-git.git",
				GitRepoName:          "test-security-git",
				GitProject:           "attiasas/test-group",
				GitProvider:          "gitlab",
				BranchName:           "main",
				LastCommitHash:       "ada14e9f525d8cbfb3c8c31ebe345d85ec342480",
				LastCommitMessage:    "add npm",
				LastCommitAuthor:     "attiasas",
			},
		},
		{
			name:                  "Gerrit Project (no owner)",
			testProjectZipDirPath: filepath.Join(testDir, "gerrit"),
			gitInfo: &services.XscGitInfoContext{
				GitRepoHttpsCloneUrl: "https://gerrit.googlesource.com/git-repo",
				GitRepoName:          "git-repo",
				GitProject:           "git-repo",
				GitProvider:          "gerrit",
				BranchName:           "main",
				LastCommitHash:       "a532f57a1f20623f5b9dd022493141a5b2a71009",
				LastCommitMessage:    `clean project`,
				LastCommitAuthor:     "attiasas",
			},
		},
		{
			name:                  "Forked Project (multiple remotes)",
			testProjectZipDirPath: filepath.Join(testDir, "forked"),
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
			testProjectZipDirPath: filepath.Join(testDir, "dirty"),
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

func TestDiffGetRemovedContent(t *testing.T) {
	testCases := []struct {
		name            string
		testZipDir      string
		sourceReference string
		targetReference string
		expectedChanges DiffContent
		expectedError   string
	}{
		{
			name: 		  "Not valid target reference",
			testZipDir:   "clean",
			targetReference: "a57ea78854a46cee64ba6747b3b3b3b3b3b3b3b3",
			expectedError: "object not found",
		},
		{
			name:            "No relevant changes (commit reference)",
			testZipDir:      "clean",
			targetReference: "5fc36ff0666e5ce9dba6c0a1c539ee640cabe0b0",
			expectedChanges: DiffContent{},
		},
		{
			name:            "No relevant changes (branch reference)",
			testZipDir:      "clean",
			targetReference: "main",
			expectedChanges: DiffContent{},
		},
		{
			name:            "single commit differences with relevant changes (commit reference)",
			testZipDir:      "clean",
			sourceReference: "861b7aff93eeb9be4806f1d9cc668e3d702d90b6",
			targetReference: "2c51295ce6600ade6058c0819d4f4fae759f4d85",
			expectedChanges: DiffContent{
				ChangedFiles: []FileChanges{
					{
						Path: "README.md",
						// Appended content
						Ranges: []Range{{StartRow: 12, StartCol: 1, EndRow: 13, EndCol: 92}},
					},
					{
						Path: "npm_app/index.js",
						// Appended content
						Ranges: []Range{{StartRow: 2, StartCol: 1, EndRow: 4, EndCol: 75}},
					},
					{
						Path: "npm_app/package-lock.json",
						// Changed content
						Ranges: []Range{
							{StartRow: 12, StartCol: 21, EndRow: 81, EndCol: 1},
							{StartRow: 93, StartCol: 1, EndRow: 128, EndCol: 1},
							{StartRow: 131, StartCol: 1, EndRow: 197, EndCol: 1},
							{StartRow: 202, StartCol: 1, EndRow: 231, EndCol: 1},
						},
					},
					{
						Path: "npm_app/package.json",
						// Changed content
						Ranges: []Range{{StartRow: 12, StartCol: 18, EndRow: 13, EndCol: 24}},
					},
				},
			},
		},
		{
			name: "multiple commit differences with relevant changes (commit reference)",
			testZipDir: "clean",
			targetReference: "adcdec709cc8aecbcfb340cd32bf9d6e8236c02b",
			expectedChanges: DiffContent{
				ChangedFiles: []FileChanges{
					{
						Path: ".gitignore",
						// Added file
						Ranges: []Range{{StartRow: 1, StartCol: 1, EndRow: 21, EndCol: 4}},
					},
					{
						Path: "README.md",
						// Changed content and appended content
						Ranges: []Range{
							{StartRow: 7, StartCol: 1, EndRow: 9, EndCol: 1},
							{StartRow: 10, StartCol: 1, EndRow: 15, EndCol: 82},
						},
					},
					{
						Path: "npm_app/index.js",
						// Added file
						Ranges: []Range{{StartRow: 1, StartCol: 1, EndRow: 4, EndCol: 75}},
					},
					{
						Path: "npm_app/package-lock.json",
						// Added file
						Ranges: []Range{{StartRow: 1, StartCol: 1, EndRow: 229, EndCol: 1}},
					},
					{
						Path: "npm_app/package.json",
						// Added file
						Ranges: []Range{{StartRow: 1, StartCol: 1, EndRow: 16, EndCol: 1}},
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Create the project from the zip
			projectPath, cleanUpProject := securityTestUtils.CreateTestProjectFromZip(t, filepath.Join(testDir, "clean"))
			defer cleanUpProject()
			// Prepare the git manager at the project path
			gitManager, err := NewGitManager(projectPath)
			require.NoError(t, err)
			// checkout the source reference
			if testCase.sourceReference != "" {
				require.NoError(t, gitManager.CheckoutToHash(testCase.sourceReference))
			}
			// Get the relevant changes
			changes, err := gitManager.DiffGetRemovedContent(testCase.targetReference)
			if len(testCase.expectedError) > 0 {
				// Assert the expected error
				assert.Error(t, err)
				assert.ErrorContains(t, err, testCase.expectedError)
				return
			}
			// Assert the expected changes
			require.NoError(t, err)
			// Assert the expected changes
			assert.Equal(t, testCase.expectedChanges, changes)
		})
	}
}
