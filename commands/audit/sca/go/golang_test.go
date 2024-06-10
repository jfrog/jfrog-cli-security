package _go

import (
	"errors"
	"fmt"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca"
	xrayutils "github.com/jfrog/jfrog-cli-security/utils"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"

	"github.com/stretchr/testify/assert"
)

func TestBuildGoDependencyList(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := sca.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "go", "go-project"))
	defer cleanUp()

	err := removeTxtSuffix("go.mod.txt")
	assert.NoError(t, err)
	err = removeTxtSuffix("go.sum.txt")
	assert.NoError(t, err)
	err = removeTxtSuffix("test.go.txt")
	assert.NoError(t, err)

	// Run getModulesDependencyTrees
	server := &config.ServerDetails{
		Url:            "https://api.go.here",
		ArtifactoryUrl: "https://api.go.here/artifactory",
		User:           "user",
		AccessToken:    "sdsdccs2232",
	}
	goVersionID, err := getGoVersionAsDependency()
	assert.NoError(t, err)
	expectedUniqueDeps := []string{
		goPackageTypeIdentifier + "golang.org/x/text:v0.3.3",
		goPackageTypeIdentifier + "rsc.io/quote:v1.5.2",
		goPackageTypeIdentifier + "rsc.io/sampler:v1.3.0",
		goPackageTypeIdentifier + "testGoList",
		goVersionID.Id,
	}

	auditBasicParams := (&xrayutils.AuditBasicParams{}).SetServerDetails(server).SetDepsRepo("test-remote")
	rootNode, uniqueDeps, err := BuildDependencyTree(auditBasicParams)
	assert.NoError(t, err)
	assert.ElementsMatch(t, uniqueDeps, expectedUniqueDeps, "First is actual, Second is Expected")
	// jfrog-ignore: test case
	assert.Equal(t, "https://user:sdsdccs2232@api.go.here/artifactory/api/go/test-remote|direct", os.Getenv("GOPROXY"))
	assert.NotEmpty(t, rootNode)

	// Check root module
	assert.Equal(t, rootNode[0].Id, goPackageTypeIdentifier+"testGoList")
	assert.Len(t, rootNode[0].Nodes, 3)

	// Test go version node
	goVersion, err := utils.GetParsedGoVersion()
	assert.NoError(t, err)
	tests.GetAndAssertNode(t, rootNode[0].Nodes, strings.ReplaceAll(goVersion.GetVersion(), "go", goSourceCodePrefix))

	// Test child without sub nodes
	child1 := tests.GetAndAssertNode(t, rootNode[0].Nodes, "golang.org/x/text:v0.3.3")
	assert.Len(t, child1.Nodes, 0)

	// Test child with 1 sub node
	child2 := tests.GetAndAssertNode(t, rootNode[0].Nodes, "rsc.io/quote:v1.5.2")
	assert.Len(t, child2.Nodes, 1)
	tests.GetAndAssertNode(t, child2.Nodes, "rsc.io/sampler:v1.3.0")
}

func removeTxtSuffix(txtFileName string) error {
	// go.sum.txt  >> go.sum
	return fileutils.MoveFile(txtFileName, strings.TrimSuffix(txtFileName, ".txt"))
}

func Test_handleCurationGoError(t *testing.T) {

	tests := []struct {
		name          string
		err           error
		expectedError error
	}{
		{
			name:          "curation error 403",
			err:           errors.New("package download failed due to 403 forbidden test failure"),
			expectedError: fmt.Errorf(sca.CurationErrorMsgToUserTemplate, techutils.Go),
		},
		{
			name: "not curation error 500",
			err:  errors.New("package download failed due to 500 internal server error test failure"),
		},
		{
			name: "no error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := handleCurationGoError(tt.err)
			assert.Equal(t, tt.expectedError, err)
			assert.Equal(t, tt.expectedError != nil, got)
		})
	}
}
