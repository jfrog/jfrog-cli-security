package scm

import (
	"errors"
	"fmt"
	"path"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/xsc/services"
)

const (
	Github    ScProvider = "github"
	Gitlab    ScProvider = "gitlab"
	Bitbucket ScProvider = "bitbucket"
	Azure     ScProvider = "azure"
	Gerrit    ScProvider = "gerrit"

	// TODO: Add support for other git providers

	// git clone https://git-codecommit.{region}.amazonaws.com/v1/repos/{repository_name}
	AWSCodeCommit ScProvider = "codecommit"
	// git clone https://gitea.com/gitea/helm-chart.git
	Gitea ScProvider = "gitea"

	// svn checkout https://svn.code.sf.net/p/svn-sample-repo/code/ svn-sample-repo-code
	SourceForge ScProvider = "sourceforge"

	Unknown ScProvider = ""
)

// ScProvider is the type of source control provider
type ScProvider string

func (sp ScProvider) String() string {
	return string(sp)
}

const (
	Git ScType = "git"
)

// ScType is the type of source control manager
type ScType string

func (st ScType) String() string {
	return string(st)
}

// ScmTypeData holds the data for each source control manager type
type ScmTypeData struct {
	indicator string
}

var supportedScmTypes = map[ScType]ScmTypeData{Git: {".git"}}

type ScmManager interface {
	GetSourceControlContext() (gitInfo *services.XscGitInfoContext, err error)
}

func DetectScmInProject(projectPath string) (manager ScmManager, err error) {
	for scmType, scmData := range supportedScmTypes {
		if exists, e := isScmProject(projectPath, scmData); !exists || err != nil {
			err = errors.Join(e, err)
			continue
		}
		if scmType == Git {
			return NewGitManager(projectPath)
		}
	}
	err = errors.Join(err, fmt.Errorf("failed to detect source control manager in project path: %s", projectPath))
	return
}

func isScmProject(projectPath string, scmData ScmTypeData) (bool, error) {
	return fileutils.IsDirExists(path.Join(projectPath, scmData.indicator), false)
}
