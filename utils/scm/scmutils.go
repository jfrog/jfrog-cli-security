package scm

import (
	"errors"
	"fmt"
	"path"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/xsc/services"
)

const (
	Github    ScmProvider = "github"
	Gitlab    ScmProvider = "gitlab"
	Bitbucket ScmProvider = "bitbucket"
	Azure     ScmProvider = "azure"
	Gerrit    ScmProvider = "gerrit"

	// TODO: Add support for other git providers

	// git clone https://git-codecommit.{region}.amazonaws.com/v1/repos/{repository_name}
	AWSCodeCommit ScmProvider = "codecommit"
	// git clone https://gitea.com/gitea/helm-chart.git
	Gitea ScmProvider = "gitea"

	// svn checkout https://svn.code.sf.net/p/svn-sample-repo/code/ svn-sample-repo-code
	SourceForge ScmProvider = "sourceforge"

	Unknown ScmProvider = ""
)

// ScmProvider is the type of source control provider
type ScmProvider string

func (sp ScmProvider) String() string {
	return string(sp)
}

const (
	Git ScmType = "git"
)

type ScmType string

func (st ScmType) String() string {
	return string(st)
}

type ScmTypeData struct {
	indicator string
}

var scmTypeData = map[ScmType]ScmTypeData{Git: {".git"}}

type ScmManager interface {
	GetGitContext() (gitInfo *services.XscGitInfoContext, err error)
}

func DetectScmInProject(projectPath string) (manager ScmManager, err error) {
	for scmType, scmData := range scmTypeData {
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
