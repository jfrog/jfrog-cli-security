package scm

import (
	"fmt"
	"path"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/xsc/services"
)

const (
	Github ScmProvider = "github"
	Gitlab ScmProvider = "gitlab"
	// git clone https://git.id.info/scm/repo-name/repo-name.git
	Bitbucket ScmProvider = "bitbucket"
	Azure     ScmProvider = "azure"
	// svn checkout https://svn.code.sf.net/p/svn-sample-repo/code/ svn-sample-repo-code
	SourceForge ScmProvider = "sourceforge"

	// TODO: Add support for other git providers

	// git clone https://git-codecommit.{region}.amazonaws.com/v1/repos/{repository_name}
	AWSCodeCommit ScmProvider = "codecommit"
	// git clone https://gerrit.googlesource.com/git-repo
	Gerrit ScmProvider = "gerrit"
	// git clone https://gitea.com/gitea/helm-chart.git
	Gitea ScmProvider = "gitea"

	Unknown ScmProvider = ""
)

type ScmProvider string

func (sp ScmProvider) String() string {
	return string(sp)
}

const (
	Git ScmType = "git"
	Svn ScmType = "svn" // subversion
)

type ScmType string

func (st ScmType) String() string {
	return string(st)
}

type ScmTypeData struct {
	indicator string
	CliExists func() bool
}

var scmTypeData = map[ScmType]ScmTypeData{
	Git: {".git", func() bool { return true }},
	Svn: {".svn", func() bool { return true }},
}

type ScmManager interface {
	GetGitContext() (gitInfo *services.XscGitInfoContext, err error)
}

func DetectScmInProject(projectPath string) (manager ScmManager, err error) {
	// if exists .git directory in path, return the corresponding manager
	if exists, err := isScmProject(projectPath, Git); err != nil {
		return nil, err
	} else if exists {
		return NewGitManager(projectPath)
	}
	// if exists .svn directory in path, return the corresponding manager
	if exists, err := isScmProject(projectPath, Svn); err != nil {
		return nil, err
	} else if exists {
		return NewSvnManager(projectPath)
	}
	err = fmt.Errorf("failed to detect source control manager in project path: %s", projectPath)
	return
}

func isScmProject(projectPath string, scmType ScmType) (bool, error) {
	return fileutils.IsDirExists(path.Join(projectPath, scmTypeData[scmType].indicator), false)
}