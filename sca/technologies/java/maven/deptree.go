package maven

import (
	"github.com/jfrog/jfrog-cli-security/sca/technologies/java"
)

const (
	mavenDepTreeJarFile    = "maven-dep-tree.jar"
	mavenDepTreeOutputFile = "mavendeptree.out"
	// Changing this version also requires a change in MAVEN_DEP_TREE_VERSION within buildscripts/download_jars.sh
	mavenDepTreeVersion = "1.1.1"
	settingsXmlFile     = "settings.xml"
)

type MavenDepTreeCmd string

const (
	Projects MavenDepTreeCmd = "projects"
	Tree     MavenDepTreeCmd = "tree"
)

type MavenDepTreeManager struct {
	java.DepTreeManager
	isInstalled bool
	// this flag its curation command, it will set dedicated cache and download url.
	isCurationCmd bool
	// path to the curation dedicated cache
	curationCacheFolder string
	cmdName             MavenDepTreeCmd
	settingsXmlPath     string
}
