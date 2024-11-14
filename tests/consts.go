package tests

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	JvmLaunchEnvVar = "MAVEN_OPTS"
	GoCacheEnvVar   = "GOMODCACHE"
	PipCacheEnvVar  = "PIP_CACHE_DIR"

	TestJfrogUrlEnvVar      = "JFROG_SECURITY_CLI_TESTS_JFROG_URL"
	TestJfrogTokenEnvVar    = "JFROG_SECURITY_CLI_TESTS_JFROG_ACCESS_TOKEN"
	TestJfrogUserEnvVar     = "JFROG_SECURITY_CLI_TESTS_JFROG_USER"
	TestJfrogPasswordEnvVar = "JFROG_SECURITY_CLI_TESTS_JFROG_PASSWORD"

	MavenCacheRedirectionVal = "-Dmaven.repo.local="
)

const (
	XrayEndpoint        = "xray/"
	XscEndpoint         = "xsc/"
	ArtifactoryEndpoint = "artifactory/"
	AccessEndpoint      = "access/"
	RepoDetailsEndpoint = "api/repositories/"

	Out  = "out"
	Temp = "tmp"
)

// Integration tests - Artifactory information
var (
	ServerId = "testServerId"

	// Repositories
	RtRepo1       = "cli-rt1"
	RtVirtualRepo = "cli-rt-virtual"

	DockerVirtualRepo      = "cli-docker-virtual"
	DockerLocalRepo        = "cli-docker-local"
	DockerRemoteRepo       = "cli-docker-remote"
	NpmRemoteRepo          = "cli-npm-remote"
	NugetRemoteRepo        = "cli-nuget-remote"
	YarnRemoteRepo         = "cli-yarn-remote"
	GradleRemoteRepo       = "cli-gradle-remote"
	MvnRemoteRepo          = "cli-mvn-remote"
	MvnRemoteSnapshotsRepo = "cli-mvn-snapshots-remote"
	MvnVirtualRepo         = "cli-mvn-virtual"
	GoVirtualRepo          = "cli-go-virtual"
	GoRemoteRepo           = "cli-go-remote"
	GoRepo                 = "cli-go"
	PypiRemoteRepo         = "cli-pypi-remote"
)

// Integration tests - Artifactory repositories creation templates
const (
	DockerVirtualRepositoryConfig        = "docker_virtual_repository_config.json"
	DockerLocalRepositoryConfig          = "docker_local_repository_config.json"
	DockerRemoteRepositoryConfig         = "docker_remote_repository_config.json"
	NpmRemoteRepositoryConfig            = "npm_remote_repository_config.json"
	NugetRemoteRepositoryConfig          = "nuget_remote_repository_config.json"
	YarnRemoteRepositoryConfig           = "yarn_remote_repository_config.json"
	GradleRemoteRepositoryConfig         = "gradle_remote_repository_config.json"
	MavenRemoteRepositoryConfig          = "maven_remote_repository_config.json"
	MavenRemoteSnapshotsRepositoryConfig = "maven_remote_snapshots_repository_config.json"
	MavenVirtualRepositoryConfig         = "maven_virtual_repository_config.json"
	GoVirtualRepositoryConfig            = "go_virtual_repository_config.json"
	GoRemoteRepositoryConfig             = "go_remote_repository_config.json"
	GoLocalRepositoryConfig              = "go_local_repository_config.json"
	PypiRemoteRepositoryConfig           = "pypi_remote_repository_config.json"

	Repo1RepositoryConfig   = "repo1_repository_config.json"
	VirtualRepositoryConfig = "specs_virtual_repository_config.json"
)

var reposConfigMap = map[*string]string{
	&RtRepo1:       Repo1RepositoryConfig,
	&RtVirtualRepo: VirtualRepositoryConfig,

	&DockerVirtualRepo:      DockerVirtualRepositoryConfig,
	&DockerLocalRepo:        DockerLocalRepositoryConfig,
	&DockerRemoteRepo:       DockerRemoteRepositoryConfig,
	&NpmRemoteRepo:          NpmRemoteRepositoryConfig,
	&NugetRemoteRepo:        NugetRemoteRepositoryConfig,
	&YarnRemoteRepo:         YarnRemoteRepositoryConfig,
	&GradleRemoteRepo:       GradleRemoteRepositoryConfig,
	&MvnRemoteRepo:          MavenRemoteRepositoryConfig,
	&MvnRemoteSnapshotsRepo: MavenRemoteSnapshotsRepositoryConfig,
	&MvnVirtualRepo:         MavenVirtualRepositoryConfig,
	&GoVirtualRepo:          GoVirtualRepositoryConfig,
	&GoRemoteRepo:           GoRemoteRepositoryConfig,
	&GoRepo:                 GoLocalRepositoryConfig,
	&PypiRemoteRepo:         PypiRemoteRepositoryConfig,
}

func GetTestResourcesPath() string {
	dir, _ := os.Getwd()
	return getTestResourcesPath(dir)
}

func GetTestResourcesPathFromPath(basePaths ...string) string {
	return getTestResourcesPath(filepath.Join(basePaths...))
}

func getTestResourcesPath(basePath string) string {
	return filepath.Join(basePath, "tests", "testdata")
}

// Return local and remote repositories for the test suites, respectfully
func GetNonVirtualRepositories() map[*string]string {
	nonVirtualReposMap := map[*bool][]*string{
		TestDockerScan:  {&DockerLocalRepo, &DockerRemoteRepo},
		TestArtifactory: {&NpmRemoteRepo, &NugetRemoteRepo, &YarnRemoteRepo, &GradleRemoteRepo, &MvnRemoteRepo, &MvnRemoteSnapshotsRepo, &GoRepo, &GoRemoteRepo, &PypiRemoteRepo},
	}
	return getNeededRepositories(nonVirtualReposMap)
}

// Return virtual repositories for the test suites, respectfully
func GetVirtualRepositories() map[*string]string {
	virtualReposMap := map[*bool][]*string{
		TestDockerScan:  {&DockerVirtualRepo},
		TestArtifactory: {&GoVirtualRepo, &MvnVirtualRepo},
	}
	return getNeededRepositories(virtualReposMap)
}

var CreatedNonVirtualRepositories map[*string]string
var CreatedVirtualRepositories map[*string]string

func GetAllRepositoriesNames() []string {
	var baseRepoNames []string
	for repoName := range GetNonVirtualRepositories() {
		baseRepoNames = append(baseRepoNames, *repoName)
	}
	for repoName := range GetVirtualRepositories() {
		baseRepoNames = append(baseRepoNames, *repoName)
	}
	return baseRepoNames
}

func getNeededRepositories(reposMap map[*bool][]*string) map[*string]string {
	reposToCreate := map[*string]string{}
	for needed, testRepos := range reposMap {
		if *needed {
			for _, repo := range testRepos {
				reposToCreate[repo] = reposConfigMap[repo]
			}
		}
	}
	return reposToCreate
}

func AddTimestampToGlobalVars() {
	// Make sure the global timestamp is added only once even in case of multiple tests flags
	if timestampAdded {
		return
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	uniqueSuffix := "-" + timestamp

	if *ciRunId != "" {
		uniqueSuffix = "-" + *ciRunId + uniqueSuffix
	}
	// Artifactory accepts only lowercase repository names
	uniqueSuffix = strings.ToLower(uniqueSuffix)

	// Repositories
	GoRepo += uniqueSuffix
	GoRemoteRepo += uniqueSuffix
	GoVirtualRepo += uniqueSuffix
	DockerLocalRepo += uniqueSuffix
	DockerRemoteRepo += uniqueSuffix
	DockerVirtualRepo += uniqueSuffix
	GradleRemoteRepo += uniqueSuffix
	MvnRemoteRepo += uniqueSuffix
	MvnRemoteSnapshotsRepo += uniqueSuffix
	MvnVirtualRepo += uniqueSuffix
	NpmRemoteRepo += uniqueSuffix
	NugetRemoteRepo += uniqueSuffix
	YarnRemoteRepo += uniqueSuffix
	PypiRemoteRepo += uniqueSuffix

	timestampAdded = true
}

// Builds and repositories names to replace in the test files.
// We use substitution map to set repositories and builds with timestamp.
func GetSubstitutionMap() map[string]string {
	return map[string]string{
		"${REPO1}":        RtRepo1,
		"${VIRTUAL_REPO}": RtVirtualRepo,

		"${DOCKER_REPO}":         DockerLocalRepo,
		"${DOCKER_REMOTE_REPO}":  DockerRemoteRepo,
		"${DOCKER_VIRTUAL_REPO}": DockerVirtualRepo,

		"${GO_REPO}":                     GoRepo,
		"${GO_REMOTE_REPO}":              GoRemoteRepo,
		"${GO_VIRTUAL_REPO}":             GoVirtualRepo,
		"${GRADLE_REMOTE_REPO}":          GradleRemoteRepo,
		"${MAVEN_REMOTE_REPO}":           MvnRemoteRepo,
		"${MAVEN_REMOTE_SNAPSHOTS_REPO}": MvnRemoteSnapshotsRepo,
		"${MAVEN_VIRTUAL_REPO}":          MvnVirtualRepo,
		"${NPM_REMOTE_REPO}":             NpmRemoteRepo,
		"${NUGET_REMOTE_REPO}":           NugetRemoteRepo,
		"${PYPI_REMOTE_REPO}":            PypiRemoteRepo,
		"${YARN_REMOTE_REPO}":            YarnRemoteRepo,
	}
}
