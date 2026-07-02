package java

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/beevik/etree"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/ioutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

const (
	mavenDepTreeJarFile    = "maven-dep-tree.jar"
	mavenDepTreeOutputFile = "mavendeptree.out"
	// Changing this version also requires a change in MAVEN_DEP_TREE_VERSION within buildscripts/download_jars.sh
	mavenDepTreeVersion = "1.2.0"
	settingsXmlFile     = "settings.xml"

	// curationSettingsID is the stable XML id for the server/mirror/profile entries
	// injected into the temp settings.xml, ensuring idempotent re-runs.
	curationSettingsID = "artifactory"
)

var mavenConfigPath = filepath.Join(".mvn", "maven.config")

type MavenDepTreeCmd string

const (
	Projects MavenDepTreeCmd = "projects"
	Tree     MavenDepTreeCmd = "tree"
)

//go:embed resources/settings.xml
var settingsXmlTemplate string

//go:embed resources/maven-dep-tree.jar
var mavenDepTreeJar []byte

type MavenDepTreeManager struct {
	DepTreeManager
	isInstalled bool
	// isCurationCmd sets a dedicated cache and download URL for curation mode.
	isCurationCmd bool
	// mvnIncludePluginDeps enables resolution of Maven build-plugin transitive deps.
	mvnIncludePluginDeps bool
	// path to the curation dedicated cache
	curationCacheFolder string
	cmdName             MavenDepTreeCmd
	settingsXmlPath     string
	// userSettingsXmlPath overrides the default ~/.m2/settings.xml seed path used
	// in createSettingsXmlWithConfiguredArtifactory. Empty means use the default.
	userSettingsXmlPath string
}

func NewMavenDepTreeManager(params *DepTreeParams, cmdName MavenDepTreeCmd) *MavenDepTreeManager {
	depTreeManager := NewDepTreeManager(params)
	return &MavenDepTreeManager{
		DepTreeManager:       depTreeManager,
		isInstalled:          params.IsMavenDepTreeInstalled,
		cmdName:              cmdName,
		isCurationCmd:        params.IsCurationCmd,
		mvnIncludePluginDeps: params.MvnIncludePluginDeps,
		curationCacheFolder:  params.CurationCacheFolder,
	}
}

func buildMavenDependencyTree(params *DepTreeParams) (dependencyTree []*xrayUtils.GraphNode, uniqueDeps map[string]*xray.DepTreeNode, err error) {
	manager := NewMavenDepTreeManager(params, Tree)
	outputFilePaths, clearMavenDepTreeRun, err := manager.RunMavenDepTree()
	if err != nil {
		if clearMavenDepTreeRun != nil {
			err = errors.Join(err, clearMavenDepTreeRun())
		}
		return
	}
	defer func() {
		err = errors.Join(err, clearMavenDepTreeRun())
	}()
	var pluginDeps map[string]*xray.DepTreeNode
	var pluginNodesPresent bool
	dependencyTree, uniqueDeps, pluginDeps, pluginNodesPresent, err = getGraphAndPluginDepsFromDepTree(outputFilePaths)
	if err != nil {
		return
	}
	// Include Maven build-plugin transitive deps when requested.
	// They are downloaded during mvn install but never appear in mvn dependency:tree,
	// so without this step jf ca would miss curation violations that block the build.
	// Skip if the tree is empty — no roots to attach to.
	// The "--mvn-include-plugin-deps" literal below mirrors flags.MvnIncludePluginDeps
	// (cli/docs/flags.go); duplicated as a string to avoid a cli->sca import cycle.
	if manager.mvnIncludePluginDeps && len(dependencyTree) > 0 {
		switch {
		case len(pluginDeps) > 0:
			injectPluginDeps(uniqueDeps, dependencyTree, pluginDeps)
		case pluginNodesPresent:
			// Plugin ran but the plugin-deps section is empty: nothing to inject.
			log.Debug("'--mvn-include-plugin-deps' is set: maven-dep-tree reported no build-plugin dependencies to include.")
		default:
			// No plugin-deps section at all: the maven-dep-tree version pre-dates the feature.
			// Warn so plugin deps aren't silently skipped from the curation evaluation.
			log.Warn("'--mvn-include-plugin-deps' is set but the resolved maven-dep-tree plugin did not report a " +
				"plugin-dependencies section; plugin dependencies will not be included in the curation evaluation. " +
				"This usually means the maven-dep-tree plugin version does not support plugin dependency resolution.")
		}
	}
	return
}

// injectPluginDeps adds plugin deps to uniqueDeps and fans them out to every module root.
// Split out so the dedup guard and fan-out are unit-testable without spawning Maven.
func injectPluginDeps(uniqueDeps map[string]*xray.DepTreeNode, dependencyTree []*xrayUtils.GraphNode, pluginDeps map[string]*xray.DepTreeNode) {
	for id, node := range pluginDeps {
		gavID := GavPackageTypeIdentifier + id
		if _, exists := uniqueDeps[gavID]; exists {
			continue
		}
		uniqueDeps[gavID] = node
		for _, moduleRoot := range dependencyTree {
			moduleRoot.Nodes = append(moduleRoot.Nodes, &xrayUtils.GraphNode{Id: gavID, Types: node.Types, Classifier: node.Classifier})
		}
	}
}

// Runs maven-dep-tree according to cmdName. Returns the plugin output along with a function pointer to revert the plugin side effects.
// If a non-nil clearMavenDepTreeRun pointer is returns it means we had no error during the entire function execution
func (mdt *MavenDepTreeManager) RunMavenDepTree() (depTreeOutput string, clearMavenDepTreeRun func() error, err error) {
	if mdt.useWrapper {
		mdt.useWrapper, err = isMavenWrapperExist()
		if err != nil {
			return
		}
	}
	// depTreeExecDir is a temp directory for all the files that are required for the maven-dep-tree run
	depTreeExecDir, clearMavenDepTreeRun, err := mdt.CreateTempDirWithSettingsXmlIfNeeded()
	if err != nil {
		return
	}
	if err = mdt.installMavenDepTreePlugin(depTreeExecDir); err != nil {
		return
	}

	depTreeOutput, err = mdt.execMavenDepTree(depTreeExecDir)
	if err != nil {
		return
	}
	return
}

func (mdt *MavenDepTreeManager) installMavenDepTreePlugin(depTreeExecDir string) error {
	if mdt.isInstalled {
		return nil
	}
	mavenDepTreeJarPath := filepath.Join(depTreeExecDir, mavenDepTreeJarFile)
	if err := errorutils.CheckError(os.WriteFile(mavenDepTreeJarPath, mavenDepTreeJar, 0666)); err != nil {
		return err
	}
	goals := GetMavenPluginInstallationGoals(mavenDepTreeJarPath)
	_, err := mdt.RunMvnCmd(goals)
	return err
}

func GetMavenPluginInstallationGoals(pluginPath string) []string {
	return []string{"org.apache.maven.plugins:maven-install-plugin:3.1.1:install-file", "-Dfile=" + pluginPath, "-B"}
}

func GetMavenDepTreeVersion() string {
	return mavenDepTreeVersion
}

func (mdt *MavenDepTreeManager) execMavenDepTree(depTreeExecDir string) (string, error) {
	if mdt.cmdName == Tree {
		return mdt.runTreeCmd(depTreeExecDir)
	}
	return mdt.runProjectsCmd()
}

func (mdt *MavenDepTreeManager) runTreeCmd(depTreeExecDir string) (string, error) {
	mavenDepTreePath := filepath.Join(depTreeExecDir, mavenDepTreeOutputFile)
	goals := []string{"com.jfrog:maven-dep-tree:" + mavenDepTreeVersion + ":" + string(Tree), "-DdepsTreeOutputFile=" + mavenDepTreePath, "-B"}
	if mdt.isCurationCmd {
		goals = append(goals, "-Dmaven.repo.local="+mdt.curationCacheFolder)
	}
	if mdt.mvnIncludePluginDeps {
		goals = append(goals, "-DincludePluginDeps=true")
	}
	if _, err := mdt.RunMvnCmd(goals); err != nil {
		return "", err
	}

	mavenDepTreeOutput, err := os.ReadFile(mavenDepTreePath)
	if err != nil {
		return "", errorutils.CheckError(err)
	}
	return string(mavenDepTreeOutput), nil
}

func (mdt *MavenDepTreeManager) runProjectsCmd() (string, error) {
	goals := []string{"com.jfrog:maven-dep-tree:" + mavenDepTreeVersion + ":" + string(Projects), "-q"}
	output, err := mdt.RunMvnCmd(goals)
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func (mdt *MavenDepTreeManager) RunMvnCmd(goals []string) (cmdOutput []byte, err error) {
	restoreMavenConfig, err := removeMavenConfig()
	if err != nil {
		return
	}

	defer func() {
		if restoreMavenConfig != nil {
			err = errors.Join(err, restoreMavenConfig())
		}
	}()

	if mdt.settingsXmlPath != "" {
		goals = append(goals, "-s", mdt.settingsXmlPath)
	}

	execPath := getMavenExecPath(mdt.useWrapper)
	//#nosec G204
	cmdOutput, err = buildMvnExecCommand(mdt.useWrapper, execPath, goals).CombinedOutput()
	if err != nil {
		stringOutput := string(cmdOutput)
		if len(cmdOutput) > 0 {
			log.Verbose(stringOutput)
		}
		if msg := technologies.GetMsgToUserForCurationBlock(mdt.isCurationCmd, techutils.Maven, stringOutput); msg != "" {
			err = fmt.Errorf("failed running command '%s %s'\n\n%s", execPath, strings.Join(goals, " "), msg)
		} else {
			err = fmt.Errorf("failed running command '%s %s': %s", execPath, strings.Join(goals, " "), err.Error())
		}
	}
	return
}

func (mdt *MavenDepTreeManager) GetSettingsXmlPath() string {
	return mdt.settingsXmlPath
}

func (mdt *MavenDepTreeManager) SetSettingsXmlPath(settingsXmlPath string) {
	mdt.settingsXmlPath = settingsXmlPath
}

// Constructs the command to run mvnw/mvn with the given goals.
// When using the Maven wrapper on non-Windows systems, the wrapper script is invoked via 'sh' in order to avoid "permission denied" errors.
func buildMvnExecCommand(useWrapper bool, mvnExecPath string, goals []string) *exec.Cmd {
	var cmd *exec.Cmd
	if useWrapper && !coreutils.IsWindows() {
		cmd = exec.Command("sh", append([]string{mvnExecPath}, goals...)...)
	} else {
		cmd = exec.Command(mvnExecPath, goals...)
	}
	log.Info("Running maven command:", cmd.Path, strings.Join(cmd.Args[1:], " "))
	return cmd
}

func getMavenExecPath(useWrapper bool) string {
	if useWrapper {
		wrapperName := "mvnw"
		if coreutils.IsWindows() {
			wrapperName += ".cmd"
		}
		// Prefix with "." + separator to form an explicit relative path (e.g. "./mvnw" or ".\mvnw.cmd").
		// This is required since Go 1.19, which no longer resolves executables in the current directory
		// via PATH unless an explicit relative path is provided.
		return "." + string(os.PathSeparator) + wrapperName
	}
	return "mvn"
}

func isMavenWrapperExist() (bool, error) {
	wrapperName := "mvnw"
	if coreutils.IsWindows() {
		wrapperName += ".cmd"
	}
	return fileutils.IsFileExists(wrapperName, false)
}

func removeMavenConfig() (func() error, error) {
	mavenConfigExists, err := fileutils.IsFileExists(mavenConfigPath, false)
	if err != nil {
		return nil, err
	}
	if !mavenConfigExists {
		return nil, nil
	}
	restoreMavenConfig, err := ioutils.BackupFile(mavenConfigPath, "maven.config.bkp")
	if err != nil {
		return nil, err
	}
	err = os.Remove(mavenConfigPath)
	if err != nil {
		err = errorutils.CheckErrorf("failed to remove %s while building the maven dependencies tree. Error received:\n%s", mavenConfigPath, err.Error())
	}
	return restoreMavenConfig, err
}

// createSettingsXmlWithConfiguredArtifactory creates a disposable settings.xml for the
// curation-audit Maven run. When ~/.m2/settings.xml exists it is used as the base so
// existing configuration (e.g. <proxies>) is preserved; curation entries are upserted on
// top. Falls back to the built-in template when no user settings file is found.
func (mdt *MavenDepTreeManager) createSettingsXmlWithConfiguredArtifactory(settingsXmlPath string) error {
	username, password, err := getArtifactoryAuthFromServer(mdt.server)
	if err != nil {
		return err
	}
	endPoint := mdt.depsRepo
	if mdt.isCurationCmd {
		endPoint = path.Join("api/curation/audit", endPoint)
	}
	remoteRepositoryFullPath, err := url.JoinPath(mdt.server.ArtifactoryUrl, endPoint)
	if err != nil {
		return err
	}

	mdt.settingsXmlPath = filepath.Join(settingsXmlPath, settingsXmlFile)

	userSettingsPath := mdt.userSettingsXmlPath
	if userSettingsPath == "" {
		homeDir, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return fmt.Errorf("failed to get user home directory: %w", homeErr)
		}
		userSettingsPath = filepath.Join(homeDir, ".m2", settingsXmlFile)
	}

	exists, err := fileutils.IsFileExists(userSettingsPath, false)
	if err != nil {
		return err
	}
	if exists {
		log.Debug("Seeding temp settings.xml from existing user settings:", userSettingsPath)
		return mdt.createSettingsXmlFromExisting(userSettingsPath, username, password, remoteRepositoryFullPath)
	}

	// No existing user settings.xml: render from the built-in template.
	return mdt.createSettingsXmlFromTemplate(username, password, remoteRepositoryFullPath)
}

// createSettingsXmlFromTemplate renders the built-in settings.xml template (fallback path).
func (mdt *MavenDepTreeManager) createSettingsXmlFromTemplate(username, password, remoteRepositoryFullPath string) error {
	SettingsTemplate, err := template.New("settings").Parse(settingsXmlTemplate)
	if err != nil {
		return err
	}
	buf := &bytes.Buffer{}
	err = SettingsTemplate.Execute(buf, struct {
		Username                 string
		Password                 string // #nosec G117 -- required by settings.xml template; value written to local file only
		RemoteRepositoryFullPath string
	}{
		Username:                 username,
		Password:                 password,
		RemoteRepositoryFullPath: remoteRepositoryFullPath,
	})
	if err != nil {
		return err
	}
	return errorutils.CheckError(os.WriteFile(mdt.settingsXmlPath, buf.Bytes(), 0600))
}

// createSettingsXmlFromExisting seeds the temp settings.xml from the user's file,
// upserts curation entries, and writes to mdt.settingsXmlPath. The source file is unchanged.
func (mdt *MavenDepTreeManager) createSettingsXmlFromExisting(userSettingsPath, username, password, remoteRepositoryFullPath string) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromFile(userSettingsPath); err != nil {
		return fmt.Errorf("failed to read settings.xml at %s: %w", userSettingsPath, err)
	}
	root := doc.SelectElement("settings")
	if root == nil {
		return fmt.Errorf("invalid settings.xml at %s: missing <settings> root element", userSettingsPath)
	}

	upsertCurationServer(root, username, password)
	upsertCurationMirror(root, remoteRepositoryFullPath)
	upsertCurationProfile(root, remoteRepositoryFullPath)
	upsertCurationActiveProfile(root)

	doc.Indent(4)
	return errorutils.CheckError(doc.WriteToFile(mdt.settingsXmlPath))
}

func xmlGetOrCreate(parent *etree.Element, name string) *etree.Element {
	if el := parent.SelectElement(name); el != nil {
		return el
	}
	return parent.CreateElement(name)
}

func xmlFindByID(parent *etree.Element, elementName, id string) *etree.Element {
	for _, el := range parent.SelectElements(elementName) {
		if idEl := el.SelectElement("id"); idEl != nil && idEl.Text() == id {
			return el
		}
	}
	return nil
}

func xmlGetOrCreateByID(parent *etree.Element, elementName, id string) *etree.Element {
	if el := xmlFindByID(parent, elementName, id); el != nil {
		return el
	}
	return parent.CreateElement(elementName)
}

func xmlSetChild(parent *etree.Element, name, text string) {
	xmlGetOrCreate(parent, name).SetText(text)
}

func upsertCurationServer(root *etree.Element, username, password string) {
	servers := xmlGetOrCreate(root, "servers")
	server := xmlGetOrCreateByID(servers, "server", curationSettingsID)
	xmlSetChild(server, "id", curationSettingsID)
	xmlSetChild(server, "username", username)
	xmlSetChild(server, "password", password) // #nosec G117 -- written to local temp file only
}

func upsertCurationMirror(root *etree.Element, repoURL string) {
	mirrors := xmlGetOrCreate(root, "mirrors")
	mirror := xmlGetOrCreateByID(mirrors, "mirror", curationSettingsID)
	xmlSetChild(mirror, "id", curationSettingsID)
	xmlSetChild(mirror, "url", repoURL)
	xmlSetChild(mirror, "mirrorOf", "*")
}

func upsertCurationProfile(root *etree.Element, repoURL string) {
	profiles := xmlGetOrCreate(root, "profiles")
	profile := xmlGetOrCreateByID(profiles, "profile", curationSettingsID)
	xmlSetChild(profile, "id", curationSettingsID)

	repos := xmlGetOrCreate(profile, "repositories")
	repo := xmlGetOrCreateByID(repos, "repository", curationSettingsID)
	xmlSetChild(xmlGetOrCreate(repo, "snapshots"), "enabled", "true")
	xmlSetChild(repo, "id", curationSettingsID)
	xmlSetChild(repo, "name", "mavenRepo")
	xmlSetChild(repo, "url", repoURL)
}

func upsertCurationActiveProfile(root *etree.Element) {
	activeProfiles := xmlGetOrCreate(root, "activeProfiles")
	for _, ap := range activeProfiles.SelectElements("activeProfile") {
		if ap.Text() == curationSettingsID {
			return // already present
		}
	}
	activeProfiles.CreateElement("activeProfile").SetText(curationSettingsID)
}

// Creates a temporary directory.
// If Artifactory resolution repo is provided, a settings.xml file with the provided server and repository will be created inside the temporarily directory.
func (mdt *MavenDepTreeManager) CreateTempDirWithSettingsXmlIfNeeded() (tempDirPath string, clearMavenDepTreeRun func() error, err error) {
	tempDirPath, err = fileutils.CreateTempDir()
	if err != nil {
		return
	}

	clearMavenDepTreeRun = func() error { return fileutils.RemoveTempDir(tempDirPath) }

	// Create a settings.xml file that sets the dependency resolution from the given server and repository
	if mdt.depsRepo != "" {
		err = mdt.createSettingsXmlWithConfiguredArtifactory(tempDirPath)
	}
	if err != nil {
		err = errors.Join(err, clearMavenDepTreeRun())
		clearMavenDepTreeRun = nil
	}
	return
}
