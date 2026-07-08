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

	// curationSettingsID is the stable XML id for server/mirror/profile entries injected
	// into the temp settings.xml. Dedicated id keeps re-runs idempotent.
	curationSettingsID = "jfrog-curation-audit"
	// defaultSettingsID is the generic id used for non-curation runs, and is also the
	// id rendered by the built-in template (resources/settings.xml).
	defaultSettingsID = "artifactory"
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
	isInstalled          bool
	isCurationCmd        bool
	mvnIncludePluginDeps bool
	curationCacheFolder  string
	cmdName              MavenDepTreeCmd
	settingsXmlPath      string
	// userSettingsXmlPath overrides the ~/.m2/settings.xml seed path (test-only).
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
	// Plugin deps are downloaded during mvn install but absent from mvn dependency:tree;
	// without injection jf ca would miss curation violations that block the build.
	// "--mvn-include-plugin-deps" is a string literal to avoid a cli->sca import cycle
	// (mirrors flags.MvnIncludePluginDeps in cli/docs/flags.go).
	if manager.mvnIncludePluginDeps && len(dependencyTree) > 0 {
		switch {
		case len(pluginDeps) > 0:
			injectPluginDeps(uniqueDeps, dependencyTree, pluginDeps)
		case pluginNodesPresent:
			log.Debug("'--mvn-include-plugin-deps' is set: maven-dep-tree reported no build-plugin dependencies to include.")
		default:
			log.Warn("'--mvn-include-plugin-deps' is set but the resolved maven-dep-tree plugin did not report a " +
				"plugin-dependencies section; plugin dependencies will not be included in the curation evaluation. " +
				"This usually means the maven-dep-tree plugin version does not support plugin dependency resolution.")
		}
	}
	return
}

// injectPluginDeps adds plugin deps to uniqueDeps and attaches them to every module root.
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

// RunMavenDepTree runs maven-dep-tree and returns the output path along with a cleanup function.
func (mdt *MavenDepTreeManager) RunMavenDepTree() (depTreeOutput string, clearMavenDepTreeRun func() error, err error) {
	if mdt.useWrapper {
		mdt.useWrapper, err = isMavenWrapperExist()
		if err != nil {
			return
		}
	}
	depTreeExecDir, clearMavenDepTreeRun, err := mdt.CreateTempDirWithSettingsXmlIfNeeded()
	if err != nil {
		return
	}
	if err = mdt.installMavenDepTreePlugin(depTreeExecDir); err != nil {
		return
	}
	depTreeOutput, err = mdt.execMavenDepTree(depTreeExecDir)
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

// buildMvnExecCommand constructs the mvn/mvnw command. On non-Windows the wrapper is
// invoked via 'sh' to avoid "permission denied" errors on scripts without +x.
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
		// Explicit relative path required since Go 1.19 no longer resolves CWD executables via PATH.
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

// createSettingsXmlWithConfiguredArtifactory writes a temp settings.xml for the Maven run.
// For curation runs it seeds from ~/.m2/settings.xml (preserving proxies etc.) and upserts
// curation entries on top. For plain audit runs it uses the built-in template directly.
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

	// Plain audit runs use the template directly; only curation seeds from ~/.m2/settings.xml.
	if !mdt.isCurationCmd {
		return mdt.createSettingsXmlFromTemplate(username, password, remoteRepositoryFullPath, defaultSettingsID)
	}

	userSettingsPath := mdt.userSettingsXmlPath
	if userSettingsPath == "" {
		homeDir, homeErr := os.UserHomeDir()
		if homeErr != nil {
			log.Warn("Could not resolve user home directory, using settings.xml template:", homeErr.Error())
			return mdt.createSettingsXmlFromTemplate(username, password, remoteRepositoryFullPath, curationSettingsID)
		}
		userSettingsPath = filepath.Join(homeDir, ".m2", settingsXmlFile)
	}

	exists, err := fileutils.IsFileExists(userSettingsPath, false)
	if err != nil {
		log.Warn(fmt.Sprintf("Could not stat settings.xml at %s (%v); falling back to built-in template.", userSettingsPath, err))
		return mdt.createSettingsXmlFromTemplate(username, password, remoteRepositoryFullPath, curationSettingsID)
	}
	if exists {
		log.Debug("Seeding temp settings.xml from existing user settings:", userSettingsPath)
		return mdt.createSettingsXmlFromExisting(userSettingsPath, username, password, remoteRepositoryFullPath)
	}
	return mdt.createSettingsXmlFromTemplate(username, password, remoteRepositoryFullPath, curationSettingsID)
}

func (mdt *MavenDepTreeManager) createSettingsXmlFromTemplate(username, password, remoteRepositoryFullPath, id string) error {
	SettingsTemplate, err := template.New("settings").Parse(settingsXmlTemplate)
	if err != nil {
		return err
	}
	buf := &bytes.Buffer{}
	err = SettingsTemplate.Execute(buf, struct {
		ID                       string
		Username                 string
		Password                 string // #nosec G117 -- written to local temp file only
		RemoteRepositoryFullPath string
	}{
		ID:                       id,
		Username:                 username,
		Password:                 password,
		RemoteRepositoryFullPath: remoteRepositoryFullPath,
	})
	if err != nil {
		return err
	}
	return errorutils.CheckError(os.WriteFile(mdt.settingsXmlPath, buf.Bytes(), 0600))
}

// createSettingsXmlFromExisting seeds the temp settings.xml from the user's file and
// upserts curation entries. Falls back to the built-in template if the file is
// unparsable (e.g. mid-write) or missing the <settings> root. Only called for curation
// runs, so the template fallback here always uses curationSettingsID.
func (mdt *MavenDepTreeManager) createSettingsXmlFromExisting(userSettingsPath, username, password, remoteRepositoryFullPath string) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromFile(userSettingsPath); err != nil {
		log.Warn(fmt.Sprintf("Could not parse settings.xml at %s (%v); falling back to built-in template.", userSettingsPath, err))
		return mdt.createSettingsXmlFromTemplate(username, password, remoteRepositoryFullPath, curationSettingsID)
	}
	root := doc.SelectElement("settings")
	if root == nil {
		log.Warn(fmt.Sprintf("settings.xml at %s has no <settings> root; falling back to built-in template.", userSettingsPath))
		return mdt.createSettingsXmlFromTemplate(username, password, remoteRepositoryFullPath, curationSettingsID)
	}

	upsertCurationServer(root, username, password)
	upsertCurationMirror(root, remoteRepositoryFullPath)
	upsertCurationProfile(root, remoteRepositoryFullPath)
	upsertCurationActiveProfile(root)

	doc.Indent(4)
	buf, err := doc.WriteToBytes()
	if err != nil {
		return errorutils.CheckError(err)
	}
	return errorutils.CheckError(os.WriteFile(mdt.settingsXmlPath, buf, 0600))
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
	mirror := xmlFindByID(mirrors, "mirror", curationSettingsID)
	if mirror == nil {
		// Insert first: a pre-existing catch-all mirror would otherwise win in document order.
		mirror = etree.NewElement("mirror")
		mirrors.InsertChildAt(0, mirror)
	}
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
			return
		}
	}
	activeProfiles.CreateElement("activeProfile").SetText(curationSettingsID)
}

// CreateTempDirWithSettingsXmlIfNeeded creates a temp dir and, when a deps repo is
// configured, writes a settings.xml into it.
func (mdt *MavenDepTreeManager) CreateTempDirWithSettingsXmlIfNeeded() (tempDirPath string, clearMavenDepTreeRun func() error, err error) {
	tempDirPath, err = fileutils.CreateTempDir()
	if err != nil {
		return
	}
	clearMavenDepTreeRun = func() error { return fileutils.RemoveTempDir(tempDirPath) }
	if mdt.depsRepo != "" {
		err = mdt.createSettingsXmlWithConfiguredArtifactory(tempDirPath)
	}
	if err != nil {
		err = errors.Join(err, clearMavenDepTreeRun())
		clearMavenDepTreeRun = nil
	}
	return
}
