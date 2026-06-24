package java

import (
	"bytes"
	_ "embed"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"unicode/utf8"

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
	mavenDepTreeVersion = "1.1.5"
	settingsXmlFile     = "settings.xml"
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
	dependencyTree, uniqueDeps, err = getGraphFromDepTree(outputFilePaths)
	if err != nil {
		return
	}
	// Include Maven build-plugin transitive deps when requested.
	// They are downloaded during mvn install but never appear in mvn dependency:tree,
	// so without this step jf ca would miss curation violations that block the build.
	// Skip if the tree is empty — no roots to attach to and no point running extra subprocesses.
	// To move this logic to maven-dep-tree - XRAY-145307
	if manager.mvnIncludePluginDeps && len(dependencyTree) > 0 {
		injectPluginDeps(uniqueDeps, dependencyTree, manager.resolvePluginDeps())
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
			moduleRoot.Nodes = append(moduleRoot.Nodes, &xrayUtils.GraphNode{Id: gavID, Types: node.Types})
		}
	}
}

// resolvePluginDeps runs "mvn dependency:resolve-plugins" and returns all Maven build-plugin
// transitive dependencies keyed by "groupId:artifactId:version". Failure is non-fatal.
//
// The result is filtered by the install-lifecycle plugin allow-list resolved from the
// effective POM: only transitive deps of plugins that actually run during `mvn install` are
// returned. If the effective-pom resolution fails, the allow-list is nil and all plugin deps
// are returned (current behavior).
func (mdt *MavenDepTreeManager) resolvePluginDeps() map[string]*xray.DepTreeNode {
	allowedPlugins := mdt.resolveInstallLifecyclePlugins()

	goals := []string{"dependency:resolve-plugins", "-B"}
	if mdt.isCurationCmd && mdt.curationCacheFolder != "" {
		goals = append(goals, "-Dmaven.repo.local="+mdt.curationCacheFolder)
	}
	output, err := mdt.RunMvnCmd(goals)
	if err != nil {
		log.Warn("[mvn-plugin-deps] Failed to resolve Maven plugin dependencies; plugin deps will not be included in curation evaluation:", err.Error())
		return nil
	}
	if allowedPlugins != nil {
		log.Debug(fmt.Sprintf("[mvn-plugin-deps] effective-pom install-lifecycle allow-list (%d plugins):", len(allowedPlugins)))
		for coord := range allowedPlugins {
			log.Debug("[mvn-plugin-deps]   allowed:", coord)
		}
	} else {
		log.Debug("[mvn-plugin-deps] effective-pom allow-list unavailable - reporting every plugin dep without lifecycle filter")
	}
	parsed := parseMavenPluginDeps(string(output), allowedPlugins)
	if allowedPlugins != nil {
		log.Info(fmt.Sprintf("[mvn-plugin-deps] %d plugin transitive deps included after install-lifecycle filter", len(parsed)))
	} else {
		log.Info(fmt.Sprintf("[mvn-plugin-deps] %d plugin transitive deps included (lifecycle filter unavailable — all reported)", len(parsed)))
	}
	return parsed
}

// resolveInstallLifecyclePlugins runs "mvn help:effective-pom" and returns the set of
// "groupId:artifactId" for plugins bound to phases executed by `mvn install`.
// Plugins whose only executions target post-install phases (deploy/site/release) are excluded.
// Returns nil if effective-pom resolution fails — callers must treat nil as "no filter".
func (mdt *MavenDepTreeManager) resolveInstallLifecyclePlugins() map[string]struct{} {
	outputFile, err := os.CreateTemp("", "effective-pom-*.xml")
	if err != nil {
		log.Warn("[mvn-plugin-deps] Failed to create temp file for effective POM; plugin filter disabled:", err.Error())
		return nil
	}
	outputPath := outputFile.Name()
	if closeErr := outputFile.Close(); closeErr != nil {
		// Benign: mvn reopens the path via -Doutput=. Log so the rare failure is greppable.
		log.Debug("[mvn-plugin-deps] temp file close after CreateTemp failed (benign):", closeErr.Error())
	}
	// Preserve the file on parse failure so callers can inspect why no plugins were extracted.
	preserveFile := false
	defer func() {
		if preserveFile {
			log.Warn("[mvn-plugin-deps] effective POM preserved for inspection at:", outputPath)
			return
		}
		if removeErr := os.Remove(outputPath); removeErr != nil && !os.IsNotExist(removeErr) {
			log.Debug("[mvn-plugin-deps] failed to remove effective POM temp file:", removeErr.Error())
		}
	}()

	goals := []string{"help:effective-pom", "-B", "-Doutput=" + outputPath}
	if mdt.isCurationCmd && mdt.curationCacheFolder != "" {
		goals = append(goals, "-Dmaven.repo.local="+mdt.curationCacheFolder)
	}
	log.Debug("[mvn-plugin-deps] running 'mvn", strings.Join(goals, " "), "' to build the install-lifecycle plugin allow-list")
	mvnOutput, err := mdt.RunMvnCmd(goals)
	if err != nil {
		log.Warn("[mvn-plugin-deps] mvn help:effective-pom failed - plugin filter disabled, all plugin deps will be reported. Reason:", err.Error())
		if len(mvnOutput) > 0 {
			log.Debug("[mvn-plugin-deps] mvn output (tail):\n", tailString(string(mvnOutput), 2000))
		}
		return nil
	}

	// #nosec G304 -- outputPath is from os.CreateTemp above, system-generated under $TMPDIR with a random suffix; never user-controlled.
	data, err := os.ReadFile(outputPath)
	if errors.Is(err, fs.ErrNotExist) {
		log.Warn("[mvn-plugin-deps] effective POM output file missing after mvn run - plugin filter disabled. Reason:", err.Error())
		return nil
	}
	if err != nil {
		log.Warn("[mvn-plugin-deps] failed to read effective POM output - plugin filter disabled. Reason:", err.Error())
		return nil
	}
	if len(data) == 0 {
		log.Warn("[mvn-plugin-deps] effective POM output file is empty - plugin filter disabled. The maven-help-plugin version may not honor -Doutput=")
		return nil
	}
	allowed := parseEffectivePomPluginCoordinates(string(data))
	if allowed == nil {
		log.Warn(fmt.Sprintf("[mvn-plugin-deps] effective POM parsed to empty allow-list (file size %d bytes) - plugin filter disabled", len(data)))
		preserveFile = true
	}
	return allowed
}

// tailString returns roughly the last n bytes of s, advancing to the next rune
// boundary so the result is always valid UTF-8 (off by at most 3 bytes vs n).
func tailString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	start := len(s) - n
	for start < len(s) && !utf8.RuneStart(s[start]) {
		start++
	}
	return "..." + s[start:]
}

// phasesNotRunByInstall is the set of lifecycle phases that `mvn install` never executes.
// Covers the single Default-lifecycle phase past install (deploy), the entire Site
// lifecycle, and the entire Clean lifecycle. A plugin whose only executions target
// these phases is excluded from the allow-list.
var phasesNotRunByInstall = map[string]struct{}{
	"pre-site":    {},
	"site":        {},
	"post-site":   {},
	"site-deploy": {},
	"deploy":      {},
	"pre-clean":   {},
	"clean":       {},
	"post-clean":  {},
}

// postInstallPluginsByDefault lists plugins whose default goal phase is past `install`,
// even when the effective POM declares them without explicit <executions>.
// Such plugins are excluded unless the user explicitly binds them to an install-lifecycle phase.
var postInstallPluginsByDefault = map[string]struct{}{
	"org.apache.maven.plugins:maven-deploy-plugin":  {},
	"org.apache.maven.plugins:maven-site-plugin":    {},
	"org.apache.maven.plugins:maven-release-plugin": {},
	"org.apache.maven.plugins:maven-gpg-plugin":     {},
}

// effectivePomProject mirrors the subset of fields we need from `mvn help:effective-pom`.
// A multi-module effective POM is wrapped in <projects>; we stream-decode <project> elements
// regardless of nesting depth so both single and multi-module outputs work.
type effectivePomProject struct {
	XMLName xml.Name          `xml:"project"`
	Build   effectivePomBuild `xml:"build"`
}

type effectivePomBuild struct {
	Plugins []effectivePomPlugin `xml:"plugins>plugin"`
}

type effectivePomPlugin struct {
	GroupID    string                  `xml:"groupId"`
	ArtifactID string                  `xml:"artifactId"`
	Executions []effectivePomExecution `xml:"executions>execution"`
}

type effectivePomExecution struct {
	Phase string `xml:"phase"`
}

// effectivePomXmlnsRe matches xmlns and xmlns:prefix attribute declarations.
// Maven emits the effective POM with xmlns="http://maven.apache.org/POM/4.0.0";
// stripping it lets our namespace-agnostic struct tags match the actual elements.
var effectivePomXmlnsRe = regexp.MustCompile(`\s+xmlns(?::[^=\s]+)?="[^"]*"`)

// mavenCoordRe matches both plugin headers and transitive dep lines in dependency:resolve-plugins output.
var mavenCoordRe = regexp.MustCompile(`\[INFO\]\s+([\w.\-]+):([\w.\-]+):(jar|war|pom|ear|aar|ejb|bundle|test-jar|maven-plugin):([\w.\-]+)(?::([\w.\-]+))?`)

// defaultPluginGroupID is the implicit groupId for plugins under the official Maven
// plugin namespace. The effective POM commonly omits <groupId> for these plugins,
// relying on this default.
const defaultPluginGroupID = "org.apache.maven.plugins"

// parseEffectivePomPluginCoordinates walks the effective POM XML and returns the
// allow-list of "groupId:artifactId" for plugins that participate in `mvn install`.
// Returns nil if the XML cannot be decoded — callers treat nil as "no filter".
func parseEffectivePomPluginCoordinates(xmlData string) map[string]struct{} {
	// Strip xmlns declarations so the struct-tag matcher works regardless of the
	// POM namespace declared by maven-help-plugin (defaults to maven.apache.org/POM/4.0.0).
	xmlData = effectivePomXmlnsRe.ReplaceAllString(xmlData, "")
	decoder := xml.NewDecoder(strings.NewReader(xmlData))
	allowed := map[string]struct{}{}
	projectsSeen, pluginsSeen, pluginsAllowed := 0, 0, 0
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "project" {
			continue
		}
		projectsSeen++
		var project effectivePomProject
		if err := decoder.DecodeElement(&project, &start); err != nil {
			// Skip malformed <project> blocks; effective-pom for one module shouldn't fail the rest.
			log.Debug("[mvn-plugin-deps] skipping malformed <project> block in effective POM:", err.Error())
			continue
		}
		for _, p := range project.Build.Plugins {
			pluginsSeen++
			groupID := p.GroupID
			if groupID == "" {
				// Maven's effective POM frequently omits <groupId> for org.apache.maven.plugins.
				groupID = defaultPluginGroupID
			}
			if p.ArtifactID == "" {
				continue
			}
			coord := groupID + ":" + p.ArtifactID
			if !isPluginInInstallLifecycle(coord, p.Executions) {
				continue
			}
			allowed[coord] = struct{}{}
			pluginsAllowed++
		}
	}
	log.Debug(fmt.Sprintf("[mvn-plugin-deps] effective POM scan: %d <project> blocks, %d <plugin> entries under <build><plugins>, %d allowed", projectsSeen, pluginsSeen, pluginsAllowed))
	if projectsSeen == 0 {
		// No <project> parsed — treat as malformed and fall back to "no filter".
		// An empty (non-nil) map is a valid result when every plugin was filtered out.
		return nil
	}
	return allowed
}

// isPluginInInstallLifecycle returns true when the plugin's executions (or default phase)
// fall within phases executed by `mvn install`.
func isPluginInInstallLifecycle(coord string, executions []effectivePomExecution) bool {
	// Single pass: keep an include if any explicit phase is in the install lifecycle,
	// otherwise fall back to the plugin's default phase.
	hasExplicit := false
	for _, ex := range executions {
		if ex.Phase == "" {
			continue
		}
		hasExplicit = true
		if _, skip := phasesNotRunByInstall[ex.Phase]; !skip {
			return true
		}
	}
	if !hasExplicit {
		_, isPostInstall := postInstallPluginsByDefault[coord]
		return !isPostInstall
	}
	return false
}

// mavenKnownScopes distinguishes a Maven scope from a classifier in a 5-field coordinate
// (g:a:packaging:field4:field5). If field5 is a known scope, field4 is the version.
var mavenKnownScopes = map[string]bool{
	"compile": true, "runtime": true, "test": true, "provided": true, "system": true,
}

// parseMavenPluginDeps parses "mvn dependency:resolve-plugins" output and returns a map of
// "groupId:artifactId:version" -> DepTreeNode for every resolved plugin dependency.
//
// When allowedPlugins is non-nil, only transitive deps of plugins in the allow-list are
// returned, filtering out plugins bound to post-install lifecycles (deploy, site, release).
// When allowedPlugins is nil all plugin deps are returned.
//
// Output formats matched:
//
//	[INFO]    g:a:maven-plugin:version:scope   (top-level plugin — switches the active filter)
//	[INFO]       g:a:jar:version               (transitive dep, no classifier)
//	[INFO]       g:a:jar:classifier:version    (transitive dep with classifier — version is last)
func parseMavenPluginDeps(output string, allowedPlugins map[string]struct{}) map[string]*xray.DepTreeNode {
	deps := map[string]*xray.DepTreeNode{}
	// includeCurrent gates whether transitive deps under the most recently seen top-level
	// plugin should be collected. nil allow-list means "include all".
	includeCurrent := allowedPlugins == nil
	for line := range strings.SplitSeq(output, "\n") {
		m := mavenCoordRe.FindStringSubmatch(line)
		if len(m) < 5 {
			continue
		}
		groupID, artifactID, packaging := m[1], m[2], m[3]
		version := m[4]
		if m[5] != "" && !mavenKnownScopes[m[5]] {
			// 5-field: g:a:packaging:classifier:version — m[4] is the classifier
			version = m[5]
		}
		// else: g:a:packaging:version:scope — version is already m[4]
		if packaging == "maven-plugin" {
			// Top-level plugin line — update the active filter for the indented transitive deps below.
			coord := groupID + ":" + artifactID
			if allowedPlugins == nil {
				includeCurrent = true
				log.Debug("[mvn-plugin-deps] top-level plugin (no filter active):", coord)
			} else if _, ok := allowedPlugins[coord]; ok {
				includeCurrent = true
				log.Debug("[mvn-plugin-deps] top-level plugin kept:", coord)
			} else {
				includeCurrent = false
				log.Debug("[mvn-plugin-deps] top-level plugin filtered out:", coord)
			}
			continue
		}
		if !includeCurrent {
			continue
		}
		nodeID := groupID + ":" + artifactID + ":" + version
		deps[nodeID] = &xray.DepTreeNode{Types: &[]string{packaging}}
	}
	return deps
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

// Creates a new settings.xml file configured with the provided server and repository from the current MavenDepTreeManager instance.
// The settings.xml will be written to the given path.
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
