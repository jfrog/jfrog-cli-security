package python

import (
	"encoding/json"
	"errors"
	"fmt"

	"net/http"
	"net/url"

	"github.com/jfrog/gofrog/version"

	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/build-info-go/utils/pythonutils"
	"github.com/jfrog/gofrog/datastructures"
	artifactoryutils "github.com/jfrog/jfrog-cli-artifactory/artifactory/commands/python"
	rtUtils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/artifactory"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/io/httputils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	clientutils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"
)

const (
	PythonPackageTypeIdentifier = "pypi://"
	pythonReportFile            = "report.json"
	poetryLockFile              = "poetry.lock"

	CurationPipMinimumVersion    = "23.0.0"
	PoetryNoInteractionFlag      = "--no-interaction"
	pyprojectToml                = "pyproject.toml"
	CurationPoetryMinimumVersion = "1.2.0"

	poetryDownloadUrlWorkers = 8
)

var (
	poetryLockFileEntry  = regexp.MustCompile(`\{[^}]*\bfile\s*=\s*"([^"]+)"`)
	simpleIndexHrefEntry = regexp.MustCompile(`<a\s+[^>]*href\s*=\s*"([^"]+)"`)
	// poetryVersionRegex matches the canonical "Poetry (version X.Y.Z)" line
	// emitted by `poetry --version`. Older Poetry releases (e.g. 1.2.x on macOS
	// with a legacy ~/Library/Application Support/pypoetry config dir) prepend
	// deprecation notices on stdout before this line, so we scan the full
	// output rather than assuming a single-line response.
	poetryVersionRegex = regexp.MustCompile(`Poetry \(?version\s+([^)\s]+)\)?`)
)

// parsePoetryVersion extracts the semantic version (e.g. "1.2.2") from the
// raw stdout of `poetry --version`. Returns "" if no version line is found.
func parsePoetryVersion(out string) string {
	m := poetryVersionRegex.FindStringSubmatch(out)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

func BuildDependencyTree(params technologies.BuildInfoBomGeneratorParams, technology techutils.Technology) (dependencyTree []*clientutils.GraphNode, uniqueDeps []string, downloadUrls map[string]string, err error) {
	rootDetected, dependenciesGraph, directDependenciesList, pipUrls, errGetTree := getDependencies(params, technology)
	if errGetTree != nil {
		err = errGetTree
		return
	}
	downloadUrls = pipUrls
	directDependencies := []*clientutils.GraphNode{}
	uniqueDepsSet := datastructures.MakeSet[string]()
	for _, rootDep := range directDependenciesList {
		directDependency := &clientutils.GraphNode{
			Id:    PythonPackageTypeIdentifier + rootDep,
			Nodes: []*clientutils.GraphNode{},
		}
		populatePythonDependencyTree(directDependency, dependenciesGraph, uniqueDepsSet)
		directDependencies = append(directDependencies, directDependency)
	}
	dependencyTree = getRootNodes(directDependencies, rootDetected)
	uniqueDeps = uniqueDepsSet.ToSlice()
	return
}

func getRootNodes(directDependencies []*clientutils.GraphNode, rootDetected bool) (roots []*clientutils.GraphNode) {
	if !rootDetected {
		return []*clientutils.GraphNode{{
			Id:    "root",
			Nodes: directDependencies,
		}}
	}
	// root was detected. in Pip, the pip version is also detected as root component.
	// In this case, we need to append the pip node to the actual roots.
	roots = []*clientutils.GraphNode{}
	var pipNode *clientutils.GraphNode
	// Search if pip is one of the direct dependencies.
	for _, dep := range directDependencies {
		if strings.HasPrefix(dep.Id, PythonPackageTypeIdentifier+techutils.Pip.String()+":") {
			pipNode = dep
		} else {
			roots = append(roots, dep)
		}
	}
	if pipNode != nil {
		// Append pip node to actual roots.
		for _, root := range roots {
			root.Nodes = append(root.Nodes, pipNode)
		}
	}
	return
}

func getDependencies(params technologies.BuildInfoBomGeneratorParams, technology techutils.Technology) (rootDetected bool, dependenciesGraph map[string][]string, directDependencies []string, downloadUrls map[string]string, err error) {
	wd, err := os.Getwd()
	if errorutils.CheckError(err) != nil {
		return
	}

	// Create temp dir to run all work outside users working directory
	tempDirPath, err := fileutils.CreateTempDir()
	if err != nil {
		return
	}
	log.Debug(fmt.Sprintf("Python (%s): created temp working dir at %s", technology, tempDirPath))

	err = os.Chdir(tempDirPath)
	if errorutils.CheckError(err) != nil {
		return
	}

	defer func() {
		err = errors.Join(
			err,
			errorutils.CheckError(os.Chdir(wd)),
			fileutils.RemoveTempDir(tempDirPath),
		)
	}()

	// Exclude Visual Studio inner directory since it is not necessary for the scan process and may cause race condition.
	err = biutils.CopyDir(wd, tempDirPath, true, []string{technologies.DotVsRepoSuffix})
	if err != nil {
		return
	}

	pythonTool := pythonutils.PythonTool(technology)
	if technology == techutils.Pipenv || !params.SkipAutoInstall {
		var restoreEnv func() error
		rootDetected, restoreEnv, err = runPythonInstall(params, pythonTool)
		defer func() {
			err = errors.Join(err, restoreEnv())
		}()
		if err != nil {
			return
		}
	} else {
		log.Debug(fmt.Sprintf("JF_SKIP_AUTO_INSTALL was set to 'true' with one of the following technologies: %s, %s. Skipping installation...\n"+
			"NOTE: in this case all dependencies must be manually pre-installed by the user", techutils.Pip, techutils.Poetry))
	}

	localDependenciesPath, err := config.GetJfrogDependenciesPath()
	if err != nil {
		return
	}
	dependenciesGraph, directDependencies, err = pythonutils.GetPythonDependencies(pythonTool, tempDirPath, localDependenciesPath, log.GetLogger())
	if err != nil {
		technologies.LogExecutableVersion("python")
		technologies.LogExecutableVersion(string(pythonTool))
	}
	if technology == techutils.Poetry {
		graphKeyByCanonicalName := make(map[string]string, len(dependenciesGraph))
		for k := range dependenciesGraph {
			if name, _, ok := strings.Cut(k, ":"); ok {
				graphKeyByCanonicalName[NormalizePypiName(name)] = k
			}
		}
		for i, d := range directDependencies {
			name, _, _ := strings.Cut(d, ":")
			if key, ok := graphKeyByCanonicalName[NormalizePypiName(name)]; ok {
				directDependencies[i] = key
			}
		}
	}
	if !params.IsCurationCmd {
		return
	}
	switch technology {
	case techutils.Pip:
		downloadUrls, err = processPipDownloadsUrlsFromReportFile()
	case techutils.Poetry:
		downloadUrls, err = buildPoetryDownloadUrlsMap(params.ServerDetails, params.DependenciesRepository)
		log.Debug(fmt.Sprintf("Poetry: curation download-URL map built — %d packages resolved", len(downloadUrls)))
	}
	return
}

func processPipDownloadsUrlsFromReportFile() (map[string]string, error) {
	pipReport, err := readPipReportIfExists()
	if err != nil {
		return nil, err
	}
	pipUrls := map[string]string{}
	for _, dep := range pipReport.Install {
		if dep.MetaData.Name != "" {
			compId := PythonPackageTypeIdentifier + strings.ToLower(dep.MetaData.Name) + ":" + dep.MetaData.Version
			pipUrls[compId] = strings.Replace(dep.DownloadInfo.Url, "api/curation/audit/", "", 1)
		}
	}
	return pipUrls, nil
}

func readPipReportIfExists() (pipReport *pypiReport, err error) {
	if exist, existErr := fileutils.IsFileExists(pythonReportFile, false); existErr != nil {
		err = existErr
		return
	} else if !exist {
		err = errors.New("process failed, report file wasn't found, cant processed with curation command")
		return
	}

	var reportBytes []byte
	if reportBytes, err = fileutils.ReadFile(pythonReportFile); err != nil {
		return
	}
	pipReport = &pypiReport{}
	if err = json.Unmarshal(reportBytes, pipReport); err != nil {
		return
	}
	return
}

type pypiReport struct {
	Install []pypiReportInfo
}

type pypiReportInfo struct {
	DownloadInfo pypiDownloadInfo `json:"download_info"`
	MetaData     pypiMetaData     `json:"metadata"`
}

type pypiDownloadInfo struct {
	Url string `json:"url"`
}

type pypiMetaData struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type poetryLockPackage struct {
	Name    string
	Version string
	Files   []string
}

func buildPoetryDownloadUrlsMap(serverDetails *config.ServerDetails, repository string) (map[string]string, error) {
	if serverDetails == nil || serverDetails.GetArtifactoryUrl() == "" {
		return nil, errorutils.CheckErrorf("server details with Artifactory URL are required for poetry curation")
	}
	if repository == "" {
		return nil, errorutils.CheckErrorf("a poetry repository must be configured (run 'jf poetry-config') for poetry curation")
	}
	packages, err := readPoetryLockIfExists()
	if err != nil {
		return nil, err
	}
	log.Debug(fmt.Sprintf("Poetry: parsed %d package entries from poetry.lock", len(packages)))
	rtAuth, err := serverDetails.CreateArtAuthConfig()
	if err != nil {
		return nil, err
	}
	rtManager, err := rtUtils.CreateServiceManager(serverDetails, 2, 0, false)
	if err != nil {
		return nil, err
	}
	httpClientDetails := rtAuth.CreateHttpClientDetails()
	artiUrl := strings.TrimSuffix(serverDetails.GetArtifactoryUrl(), "/")
	urls := map[string]string{}
	skipped := 0
	var mu sync.Mutex

	g := new(errgroup.Group)
	g.SetLimit(poetryDownloadUrlWorkers)
	for _, pkg := range packages {
		if pkg.Name == "" || pkg.Version == "" || len(pkg.Files) == 0 {
			skipped++
			continue
		}
		g.Go(func() error {
			return resolvePoetryPackageURL(rtManager, httpClientDetails, artiUrl, repository, pkg, urls, &mu)
		})
	}
	_ = g.Wait()

	expected := len(packages) - skipped
	resolved := len(urls)
	if resolved < expected {
		log.Warn(fmt.Sprintf(
			"Poetry: resolved download URLs for %d/%d packages — %d package(s) will not be HEAD-checked by curation. "+
				"Re-run with JFROG_CLI_LOG_LEVEL=DEBUG to see per-package resolution errors.",
			resolved, expected, expected-resolved))
	}
	log.Debug(fmt.Sprintf("Poetry: resolved %d download URLs (skipped %d entries with no files)", resolved, skipped))
	return urls, nil
}

func resolvePoetryPackageURL(rtManager artifactory.ArtifactoryServicesManager, httpClientDetails httputils.HttpClientDetails, artiUrl, repository string, pkg poetryLockPackage, urls map[string]string, mu *sync.Mutex) error {
	localDetails := httpClientDetails.Clone()
	downloadUrl, lookupErr := buildPoetryDownloadUrl(rtManager, localDetails, artiUrl, repository, pkg)
	if lookupErr != nil {
		log.Debug(fmt.Sprintf("Poetry: could not resolve download URL for %s:%s: %v", pkg.Name, pkg.Version, lookupErr))
		return nil
	}
	normalizedName := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(pkg.Name)), "-", "_")
	compId := PythonPackageTypeIdentifier + normalizedName + ":" + pkg.Version
	mu.Lock()
	urls[compId] = downloadUrl
	mu.Unlock()
	return nil
}

// buildPoetryDownloadUrl is the Poetry equivalent of npm's buildNpmDownloadUrl: given a
// package, it returns the absolute Artifactory download URL that curation will HEAD against.
// It does so by fetching the package's simple-index HTML and matching one of the filenames
// recorded in poetry.lock against the listed <a href>s.
func buildPoetryDownloadUrl(rtManager artifactory.ArtifactoryServicesManager, clientDetails *httputils.HttpClientDetails, artiUrl, repository string, pkg poetryLockPackage) (string, error) {
	normalized := NormalizePypiName(pkg.Name)
	simpleIndexUrl := fmt.Sprintf("%s/api/pypi/%s/simple/%s/", artiUrl, repository, normalized)
	log.Debug(fmt.Sprintf("Poetry: GET simple-index %s (matching against %d filenames)", simpleIndexUrl, len(pkg.Files)))
	resp, body, _, err := rtManager.Client().SendGet(simpleIndexUrl, true, clientDetails)
	if err != nil {
		return "", err
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		return "", fmt.Errorf("simple-index GET returned status %d for %s", status, simpleIndexUrl)
	}

	href := pickPoetryHrefByFilename(body, pkg.Files)
	if href == "" {
		return "", fmt.Errorf("no matching href found in simple index for any of %v", pkg.Files)
	}
	base, err := url.Parse(simpleIndexUrl)
	if err != nil {
		return "", err
	}
	target, err := url.Parse(href)
	if err != nil {
		return "", err
	}
	absolute := base.ResolveReference(target).String()
	log.Debug(fmt.Sprintf("Poetry: resolved %s:%s -> %s", pkg.Name, pkg.Version, absolute))
	return absolute, nil
}

// pickPoetryHrefByFilename scans the simple-index body for an <a href> whose filename
// (after stripping the optional "#sha256=..." fragment) matches one of the wanted filenames.
// Returns "" when no href matches. Mirrors the focused-helper style of npm's appendUniqueChild.
func pickPoetryHrefByFilename(body []byte, wantedFiles []string) string {
	wanted := make(map[string]struct{}, len(wantedFiles))
	for _, f := range wantedFiles {
		wanted[f] = struct{}{}
	}
	hrefMatches := simpleIndexHrefEntry.FindAllStringSubmatch(string(body), -1)
	for _, m := range hrefMatches {
		candidate, _, _ := strings.Cut(m[1], "#")
		if _, ok := wanted[path.Base(candidate)]; ok {
			return candidate
		}
	}
	return ""
}

func NormalizePypiName(name string) string {
	name = strings.ToLower(name)
	var b strings.Builder
	prevSep := false
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteByte('-')
				prevSep = true
			}
			continue
		}
		b.WriteRune(r)
		prevSep = false
	}
	return b.String()
}

func readPoetryLockIfExists() ([]poetryLockPackage, error) {
	exists, err := fileutils.IsFileExists(poetryLockFile, false)
	if err != nil {
		return nil, errorutils.CheckError(err)
	}
	if !exists {
		return nil, errorutils.CheckErrorf("%s not found — run 'poetry lock' to generate it before running 'jf ca'", poetryLockFile)
	}
	content, err := os.ReadFile(poetryLockFile)
	if err != nil {
		return nil, errorutils.CheckError(err)
	}
	log.Debug(fmt.Sprintf("Poetry: reading %s (%d bytes)", poetryLockFile, len(content)))
	return parsePoetryLockPackages(content), nil
}

func parsePoetryLockPackages(content []byte) []poetryLockPackage {
	var packages []poetryLockPackage
	var current *poetryLockPackage
	nameToIdx := map[string]int{}
	inMetadataFiles := false
	currentMetaPkg := ""
	lockVersion := ""

	flush := func() {
		if current != nil {
			key := strings.ToLower(current.Name)
			if _, dup := nameToIdx[key]; dup {
				log.Warn(fmt.Sprintf("Poetry lock: duplicate package name %q — keeping first entry, skipping index update", current.Name))
			} else {
				nameToIdx[key] = len(packages)
			}
			packages = append(packages, *current)
			current = nil
		}
	}

	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if line == "[[package]]" {
			flush()
			inMetadataFiles = false
			current = &poetryLockPackage{}
			continue
		}
		if lockVersion == "" && strings.HasPrefix(line, "lock-version") {
			if v, ok := parsePoetryScalar(line, "lock-version"); ok {
				lockVersion = v
			}
		}
		if strings.HasPrefix(line, "[") {
			flush()
			inMetadataFiles = line == "[metadata.files]"
			currentMetaPkg = ""
			continue
		}
		// lock v1.x: files live in [metadata.files] as  pkgname = [{file = "..."},]
		if inMetadataFiles {
			if key, value, ok := strings.Cut(line, "="); ok && strings.HasPrefix(strings.TrimSpace(value), "[") {
				currentMetaPkg = strings.ToLower(strings.Trim(strings.TrimSpace(key), `"`))
			} else if currentMetaPkg != "" {
				for _, m := range poetryLockFileEntry.FindAllStringSubmatch(line, -1) {
					if idx, ok := nameToIdx[currentMetaPkg]; ok {
						packages[idx].Files = append(packages[idx].Files, m[1])
					}
				}
			}
			continue
		}
		if current == nil {
			continue
		}
		if current.Name == "" && strings.HasPrefix(line, "name") {
			if v, ok := parsePoetryScalar(line, "name"); ok {
				current.Name = v
				continue
			}
		}
		if current.Version == "" && strings.HasPrefix(line, "version") {
			if v, ok := parsePoetryScalar(line, "version"); ok {
				current.Version = v
				continue
			}
		}
		for _, m := range poetryLockFileEntry.FindAllStringSubmatch(line, -1) {
			current.Files = append(current.Files, m[1])
		}
	}
	flush()
	log.Debug(fmt.Sprintf("Poetry lock: done — %d packages parsed, lock version: %s", len(packages), lockVersion))
	return packages
}

func parsePoetryScalar(line, key string) (string, bool) {
	rest := strings.TrimSpace(strings.TrimPrefix(line, key))
	if !strings.HasPrefix(rest, "=") {
		return "", false
	}
	rest = strings.TrimSpace(strings.TrimPrefix(rest, "="))
	if !strings.HasPrefix(rest, `"`) {
		return "", false
	}
	rest = rest[1:]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}

func runPythonInstall(params technologies.BuildInfoBomGeneratorParams, tool pythonutils.PythonTool) (rootDetected bool, restoreEnv func() error, err error) {
	switch tool {
	case pythonutils.Pip:
		return installPipDeps(params)
	case pythonutils.Pipenv:
		return installPipenvDeps(params)
	case pythonutils.Poetry:
		return installPoetryDeps(params)
	}
	return
}

func installPoetryDeps(params technologies.BuildInfoBomGeneratorParams) (rootDetected bool, restoreEnv func() error, err error) {
	restoreEnv = func() error {
		return nil
	}
	technologies.LogExecutableVersion("poetry")

	var poetryMajor int
	if params.IsCurationCmd {
		if poetryMajor, err = validateMinimumPoetryVersion(CurationPoetryMinimumVersion); err != nil {
			return false, restoreEnv, err
		}
	}
	// jf ca: check lock staleness BEFORE changing the source URL.
	// Poetry 1.x stores the source URL in poetry.lock — swapping the URL first causes a
	// false stale result even when no dependencies changed.
	//   lockNeedsGenerate = true  → no lock file, generate fresh
	//   lockIsStale       = true  → lock exists but is out of sync with pyproject.toml
	lockNeedsGenerate, lockIsStale := false, false
	var lockCheckErr error
	if params.IsCurationCmd {
		lockExists, existErr := fileutils.IsFileExists(poetryLockFile, false)
		if existErr != nil {
			return false, restoreEnv, existErr
		}
		log.Debug(fmt.Sprintf("Poetry: poetry.lock exists in temp dir: %v", lockExists))
		if !lockExists {
			lockNeedsGenerate = true
		} else {
			// `poetry check --lock` exits 0 when lock matches pyproject.toml (Poetry 1.8+/2.x).
			// Older versions expose the same check via `poetry lock --check`.
			_, lockCheckErr = executeCommand("poetry", "check", "--lock")
			if lockCheckErr != nil && strings.Contains(lockCheckErr.Error(), "does not exist") {
				log.Debug("Poetry: 'poetry check --lock' not supported, falling back to 'poetry lock --check'")
				_, lockCheckErr = executeCommand("poetry", "lock", "--check")
			}
			lockIsStale = lockCheckErr != nil
			log.Debug(fmt.Sprintf("Poetry: stale check result: stale=%v", lockIsStale))
		}
	}

	if params.DependenciesRepository != "" {
		rtUrl, username, password, err := artifactoryutils.GetPypiRepoUrlWithCredentials(params.ServerDetails, params.DependenciesRepository, params.IsCurationCmd)
		if err != nil {
			return false, restoreEnv, err
		}
		baseUrl := rtUrl.Scheme + "://" + rtUrl.Host + rtUrl.Path
		if params.IsCurationCmd {
			// Overwrite [[tool.poetry.source]] in the temp pyproject.toml with the curation
			// pass-through URL.
			if err = setCurationSourceInPyproject(params.DependenciesRepository, baseUrl, poetryMajor); err != nil {
				return false, restoreEnv, err
			}
		}
		if password != "" {
			if params.IsCurationCmd {
				if _, err = executeCommand("poetry", "config", "--local", "repositories."+params.DependenciesRepository, baseUrl); err != nil {
					return false, restoreEnv, err
				}
				// poetry config --local http-basic.<name> <user> <pass>
				if _, err = executeCommand("poetry", "config", "--local", "http-basic."+params.DependenciesRepository, username, password); err != nil {
					return false, restoreEnv, err
				}
			} else {
				if err = artifactoryutils.ConfigPoetryRepo(baseUrl, username, password, params.DependenciesRepository); err != nil {
					return false, restoreEnv, err
				}
			}
		}
	}

	if params.IsCurationCmd {
		switch {
		case lockNeedsGenerate:
			// No lock file — generate fresh.
			if _, lockErr := executeCommand("poetry", "lock", PoetryNoInteractionFlag); lockErr != nil {
				return false, restoreEnv, wrapPoetryCurationErr(lockErr)
			}
			log.Debug("Poetry: lock generated")
		case lockIsStale:
			// Lock exists but is out of sync — add new/changed deps without bumping locked versions.
			// `--no-update` is Poetry 1.x; Poetry 2.x removed the flag (its default is no-update).
			_, lockErr := executeCommand("poetry", "lock", "--no-update", PoetryNoInteractionFlag)
			if lockErr != nil && strings.Contains(lockErr.Error(), "does not exist") {
				log.Debug("Poetry: '--no-update' not supported (Poetry 2.x), running 'poetry lock --no-interaction'")
				_, lockErr = executeCommand("poetry", "lock", PoetryNoInteractionFlag)
			}
			if lockErr != nil {
				return false, restoreEnv, wrapPoetryCurationErr(errors.Join(lockCheckErr, lockErr))
			}
			log.Debug("Poetry: lock updated")
		default:
			log.Debug("Poetry: poetry.lock is up to date — skipping lock")
		}
	} else {
		_, err = executeCommand("poetry", "install")
	}
	return false, restoreEnv, err
}

func wrapPoetryCurationErr(lockErr error) error {
	if lockErr == nil {
		return nil
	}
	if isCvsVersionFilteredOutput(lockErr.Error()) {
		return &CvsBlockedError{Packages: parseCvsFailedPackages(lockErr.Error()), Cause: lockErr}
	}
	if msgToUser := technologies.GetMsgToUserForCurationBlock(true, techutils.Poetry, lockErr.Error()); msgToUser != "" {
		return errors.Join(lockErr, errors.New(msgToUser))
	}
	return lockErr
}

// setCurationSourceInPyproject rewrites [[tool.poetry.source]] in the temp
// pyproject.toml so that every dependency resolves through the curation
// pass-through endpoint. The source NAME(s) from the user's original
// pyproject.toml are preserved; only the URL is overwritten.
//
// Why preserve the name: poetry.lock records every package against its
// source NAME (not URL). If we renamed the source here, an existing lock
// would suddenly reference a source that no longer exists, Poetry would
// abort the relock with "Repository '<old-name>' does not exist".
// Preserving the name keeps the lock valid and lets the normal post-lock
// pipeline (with HEAD probes against the wheel URLs) run as designed.
//
// If pyproject.toml has no [[tool.poetry.source]] at all, we fall back to
// adding a single entry named after the Artifactory repository so Poetry
// has somewhere to resolve from.
func setCurationSourceInPyproject(repoName, repoUrl string, majorVersion int) error {
	currentDir, err := os.Getwd()
	if err != nil {
		return errorutils.CheckError(err)
	}
	absPath := filepath.Join(currentDir, pyprojectToml)
	v := viper.New()
	v.SetConfigType("toml")
	v.SetConfigFile(absPath)
	if err = v.ReadInConfig(); err != nil {
		return errorutils.CheckErrorf("failed to read %s: %s", pyprojectToml, err)
	}

	names := extractPoetrySourceNames(v.Get("tool.poetry.source"))
	if len(names) == 0 {
		names = []string{repoName}
	}
	raw, err := os.ReadFile(absPath)
	if err != nil {
		return errorutils.CheckError(err)
	}
	var buf strings.Builder
	buf.WriteString(strings.TrimRight(stripPoetrySourceBlocks(string(raw)), "\n"))
	setDefault := majorVersion < 2
	for i, n := range names {
		buf.WriteString("\n\n[[tool.poetry.source]]\n")
		fmt.Fprintf(&buf, "name = %q\n", n)
		fmt.Fprintf(&buf, "url = %q\n", repoUrl)
		if setDefault && i == 0 {
			buf.WriteString("default = true\n")
		}
		log.Info(fmt.Sprintf("Configured tool.poetry.source name:%q url:%q for curation", n, repoUrl))
	}
	if err = os.WriteFile(absPath, []byte(buf.String()), 0600); err != nil {
		return errorutils.CheckErrorf("failed to write %s: %s", pyprojectToml, err)
	}
	return nil
}

func stripPoetrySourceBlocks(content string) string {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	inSourceBlock := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[[tool.poetry.source]]") {
			inSourceBlock = true
			continue
		}
		if inSourceBlock && strings.HasPrefix(trimmed, "[") {
			inSourceBlock = false
		}
		if !inSourceBlock {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// extractPoetrySourceNames returns the canonical list of source names from
// viper's view of `[[tool.poetry.source]]`. Entries without a name, or with
// duplicate names, are skipped. Returns nil when the key is missing or has
// an unexpected shape so callers can fall back to a default.
func extractPoetrySourceNames(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	names := make([]string, 0, len(arr))
	seen := map[string]struct{}{}
	for _, e := range arr {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		n, _ := m["name"].(string)
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		names = append(names, n)
	}
	return names
}

func validateMinimumPoetryVersion(minVersion string) (int, error) {
	out, err := executeCommand("poetry", "--version")
	if err != nil {
		log.Debug(fmt.Sprintf("Poetry is not installed or not on PATH: %v", err))
		return 0, errorutils.CheckErrorf("JFrog CLI poetry curation requires Poetry %s or higher to be installed.", minVersion)
	}
	v := parsePoetryVersion(out)
	if v == "" {
		log.Debug(fmt.Sprintf("Could not parse Poetry version from output: %q", out))
		return 0, errorutils.CheckErrorf("Could not parse Poetry version from output %q — ensure Poetry %s or higher is installed correctly", out, minVersion)
	}
	log.Debug(fmt.Sprintf("Poetry version: %s", v))
	if !version.NewVersion(v).AtLeast(minVersion) {
		return 0, errorutils.CheckErrorf("JFrog CLI poetry curation requires Poetry %s or higher. The current version is: %s", minVersion, v)
	}
	dot := strings.IndexByte(v, '.')
	if dot < 0 {
		dot = len(v)
	}
	major, parseErr := strconv.Atoi(v[:dot])
	if parseErr != nil {
		return 0, errorutils.CheckErrorf("could not parse Poetry version from %q: %s", v, parseErr.Error())
	}
	return major, nil
}

func installPipenvDeps(params technologies.BuildInfoBomGeneratorParams) (rootDetected bool, restoreEnv func() error, err error) {
	// Set virtualenv path to venv dir
	err = os.Setenv("WORKON_HOME", ".jfrog")
	if err != nil {
		return
	}
	restoreEnv = func() error {
		return os.Unsetenv("WORKON_HOME")
	}
	if params.DependenciesRepository != "" {
		return false, restoreEnv, runPipenvInstallFromRemoteRegistry(params.ServerDetails, params.DependenciesRepository)
	}
	// Run 'pipenv install -d'
	_, err = executeCommand("pipenv", "install", "-d")
	return false, restoreEnv, err
}

func installPipDeps(params technologies.BuildInfoBomGeneratorParams) (setupFileUsed bool, restoreEnv func() error, err error) {
	restoreEnv, err = SetPipVirtualEnvPath()
	if err != nil {
		return
	}

	remoteUrl := ""
	if params.DependenciesRepository != "" {
		remoteUrl, err = artifactoryutils.GetPypiRepoUrl(params.ServerDetails, params.DependenciesRepository, params.IsCurationCmd)
		if err != nil {
			return
		}
	}

	var curationCachePip string
	var reportFileName string
	if params.IsCurationCmd {
		// upgrade pip version to 23.0.0, as it is required for the curation command.
		if err = upgradePipVersion(CurationPipMinimumVersion); err != nil {
			log.Warn(fmt.Sprintf("Failed to upgrade pip version, err: %v", err))
		}
		if curationCachePip, err = utils.GetCurationPipCacheFolder(); err != nil {
			return
		}
		reportFileName = pythonReportFile
	}
	setupFileUsed = params.PipRequirementsFile == ""
	pipInstallArgs := getPipInstallArgs(params.PipRequirementsFile, remoteUrl, curationCachePip, reportFileName, params.InstallCommandArgs...)
	var reqErr error
	_, err = executeCommand("python", pipInstallArgs...)
	if err != nil && params.PipRequirementsFile == "" {
		pipInstallArgs = getPipInstallArgs("requirements.txt", remoteUrl, curationCachePip, reportFileName, params.InstallCommandArgs...)
		_, reqErr = executeCommand("python", pipInstallArgs...)
		if reqErr != nil {
			// Return Pip install error and log the requirements fallback error.
			log.Debug(reqErr.Error())
		} else {
			err = nil
		}
		setupFileUsed = false
	}
	// When CVS hides the pinned version from the simple-index, pip fails with
	// "No matching distribution found" instead of hitting a 403. Return a
	// structured CvsBlockedError so the curation-audit command can recover
	// policy details via the PyPI metadata-API fallback and still produce a
	// (partial) curation table instead of failing with no report at all.
	if err != nil && params.IsCurationCmd && remoteUrl != "" {
		if combinedOutput := errors.Join(err, reqErr).Error(); isCvsVersionFilteredOutput(combinedOutput) {
			err = &CvsBlockedError{Packages: parseCvsFailedPackages(combinedOutput), Cause: err}
		}
	}
	if err != nil || reqErr != nil {
		if msgToUser := technologies.GetMsgToUserForCurationBlock(params.IsCurationCmd, techutils.Pip, errors.Join(err, reqErr).Error()); msgToUser != "" {
			err = errors.Join(err, errors.New(msgToUser))
		}
	}
	return
}

func upgradePipVersion(atLeastVersion string) (err error) {
	output, err := executeCommand("python", "-m", "pip", "--version")
	if err != nil {
		return
	}
	outputVersion := ""
	if splitVersion := strings.Split(output, " "); len(splitVersion) > 1 {
		outputVersion = splitVersion[1]
	}
	log.Debug("Current pip version in virtual env:", outputVersion)
	if version.NewVersion(outputVersion).AtLeast(atLeastVersion) {
		return
	}
	_, err = executeCommand("python", "-m", "pip", "install", "--upgrade", "pip")
	return
}

func executeCommand(executable string, args ...string) (string, error) {
	installCmd := exec.Command(executable, args...)
	maskedCmdString := coreutils.GetMaskedCommandString(installCmd)
	log.Debug("Running", maskedCmdString)
	output, err := installCmd.CombinedOutput()
	if err != nil {
		technologies.LogExecutableVersion(executable)
		return string(output), errorutils.CheckErrorf("%q command failed: %s - %s", maskedCmdString, err.Error(), output)
	}
	return string(output), nil
}

func getPipInstallArgs(requirementsFile, remoteUrl, cacheFolder, reportFileName string, customArgs ...string) []string {
	args := []string{"-m", "pip", "install"}
	if requirementsFile == "" {
		// Run 'pip install .'
		args = append(args, ".")
	} else {
		// Run pip 'install -r requirements <requirementsFile>'
		args = append(args, "-r", requirementsFile)
	}
	if remoteUrl != "" {
		args = append(args, artifactoryutils.GetPypiRemoteRegistryFlag(pythonutils.Pip), remoteUrl)
	}
	if cacheFolder != "" {
		args = append(args, "--cache-dir", cacheFolder)
	}
	if reportFileName != "" {
		// For report to include download urls, pip should ignore installed packages.
		args = append(args, "--ignore-installed")
		args = append(args, "--report", reportFileName)
	}
	args = append(args, parseCustomArgs(remoteUrl, cacheFolder, reportFileName, customArgs...)...)
	return args
}

func parseCustomArgs(remoteUrl, cacheFolder, reportFileName string, customArgs ...string) (args []string) {
	for i := 0; i < len(customArgs); i++ {
		if strings.Contains(customArgs[i], "-r") {
			log.Warn("The -r flag is not supported in the custom arguments list. use the 'PipRequirementsFile' instead.")
			i++
			continue
		}
		if strings.Contains(customArgs[i], "--cache-dir") {
			if cacheFolder != "" {
				log.Warn("The --cache-dir flag is not supported in the custom arguments list. skipping...")
			} else if i+1 < len(customArgs) {
				args = append(args, customArgs[i], customArgs[i+1])
			}
			i++
			continue
		}
		if reportFileName != "" {
			if strings.Contains(customArgs[i], "--report") {
				log.Warn("The --report flag is not supported in the custom arguments list. skipping...")
				i++
				continue
			}
			if strings.Contains(customArgs[i], "--ignore-installed") {
				// will be added by default
				continue
			}
		}
		if remoteUrl != "" && strings.Contains(customArgs[i], artifactoryutils.GetPypiRemoteRegistryFlag(pythonutils.Pip)) {
			log.Warn("The remote registry flag is not supported in the custom arguments list. skipping...")
			i++
			continue
		}
		args = append(args, customArgs[i])
	}
	return
}

func runPipenvInstallFromRemoteRegistry(server *config.ServerDetails, depsRepoName string) (err error) {
	rtUrl, err := artifactoryutils.GetPypiRepoUrl(server, depsRepoName, false)
	if err != nil {
		return err
	}
	args := []string{"install", "-d", artifactoryutils.GetPypiRemoteRegistryFlag(pythonutils.Pipenv), rtUrl}
	_, err = executeCommand("pipenv", args...)
	return err
}

// Execute virtualenv command: "virtualenv venvdir" / "python3 -m venv venvdir" and set path
func SetPipVirtualEnvPath() (restoreEnv func() error, err error) {
	restoreEnv = func() error {
		return nil
	}
	venvdirName := "venvdir"
	var cmdArgs []string
	pythonPath, windowsPyArg := pythonutils.GetPython3Executable(true)
	if windowsPyArg != "" {
		// Add '-3' arg for windows 'py -3' command
		cmdArgs = append(cmdArgs, windowsPyArg)
	}
	cmdArgs = append(cmdArgs, "-m", "venv", venvdirName)
	_, err = executeCommand(pythonPath, cmdArgs...)
	if err != nil {
		// Failed running 'python -m venv', trying to run 'virtualenv'
		log.Debug("Failed running python venv:", err.Error())
		_, err = executeCommand("virtualenv", "-p", pythonPath, venvdirName)
		if err != nil {
			return
		}
	}

	// Keep original value of 'PATH'.
	origPathValue := os.Getenv("PATH")
	venvPath, err := filepath.Abs(venvdirName)
	if err != nil {
		return
	}
	var venvBinPath string
	if runtime.GOOS == "windows" {
		venvBinPath = filepath.Join(venvPath, "Scripts")
	} else {
		venvBinPath = filepath.Join(venvPath, "bin")
	}
	err = os.Setenv("PATH", fmt.Sprintf("%s%c%s", venvBinPath, os.PathListSeparator, origPathValue))
	if err != nil {
		return
	}
	restoreEnv = func() error {
		return os.Setenv("PATH", origPathValue)
	}
	return
}

func populatePythonDependencyTree(currNode *clientutils.GraphNode, dependenciesGraph map[string][]string, uniqueDepsSet *datastructures.Set[string]) {
	if currNode.NodeHasLoop() {
		return
	}
	uniqueDepsSet.Add(currNode.Id)
	currDepChildren := dependenciesGraph[strings.TrimPrefix(currNode.Id, PythonPackageTypeIdentifier)]
	// Recursively create & append all node's dependencies.
	for _, dependency := range currDepChildren {
		childNode := &clientutils.GraphNode{
			Id:     PythonPackageTypeIdentifier + dependency,
			Nodes:  []*clientutils.GraphNode{},
			Parent: currNode,
		}
		currNode.Nodes = append(currNode.Nodes, childNode)
		populatePythonDependencyTree(childNode, dependenciesGraph, uniqueDepsSet)
	}
}
