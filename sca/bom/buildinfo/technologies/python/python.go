package python

import (
	"encoding/json"
	"errors"
	"fmt"

	"net/http"
	"net/url"

	"github.com/BurntSushi/toml"
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
	"github.com/subosito/gotenv"
	"golang.org/x/sync/errgroup"
	"gopkg.in/ini.v1"
)

const (
	PythonPackageTypeIdentifier = "pypi://"
	pythonReportFile            = "report.json"
	poetryLockFile              = "poetry.lock"

	CurationPipMinimumVersion    = "23.0.0"
	PoetryNoInteractionFlag      = "--no-interaction"
	pyprojectToml                = "pyproject.toml"
	CurationPoetryMinimumVersion = "1.2.0"
	CurationPipenvMinimumVersion = "2023.7.4"
	pipfileFile                  = "Pipfile"
	pipfileLockFile              = "Pipfile.lock"

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

	// pipenvVersionRegex matches the date-based version emitted by `pipenv --version`,
	// e.g. "pipenv, version 2023.7.4" or "pipenv, version 2026.6.1".
	pipenvVersionRegex = regexp.MustCompile(`pipenv,\s+version\s+(\S+)`)
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

	if shouldRunPythonInstall(params, technology) {
		var restoreEnv func() error
		rootDetected, restoreEnv, err = runPythonInstall(params, pythonTool)
		defer func() {
			err = errors.Join(err, restoreEnv())
		}()
		if err != nil {
			return
		}
	} else {
		log.Debug(fmt.Sprintf("JF_SKIP_AUTO_INSTALL was set to 'true' for %s. Skipping installation...\n"+
			"NOTE: in this case all dependencies must be manually pre-installed by the user", technology))
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
	case techutils.Pipenv:
		downloadUrls, err = buildPipenvDownloadUrlsMap(params.ServerDetails, params.DependenciesRepository)
		log.Debug(fmt.Sprintf("Pipenv: curation download-URL map built — %d packages resolved", len(downloadUrls)))
	}
	return
}

func shouldRunPythonInstall(params technologies.BuildInfoBomGeneratorParams, technology techutils.Technology) bool {
	return !params.SkipAutoInstall || (technology == techutils.Pipenv && params.IsCurationCmd)
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

// buildPoetryDownloadUrl fetches the simple-index HTML for a package and returns
// the Artifactory download URL matching a filename in poetry.lock.
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

// pickPoetryHrefByFilename returns the first href whose filename (sans "#sha256=…" fragment)
// matches one of wantedFiles, or "" if none match.
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

// pipfileLockEntry is one package entry in Pipfile.lock's "default" or "develop" section.
type pipfileLockEntry struct {
	Version  string   `json:"version"`
	Hashes   []string `json:"hashes"`
	Index    string   `json:"index"`
	File     string   `json:"file"`
	URL      string   `json:"url"`
	Path     string   `json:"path"`
	Editable bool     `json:"editable"`
	Git      string   `json:"git"`
	Hg       string   `json:"hg"`
	Svn      string   `json:"svn"`
	Bzr      string   `json:"bzr"`
	Unknown  []string `json:"-"`
}

func (e *pipfileLockEntry) UnmarshalJSON(data []byte) error {
	type lockEntryAlias pipfileLockEntry
	var decoded lockEntryAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	known := map[string]struct{}{
		"version": {}, "hashes": {}, "index": {}, "file": {}, "url": {}, "path": {},
		"editable": {}, "git": {}, "hg": {}, "svn": {}, "bzr": {}, "ref": {},
		"subdirectory": {}, "markers": {}, "extras": {},
	}
	for field := range fields {
		if _, ok := known[field]; !ok {
			decoded.Unknown = append(decoded.Unknown, field)
		}
	}
	*e = pipfileLockEntry(decoded)
	return nil
}

// pipfileLockContent is the top-level structure of Pipfile.lock.
type pipfileLockContent struct {
	Default map[string]pipfileLockEntry `json:"default"`
	Develop map[string]pipfileLockEntry `json:"develop"`
}

// pipfileLockPackage holds the name, resolved version, and file hashes for one
// locked package, extracted from Pipfile.lock for use in the curation URL map.
type pipfileLockPackage struct {
	Name    string
	Version string   // bare version, e.g. "2.0.7" (== prefix stripped)
	Hashes  []string // e.g. ["sha256:abc123..."]
}

// buildPipenvDownloadUrlsMap reads Pipfile.lock, then resolves each package's
// download URL from the simple index so fetchNodeStatus can HEAD-probe for blocks.
func buildPipenvDownloadUrlsMap(serverDetails *config.ServerDetails, repository string) (map[string]string, error) {
	if serverDetails == nil || serverDetails.GetArtifactoryUrl() == "" {
		return nil, errorutils.CheckErrorf("server details with Artifactory URL are required for pipenv curation")
	}
	if repository == "" {
		return nil, errorutils.CheckErrorf("a pipenv Artifactory repository must be configured for curation")
	}
	packages, err := readPipfileLockPackages()
	if err != nil {
		return nil, err
	}
	log.Debug(fmt.Sprintf("Pipenv: parsed %d package entries from Pipfile.lock", len(packages)))
	rtAuth, err := serverDetails.CreateArtAuthConfig()
	if err != nil {
		return nil, err
	}
	rtManager, err := rtUtils.CreateServiceManager(serverDetails, 0, 0, false)
	if err != nil {
		return nil, err
	}
	httpClientDetails := rtAuth.CreateHttpClientDetails()
	artiUrl := strings.TrimSuffix(serverDetails.GetArtifactoryUrl(), "/")
	urls := map[string]string{}
	var mu sync.Mutex
	var lookupErrs []error

	g := new(errgroup.Group)
	g.SetLimit(poetryDownloadUrlWorkers)
	for _, pkg := range packages {
		g.Go(func() error {
			return resolvePipenvPackageURL(rtManager, httpClientDetails, artiUrl, repository, pkg, urls, &mu, &lookupErrs)
		})
	}
	_ = g.Wait() // failures are collected into lookupErrs, not returned here

	if len(lookupErrs) > 0 {
		// Unresolved packages are never HEAD-checked; fail loudly instead of a false-clean partial audit.
		return nil, errorutils.CheckErrorf(
			"pipenv: failed to resolve download URLs for %d of %d package(s) — curation cannot verify these packages: %s",
			len(lookupErrs), len(packages), errors.Join(lookupErrs...))
	}
	log.Debug(fmt.Sprintf("Pipenv: resolved %d download URLs", len(urls)))
	return urls, nil
}

func resolvePipenvPackageURL(rtManager artifactory.ArtifactoryServicesManager, httpClientDetails httputils.HttpClientDetails, artiUrl, repository string, pkg pipfileLockPackage, urls map[string]string, mu *sync.Mutex, lookupErrs *[]error) error {
	localDetails := httpClientDetails.Clone()
	downloadUrl, lookupErr := buildPipenvDownloadUrl(rtManager, localDetails, artiUrl, repository, pkg)
	if lookupErr != nil {
		mu.Lock()
		*lookupErrs = append(*lookupErrs, fmt.Errorf("%s:%s: %w", pkg.Name, pkg.Version, lookupErr))
		mu.Unlock()
		return nil
	}
	// PEP 503 normalization keeps the map key aligned with the hyphenated pipenv graph node IDs.
	normalizedName := NormalizePypiName(pkg.Name)
	compId := PythonPackageTypeIdentifier + normalizedName + ":" + pkg.Version
	mu.Lock()
	urls[compId] = downloadUrl
	mu.Unlock()
	return nil
}

// buildPipenvDownloadUrl fetches the regular (non-curation) simple-index page for
// a package and returns the absolute download URL whose sha256 fragment matches
// one of the hashes recorded in Pipfile.lock.
func buildPipenvDownloadUrl(rtManager artifactory.ArtifactoryServicesManager, clientDetails *httputils.HttpClientDetails, artiUrl, repository string, pkg pipfileLockPackage) (string, error) {
	normalized := NormalizePypiName(pkg.Name)
	repositoryURL := fmt.Sprintf("%s/api/pypi/%s/", artiUrl, repository)
	boundary, err := utils.NewEndpointBoundary(repositoryURL)
	if err != nil {
		return "", err
	}
	simpleIndexUrl := repositoryURL + "simple/" + normalized + "/"
	log.Debug(fmt.Sprintf("Pipenv: GET simple-index %s (matching against %d hashes)", simpleIndexUrl, len(pkg.Hashes)))
	resp, body, err := utils.SendWithBoundedRedirects(rtManager.Client(), http.MethodGet, simpleIndexUrl,
		clientDetails, boundary, utils.MaxAuthenticatedRedirects)
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

	// Pipfile.lock stores hashes as "sha256:abc123"; the simple-index URL fragment
	// uses "#sha256=abc123". Convert and build a lookup set.
	wantedFragments := make(map[string]struct{}, len(pkg.Hashes))
	for _, h := range pkg.Hashes {
		// "sha256:abc123" → "#sha256=abc123"
		wantedFragments["#"+strings.Replace(h, ":", "=", 1)] = struct{}{}
	}

	href := pickHrefByHashFragment(body, wantedFragments)
	if href == "" {
		return "", fmt.Errorf("no matching href found in simple index for %s (checked %d hashes)", pkg.Name, len(pkg.Hashes))
	}
	base, err := url.Parse(simpleIndexUrl)
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(href)
	if err != nil {
		return "", err
	}
	absolute := base.ResolveReference(ref)
	if err := boundary.Validate(absolute.String()); err != nil {
		return "", fmt.Errorf("resolved href %q for %s escapes the configured Artifactory endpoint %q", href, pkg.Name, artiUrl)
	}
	// Strip the fragment — fetchNodeStatus only needs the bare download URL.
	absolute.Fragment = ""
	log.Debug(fmt.Sprintf("Pipenv: resolved %s:%s -> %s", pkg.Name, pkg.Version, absolute))
	return absolute.String(), nil
}

// pickHrefByHashFragment scans the simple-index body for an <a href> whose URL
// fragment (the "#sha256=..." part) matches one of the wanted fragments.
func pickHrefByHashFragment(body []byte, wantedFragments map[string]struct{}) string {
	hrefMatches := simpleIndexHrefEntry.FindAllStringSubmatch(string(body), -1)
	for _, m := range hrefMatches {
		href := m[1]
		if idx := strings.Index(href, "#"); idx >= 0 {
			if _, ok := wantedFragments[href[idx:]]; ok {
				return href
			}
		}
	}
	return ""
}

func readPipfileLockPackages() ([]pipfileLockPackage, error) {
	exists, err := fileutils.IsFileExists(pipfileLockFile, false)
	if err != nil {
		return nil, errorutils.CheckError(err)
	}
	if !exists {
		// 'pipenv install' (run earlier in this flow) auto-generates Pipfile.lock when
		// missing, so reaching this point means it unexpectedly failed to do so —
		// this is not something the user needs to fix manually.
		return nil, errorutils.CheckErrorf("pipenv: Pipfile.lock is unexpectedly missing after 'pipenv install' completed successfully")
	}
	content, err := os.ReadFile(pipfileLockFile) // #nosec G304 -- temp-dir copy of the project's Pipfile.lock
	if err != nil {
		return nil, errorutils.CheckError(err)
	}
	log.Debug(fmt.Sprintf("Pipenv: reading Pipfile.lock (%d bytes)", len(content)))
	return parsePipfileLockPackages(content)
}

func parsePipfileLockPackages(content []byte) ([]pipfileLockPackage, error) {
	var lock pipfileLockContent
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("failed to parse Pipfile.lock: %w", err)
	}
	if lock.Default == nil && lock.Develop == nil {
		return nil, errors.New("pipenv: Pipfile.lock has no default or develop dependency sections")
	}
	seen := map[string]pipfileLockPackage{}
	var packages []pipfileLockPackage

	addEntry := func(name string, entry pipfileLockEntry) error {
		if name == "" {
			return errors.New("pipenv: Pipfile.lock contains an entry with no package name")
		}
		if len(entry.Unknown) > 0 {
			return fmt.Errorf("pipenv: package %q has unknown lock fields %q", name, entry.Unknown)
		}
		vcsCount := 0
		for _, value := range []string{entry.Git, entry.Hg, entry.Svn, entry.Bzr} {
			if value != "" {
				vcsCount++
			}
		}
		directKinds := 0
		if entry.Path != "" {
			directKinds++
		}
		if entry.File != "" {
			directKinds++
		}
		if entry.URL != "" {
			directKinds++
		}
		if vcsCount > 0 {
			directKinds++
		}
		if vcsCount > 1 || directKinds > 1 || (directKinds > 0 && (entry.Version != "" || entry.Index != "")) {
			return fmt.Errorf("pipenv: package %q has conflicting provenance in Pipfile.lock", name)
		}
		if entry.File != "" || entry.URL != "" {
			return fmt.Errorf("pipenv: package %q uses an unsupported direct-file dependency", name)
		}
		if entry.Path != "" || vcsCount == 1 {
			return nil
		}
		if entry.Editable {
			return fmt.Errorf("pipenv: editable package %q has no recognized local path or VCS provenance", name)
		}
		if entry.Version == "" {
			return fmt.Errorf("pipenv: package %q has unknown provenance in Pipfile.lock", name)
		}
		if !strings.HasPrefix(entry.Version, "==") || len(entry.Version) == 2 {
			return fmt.Errorf("pipenv: registry package %q has unsupported locked version %q", name, entry.Version)
		}
		version := strings.TrimPrefix(entry.Version, "==")
		if len(entry.Hashes) == 0 {
			return fmt.Errorf("pipenv: registry package %q at version %q has no hashes in Pipfile.lock", name, version)
		}
		pkg := pipfileLockPackage{Name: name, Version: version, Hashes: entry.Hashes}
		key := NormalizePypiName(name)
		if existing, dup := seen[key]; dup {
			if existing.Version != pkg.Version || !sameStringSet(existing.Hashes, pkg.Hashes) {
				return fmt.Errorf("pipenv: package %q has conflicting locked entries", name)
			}
			return nil
		}
		seen[key] = pkg
		packages = append(packages, pkg)
		return nil
	}
	for name, entry := range lock.Default {
		if err := addEntry(name, entry); err != nil {
			return nil, err
		}
	}
	for name, entry := range lock.Develop {
		if err := addEntry(name, entry); err != nil {
			return nil, err
		}
	}
	return packages, nil
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	values := make(map[string]int, len(left))
	for _, value := range left {
		values[value]++
	}
	for _, value := range right {
		if values[value] == 0 {
			return false
		}
		values[value]--
	}
	return true
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

// parsePipenvVersion extracts the version string from `pipenv --version` output.
// Pipenv emits "pipenv, version 2023.7.4" (date-based versioning).
// Returns "" if the version line is not found.
func parsePipenvVersion(out string) string {
	m := pipenvVersionRegex.FindStringSubmatch(out)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// validateMinimumPipenvVersion checks that the pipenv CLI on PATH meets CurationPipenvMinimumVersion.
func validateMinimumPipenvVersion() error {
	minVersion := CurationPipenvMinimumVersion
	out, err := executeCommand("pipenv", "--version")
	if err != nil {
		log.Debug(fmt.Sprintf("pipenv is not installed or not on PATH: %v", err))
		return errorutils.CheckErrorf("JFrog CLI pipenv curation requires pipenv %s or higher to be installed.", minVersion)
	}
	v := parsePipenvVersion(out)
	if v == "" {
		log.Debug(fmt.Sprintf("Could not parse pipenv version from output: %q", out))
		return errorutils.CheckErrorf("Could not parse pipenv version from output %q — ensure pipenv %s or higher is installed correctly", out, minVersion)
	}
	log.Debug(fmt.Sprintf("pipenv version: %s", v))
	if !version.NewVersion(v).AtLeast(minVersion) {
		return errorutils.CheckErrorf("JFrog CLI pipenv curation requires pipenv %s or higher. The current version is: %s", minVersion, v)
	}
	return nil
}

var (
	pipfileEnvVarRegex        = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)\}|\$([A-Za-z0-9_]+)`)
	pipfileWindowsExpandVars  = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)\}|\$([A-Za-z0-9_]+)|%[0-9A-Fa-f]{2}|%([A-Za-z0-9_]+)%|%%`)
	pipfilePercentEncodedByte = regexp.MustCompile(`^%[0-9A-Fa-f]{2}$`)
)

type pipfileSource struct {
	Name      string `toml:"name"`
	URL       string `toml:"url"`
	VerifySSL bool   `toml:"verify_ssl"`
}

type pipfileConfig struct {
	Sources     []pipfileSource `toml:"source"`
	Packages    map[string]any  `toml:"packages"`
	DevPackages map[string]any  `toml:"dev-packages"`
	Pipenv      struct {
		InstallSearchAllSources bool `toml:"install_search_all_sources"`
	} `toml:"pipenv"`
}

type pipfileSourceRecord struct {
	index      int
	name       string
	rawURL     string
	parsedURL  *url.URL
	server     *config.ServerDetails
	repository string
	isPyPI     bool
}

type pipenvEndpoint struct {
	scheme     string
	host       string
	basePath   string
	repository string
}

func (e pipenvEndpoint) String() string {
	return fmt.Sprintf("%s://%s%s/api/pypi/%s", e.scheme, e.host, e.basePath, e.repository)
}

type pipfileVariableError struct {
	Source   string
	Variable string
}

func (e *pipfileVariableError) Error() string {
	return fmt.Sprintf("pipenv: source %q references unset environment variable %q", e.Source, e.Variable)
}

func expandPipfileEnvVars(raw, sourceName string, environment map[string]string) (string, error) {
	return expandPipfileEnvVarsForOS(raw, sourceName, environment, runtime.GOOS)
}

func expandPipfileEnvVarsForOS(raw, sourceName string, environment map[string]string, goos string) (string, error) {
	if strings.Contains(pipfileEnvVarRegex.ReplaceAllString(raw, ""), "$") {
		return "", fmt.Errorf("pipenv: source %q contains a malformed environment variable reference", sourceName)
	}
	var expansionErr error
	expand := func(pattern *regexp.Regexp, value string) string {
		return pattern.ReplaceAllStringFunc(value, func(match string) string {
			if match == "%%" { // cmd.exe/ntpath convention: an escaped literal '%'
				return "%"
			}
			if pipfilePercentEncodedByte.MatchString(match) {
				// A URL percent-encoded byte (e.g. %40, %2F), not a %VAR% reference.
				// Leave it untouched here; url.Parse decodes it once the caller parses the URL.
				return match
			}
			groups := pattern.FindStringSubmatch(match)
			name := ""
			for _, group := range groups[1:] {
				if group != "" {
					name = group
					break
				}
			}
			expanded, ok := environment[name]
			if !ok && goos == "windows" {
				for environmentName, value := range environment {
					if strings.EqualFold(environmentName, name) {
						expanded, ok = value, true
						break
					}
				}
			}
			if !ok {
				expansionErr = &pipfileVariableError{Source: sourceName, Variable: name}
				return match
			}
			return expanded
		})
	}
	if goos == "windows" {
		expanded := expand(pipfileWindowsExpandVars, raw)
		if expansionErr != nil {
			return "", expansionErr
		}
		return expanded, nil
	}
	expanded := expand(pipfileEnvVarRegex, raw)
	if expansionErr != nil {
		return "", expansionErr
	}
	return expanded, nil
}

func pipfileEnvironment(pipfilePath string) (map[string]string, error) {
	environment := map[string]string{}
	dontLoad := strings.ToLower(strings.TrimSpace(os.Getenv("PIPENV_DONT_LOAD_ENV")))
	skipDotenv := dontLoad == "1" || dontLoad == "true" || dontLoad == "yes" || dontLoad == "on"
	if !skipDotenv {
		envPath := os.Getenv("PIPENV_DOTENV_LOCATION")
		if envPath == "" {
			envPath = filepath.Join(filepath.Dir(pipfilePath), ".env")
		}
		envFile, err := gotenv.Read(envPath) // #nosec G304 -- Pipenv supports a user-selected dotenv path
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("pipenv: failed to parse environment file %q", filepath.Base(envPath))
		}
		for name, value := range envFile {
			environment[name] = value
		}
	}
	for _, entry := range os.Environ() {
		name, value, ok := strings.Cut(entry, "=")
		if ok {
			environment[name] = value
		}
	}
	return environment, nil
}

func parseArtifactoryPypiURL(rawURL string) (*config.ServerDetails, string) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" ||
		(!strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https")) {
		return nil, ""
	}
	const pypiSegment = "/api/pypi/"
	pypiIdx := strings.Index(u.Path, pypiSegment)
	if pypiIdx < 0 {
		return nil, ""
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(u.Path[pypiIdx:], pypiSegment), "/"), "/")
	if len(parts) != 2 || !validPipenvRepository(parts[0]) || parts[1] != "simple" {
		return nil, ""
	}
	repoName := parts[0]
	artURL := fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path[:pypiIdx+1])
	sd := &config.ServerDetails{ArtifactoryUrl: artURL}
	if u.User != nil {
		sd.User = u.User.Username()
		if p, ok := u.User.Password(); ok {
			sd.Password = p
		}
	}
	return sd, repoName
}

func parsePipfileSource(index int, source pipfileSource, environment map[string]string) (pipfileSourceRecord, error) {
	if strings.TrimSpace(source.Name) == "" {
		return pipfileSourceRecord{}, fmt.Errorf("pipenv: [[source]] entry %d has no name", index+1)
	}
	if strings.TrimSpace(source.URL) == "" {
		return pipfileSourceRecord{}, fmt.Errorf("pipenv: source %q has no URL", source.Name)
	}
	expanded, err := expandPipfileEnvVars(source.URL, source.Name, environment)
	if err != nil {
		return pipfileSourceRecord{}, err
	}
	u, err := url.Parse(expanded)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" ||
		(!strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https")) {
		return pipfileSourceRecord{}, fmt.Errorf("pipenv: source %q has an invalid absolute URL", source.Name)
	}
	if u.User != nil {
		user := u.User.Username()
		password, hasPassword := u.User.Password()
		if user == "" || !hasPassword || password == "" {
			return pipfileSourceRecord{}, fmt.Errorf("pipenv: source %q has incomplete URL credentials", source.Name)
		}
	}
	sd, repo := parseArtifactoryPypiURL(expanded)
	return pipfileSourceRecord{
		index:      index,
		name:       source.Name,
		rawURL:     source.URL,
		parsedURL:  u,
		server:     sd,
		repository: repo,
		isPyPI:     strings.EqualFold(u.Hostname(), "pypi.org") && path.Clean(u.Path) == "/simple",
	}, nil
}

func packageIndex(spec any) (string, bool, error) {
	value, ok := spec.(map[string]any)
	if !ok {
		return "", false, nil
	}
	indexValue, exists := value["index"]
	if !exists {
		return "", false, nil
	}
	index, ok := indexValue.(string)
	if !ok || strings.TrimSpace(index) == "" {
		return "", false, errors.New("index must be a non-empty string")
	}
	return index, true, nil
}

func effectivePipfileSourceNames(cfg pipfileConfig) ([]string, error) {
	if len(cfg.Sources) == 0 {
		for packageName, spec := range cfg.Packages {
			if _, assigned, err := packageIndex(spec); err != nil || assigned {
				return nil, fmt.Errorf("pipenv: package %q assigns an index but Pipfile has no [[source]] entries", packageName)
			}
		}
		for packageName, spec := range cfg.DevPackages {
			if _, assigned, err := packageIndex(spec); err != nil || assigned {
				return nil, fmt.Errorf("pipenv: dev package %q assigns an index but Pipfile has no [[source]] entries", packageName)
			}
		}
		return nil, nil
	}

	// Sources[0] is effective only for index-less packages (or when there are none);
	// an index-assigned package never falls back to it (pipenv dependency-confusion fix).
	names := map[string]struct{}{}
	addSpecs := func(section string, specs map[string]any) error {
		for packageName, spec := range specs {
			index, assigned, err := packageIndex(spec)
			if err != nil {
				return fmt.Errorf("pipenv: %s package %q has invalid index assignment: %w", section, packageName, err)
			}
			if assigned {
				names[index] = struct{}{}
			} else {
				names[cfg.Sources[0].Name] = struct{}{}
			}
		}
		return nil
	}
	if err := addSpecs("regular", cfg.Packages); err != nil {
		return nil, err
	}
	if err := addSpecs("development", cfg.DevPackages); err != nil {
		return nil, err
	}
	if len(names) == 0 {
		names[cfg.Sources[0].Name] = struct{}{}
	}
	if cfg.Pipenv.InstallSearchAllSources {
		for _, source := range cfg.Sources {
			names[source.Name] = struct{}{}
		}
	}
	effective := make([]string, 0, len(names))
	for _, source := range cfg.Sources {
		if _, ok := names[source.Name]; ok {
			effective = append(effective, source.Name)
			delete(names, source.Name)
		}
	}
	if len(names) > 0 {
		for name := range names {
			return nil, fmt.Errorf("pipenv: package index assignment references unknown source %q", name)
		}
	}
	return effective, nil
}

func readPipfileConfig(pipfilePath string) (pipfileConfig, []pipfileSourceRecord, []string, error) {
	var cfg pipfileConfig
	if _, err := toml.DecodeFile(pipfilePath, &cfg); err != nil {
		return cfg, nil, nil, err
	}
	effective, err := effectivePipfileSourceNames(cfg)
	if err != nil {
		return cfg, nil, nil, err
	}
	effectiveSet := make(map[string]struct{}, len(effective))
	for _, name := range effective {
		effectiveSet[name] = struct{}{}
	}
	environment, err := pipfileEnvironment(pipfilePath)
	if err != nil {
		return cfg, nil, nil, err
	}
	records := make([]pipfileSourceRecord, 0, len(cfg.Sources))
	nameCounts := make(map[string]int, len(cfg.Sources))
	for _, source := range cfg.Sources {
		nameCounts[source.Name]++
	}
	for i, source := range cfg.Sources {
		if _, isEffective := effectiveSet[source.Name]; isEffective && nameCounts[source.Name] > 1 {
			return cfg, nil, nil, fmt.Errorf("pipenv: Pipfile declares duplicate source name %q", source.Name)
		}
		if _, isEffective := effectiveSet[source.Name]; !isEffective {
			records = append(records, pipfileSourceRecord{index: i, name: source.Name, rawURL: source.URL})
			continue
		}
		record, err := parsePipfileSource(i, source, environment)
		if err != nil {
			return cfg, nil, nil, err
		}
		records = append(records, record)
	}
	return cfg, records, effective, nil
}

func endpointFromServer(server *config.ServerDetails, repository string) (pipenvEndpoint, error) {
	if server == nil || server.GetArtifactoryUrl() == "" || !validPipenvRepository(repository) {
		return pipenvEndpoint{}, errors.New("server URL and repository are required")
	}
	u, err := url.Parse(server.GetArtifactoryUrl())
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(!strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https")) {
		return pipenvEndpoint{}, errors.New("invalid Artifactory URL")
	}
	cleanBasePath := strings.TrimSuffix(path.Clean(u.Path), "/")
	if cleanBasePath != strings.TrimSuffix(u.Path, "/") {
		return pipenvEndpoint{}, errors.New("invalid Artifactory URL path")
	}
	return pipenvEndpoint{
		scheme:     strings.ToLower(u.Scheme),
		host:       normalizedURLHost(u),
		basePath:   cleanBasePath,
		repository: repository,
	}, nil
}

func validPipenvRepository(repository string) bool {
	return repository != "" && repository != "." && repository != ".." &&
		!strings.ContainsAny(repository, `/\`)
}

func endpointFromSource(record pipfileSourceRecord) (pipenvEndpoint, error) {
	if record.server == nil || record.repository == "" {
		return pipenvEndpoint{}, fmt.Errorf("source %q is not an Artifactory PyPI source", record.name)
	}
	return endpointFromServer(record.server, record.repository)
}

func normalizedURLHost(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	return host + ":" + port
}

func samePipenvEndpoint(left, right pipenvEndpoint) bool {
	return left.scheme == right.scheme && left.host == right.host &&
		left.basePath == right.basePath && left.repository == right.repository
}

type credentialState int

const (
	noCredentials credentialState = iota
	completeCredentials
	partialCredentials
)

func serverCredentialState(server *config.ServerDetails) credentialState {
	if server == nil {
		return noCredentials
	}
	if server.GetAccessToken() != "" {
		return completeCredentials
	}
	hasUser := server.GetUser() != ""
	hasPassword := server.GetPassword() != ""
	if hasUser != hasPassword {
		return partialCredentials
	}
	if hasUser {
		return completeCredentials
	}
	return noCredentials
}

func sameCredentials(left, right *config.ServerDetails) bool {
	return left.GetUser() == right.GetUser() && left.GetPassword() == right.GetPassword() &&
		left.GetAccessToken() == right.GetAccessToken()
}

func mergePipenvCredentials(target *config.ServerDetails, targetEndpoint pipenvEndpoint, sourceCredentials []*config.ServerDetails, fallback *config.ServerDetails) (*config.ServerDetails, error) {
	merged := *target
	fallbackMatches := false
	if fallback != nil {
		fallbackEndpoint, err := endpointFromServer(fallback, targetEndpoint.repository)
		fallbackMatches = err == nil && samePipenvEndpoint(fallbackEndpoint, targetEndpoint)
		if fallbackMatches {
			merged = *fallback
			merged.ArtifactoryUrl = target.GetArtifactoryUrl()
		}
	}
	merged.User, merged.Password, merged.AccessToken = "", "", ""

	var selected *config.ServerDetails
	for _, source := range sourceCredentials {
		switch serverCredentialState(source) {
		case partialCredentials:
			return nil, errors.New("pipenv: selected Pipfile source has incomplete credentials")
		case completeCredentials:
			if selected != nil && !sameCredentials(selected, source) {
				return nil, errors.New("pipenv: effective Pipfile sources contain conflicting credentials")
			}
			selected = source
		}
	}
	if selected == nil {
		switch serverCredentialState(target) {
		case partialCredentials:
			return nil, errors.New("pipenv: configured resolver has incomplete credentials")
		case completeCredentials:
			selected = target
		}
	}
	if selected == nil && fallbackMatches {
		switch serverCredentialState(fallback) {
		case partialCredentials:
			return nil, errors.New("pipenv: matching JFrog server has incomplete credentials")
		case completeCredentials:
			selected = fallback
		}
	}
	if selected != nil {
		merged.User = selected.GetUser()
		if selected.GetAccessToken() != "" {
			merged.AccessToken = selected.GetAccessToken()
		} else {
			merged.Password = selected.GetPassword()
		}
	}
	return &merged, nil
}

// ResolvePipfileArtifactorySource derives and validates Pipenv's effective sources.
func ResolvePipfileArtifactorySource(pipfilePath string, configuredServer *config.ServerDetails, configuredRepo string, fallbackServer *config.ServerDetails) (*config.ServerDetails, string, error) {
	_, records, effectiveNames, err := readPipfileConfig(pipfilePath)
	if err != nil {
		return nil, "", err
	}
	byName := make(map[string]pipfileSourceRecord, len(records))
	for _, record := range records {
		byName[record.name] = record
	}

	var target *config.ServerDetails
	var targetEndpoint pipenvEndpoint
	if configuredRepo != "" {
		target = configuredServer
		targetEndpoint, err = endpointFromServer(configuredServer, configuredRepo)
		if err != nil {
			return nil, "", fmt.Errorf("pipenv: invalid configured resolver: %w", err)
		}
	} else {
		for _, name := range effectiveNames {
			record := byName[name]
			if record.repository == "" {
				continue
			}
			target = record.server
			targetEndpoint, err = endpointFromSource(record)
			if err != nil {
				return nil, "", err
			}
			configuredRepo = record.repository
			break
		}
		if target == nil {
			return nil, "", nil
		}
	}

	var matchingSourceCredentials []*config.ServerDetails
	for _, name := range effectiveNames {
		record := byName[name]
		if record.repository == "" {
			if target != nil && record.isPyPI {
				continue
			}
			return nil, "", fmt.Errorf("pipenv: source %q does not use the configured Artifactory repository", record.name)
		}
		sourceEndpoint, endpointErr := endpointFromSource(record)
		if endpointErr != nil {
			return nil, "", endpointErr
		}
		if !samePipenvEndpoint(sourceEndpoint, targetEndpoint) {
			return nil, "", fmt.Errorf("pipenv: source %q uses %s instead of %s", record.name, sourceEndpoint, targetEndpoint)
		}
		matchingSourceCredentials = append(matchingSourceCredentials, record.server)
	}
	if target.GetArtifactoryUrl() == "" {
		target = &config.ServerDetails{ArtifactoryUrl: targetEndpoint.scheme + "://" + targetEndpoint.host + targetEndpoint.basePath + "/"}
	}
	merged, err := mergePipenvCredentials(target, targetEndpoint, matchingSourceCredentials, fallbackServer)
	if err != nil {
		return nil, "", err
	}
	return merged, configuredRepo, nil
}

func ParsePipfileArtifactorySource(pipfilePath string) (*config.ServerDetails, string, error) {
	return ResolvePipfileArtifactorySource(pipfilePath, nil, "", nil)
}

// ParsePipConfigIndexUrl extracts Artifactory server details and repo name from the
// [global] index-url, merging paths in order (later overrides earlier), pip-style.
// sourcePath is the file the winning value came from, for logging/errors.
func ParsePipConfigIndexUrl(paths ...string) (serverDetails *config.ServerDetails, repoName string, sourcePath string, err error) {
	var rawURL string
	for _, path := range paths {
		found, indexURL, fileErr := pipConfigGlobalIndexURL(path)
		if fileErr != nil {
			return nil, "", "", fileErr
		}
		if found {
			rawURL = indexURL
			sourcePath = path
		}
	}
	if rawURL == "" {
		return nil, "", "", nil
	}
	sd, repo := parseArtifactoryPypiURL(rawURL)
	if sd == nil {
		parsed, parseErr := url.Parse(rawURL)
		if parseErr != nil || parsed.Scheme == "" || parsed.Host == "" || strings.Contains(rawURL, "/api/pypi/") {
			return nil, "", "", fmt.Errorf("pip config \"%s\" [global] index-url is not a valid Artifactory PyPI URL", sourcePath)
		}
	}
	return sd, repo, sourcePath, nil
}

// pipConfigGlobalIndexURL reads a single pip config file's [global] index-url.
// found is false (with no error) when the file is missing or has no such key.
func pipConfigGlobalIndexURL(pipConfPath string) (found bool, rawURL string, err error) {
	data, readErr := os.ReadFile(pipConfPath) // #nosec G304 -- path is DefaultPipConfPaths() or PIP_CONFIG_FILE env var, not attacker-controlled
	if readErr != nil {
		if os.IsNotExist(readErr) {
			log.Debug(fmt.Sprintf("pip.conf not found at %s", pipConfPath))
			return false, "", nil
		}
		return false, "", fmt.Errorf("failed to read pip config %q: %w", pipConfPath, readErr)
	}
	// AllowShadows/AllowNonUniqueSections surface duplicates instead of silently picking one.
	cfg, loadErr := ini.LoadSources(ini.LoadOptions{AllowNonUniqueSections: true, AllowShadows: true}, data)
	if loadErr != nil {
		return false, "", fmt.Errorf("failed to parse pip config %q: %w", pipConfPath, loadErr)
	}
	var globalSections []*ini.Section
	for _, section := range cfg.Sections() {
		if strings.EqualFold(section.Name(), "global") {
			globalSections = append(globalSections, section)
		}
	}
	if len(globalSections) > 1 {
		return false, "", fmt.Errorf("pip config %q defines [global] more than once", pipConfPath)
	}
	if len(globalSections) == 0 {
		return false, "", nil
	}
	var indexURLKey *ini.Key
	for _, key := range globalSections[0].Keys() {
		if !strings.EqualFold(key.Name(), "index-url") {
			continue
		}
		if indexURLKey != nil {
			return false, "", fmt.Errorf("pip config %q defines index-url more than once in [global]", pipConfPath)
		}
		indexURLKey = key
	}
	if indexURLKey == nil {
		return false, "", nil
	}
	if shadows := indexURLKey.ValueWithShadows(); len(shadows) > 1 {
		return false, "", fmt.Errorf("pip config %q defines index-url more than once in [global]", pipConfPath)
	}
	rawURL = strings.Trim(strings.TrimSpace(indexURLKey.Value()), `"'`)
	return rawURL != "", rawURL, nil
}

// DefaultPipConfPaths returns pip's user-level config candidates: legacy,
// then modern (overrides legacy), then PIP_CONFIG_FILE if set (overrides
// both). An existing PIP_CONFIG_FILE skips legacy/modern, matching pip.
func DefaultPipConfPaths() []string {
	envConfigFile := os.Getenv("PIP_CONFIG_FILE")
	if envConfigFile != "" {
		if _, err := os.Stat(envConfigFile); err == nil { // #nosec G703 -- env-provided path, mirrors pip's own PIP_CONFIG_FILE handling
			return []string{envConfigFile}
		}
	}
	home, _ := os.UserHomeDir()
	basename := "pip.conf"
	legacyDir := filepath.Join(home, ".pip")
	if runtime.GOOS == "windows" {
		basename = "pip.ini"
		legacyDir = filepath.Join(home, "pip")
	}
	paths := []string{filepath.Join(legacyDir, basename), filepath.Join(modernPipConfDir(home), basename)}
	if envConfigFile != "" {
		paths = append(paths, envConfigFile)
	}
	return paths
}

// modernPipConfDir mirrors pip's platformdirs: on macOS, Application Support
// only if it already exists, else XDG/APPDATA config dir.
func modernPipConfDir(home string) string {
	if runtime.GOOS == "windows" {
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming")
		}
		return filepath.Join(appData, "pip")
	}
	if runtime.GOOS == "darwin" {
		appSupportDir := filepath.Join(home, "Library", "Application Support", "pip")
		if info, err := os.Stat(appSupportDir); err == nil && info.IsDir() { // #nosec G703 -- fixed home-relative path, not attacker-controlled
			return appSupportDir
		}
	}
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		configHome = filepath.Join(home, ".config")
	}
	return filepath.Join(configHome, "pip")
}

// pipfileSourceHeaderRegex matches the start of a [[source]] array-of-tables entry.
var pipfileSourceHeaderRegex = regexp.MustCompile(`(?m)^\s*\[\[\s*source\s*\]\]\s*(?:#.*)?$`)

// pipfileTableHeaderRegex matches the start of any TOML table / array-of-tables
// header, used to find where a [[source]] block ends.
var pipfileTableHeaderRegex = regexp.MustCompile(`(?m)^\[`)

// pipfileUrlValueRegex locates a `url = ...` assignment and captures the quoted
// value in group 1 (double-quoted) or group 2 (single-quoted), so callers can
// replace only that value's exact byte span — leaving whitespace, other keys,
// and comments untouched.
var pipfileUrlValueRegex = regexp.MustCompile(`(?m)^\s*url\s*=\s*(?:"([^"]*)"|'([^']*)')`)

type pipfileURLSpan struct {
	start int
	end   int
}

func findPipfileSourceURLSpans(content string) []pipfileURLSpan {
	var spans []pipfileURLSpan
	for _, h := range pipfileSourceHeaderRegex.FindAllStringIndex(content, -1) {
		blockStart := h[1]
		blockEnd := len(content)
		if next := pipfileTableHeaderRegex.FindStringIndex(content[blockStart:]); next != nil {
			blockEnd = blockStart + next[0]
		}
		block := content[blockStart:blockEnd]
		m := pipfileUrlValueRegex.FindStringSubmatchIndex(block)
		if m == nil {
			spans = append(spans, pipfileURLSpan{start: -1, end: -1})
			continue
		}
		localStart, localEnd := m[2], m[3]
		if localStart == -1 {
			localStart, localEnd = m[4], m[5]
		}
		if localStart == -1 {
			spans = append(spans, pipfileURLSpan{start: -1, end: -1})
			continue
		}
		spans = append(spans, pipfileURLSpan{start: blockStart + localStart, end: blockStart + localEnd})
	}
	return spans
}

func rewriteCurationSourceInPipfile(pipfilePath, repoName, curationUrl string) (found bool, err error) {
	data, err := os.ReadFile(pipfilePath) // #nosec G304 -- temp-dir copy of the project's Pipfile, not attacker-controlled
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, errorutils.CheckError(err)
	}
	cfg, records, effectiveNames, err := readPipfileConfig(pipfilePath)
	if err != nil {
		return false, err
	}
	content := string(data)
	if len(cfg.Sources) == 0 {
		source := fmt.Sprintf("[[source]]\nname = \"jfrog-curation\"\nurl = %q\nverify_ssl = true\n\n", curationUrl)
		updated := source + content
		if err = writePrivatePipfile(pipfilePath, []byte(updated)); err != nil {
			return false, errorutils.CheckError(err)
		}
		return true, nil
	}
	spans := findPipfileSourceURLSpans(content)
	if len(spans) != len(records) {
		return false, errors.New("pipenv: could not map parsed [[source]] entries back to Pipfile")
	}
	effective := make(map[string]struct{}, len(effectiveNames))
	for _, name := range effectiveNames {
		effective[name] = struct{}{}
	}
	var selected []pipfileURLSpan
	for _, record := range records {
		if _, isEffective := effective[record.name]; !isEffective {
			continue
		}
		if record.repository != "" && record.repository != repoName {
			return false, fmt.Errorf("pipenv: source %q uses repository %q instead of %q", record.name, record.repository, repoName)
		}
		if record.repository == "" && !record.isPyPI {
			return false, fmt.Errorf("pipenv: source %q cannot be redirected safely", record.name)
		}
		span := spans[record.index]
		if span.start < 0 {
			return false, fmt.Errorf("pipenv: effective source %q has no quoted URL", record.name)
		}
		selected = append(selected, span)
	}
	if len(selected) == 0 {
		return false, nil
	}
	updated := content
	for i := len(selected) - 1; i >= 0; i-- {
		span := selected[i]
		updated = updated[:span.start] + curationUrl + updated[span.end:]
	}
	if err = writePrivatePipfile(pipfilePath, []byte(updated)); err != nil {
		return false, errorutils.CheckError(err)
	}
	log.Info(fmt.Sprintf("Configured Pipfile [[source]] url for repository %q to use the curation pass-through endpoint", repoName))
	return true, nil
}

func writePrivatePipfile(pipfilePath string, content []byte) error {
	if err := os.WriteFile(pipfilePath, content, 0600); err != nil { // #nosec G703 -- temp-dir Pipfile copy
		return err
	}
	return os.Chmod(pipfilePath, 0600)
}

func installPipenvDeps(params technologies.BuildInfoBomGeneratorParams) (rootDetected bool, restoreEnv func() error, err error) {
	// Set virtualenv path to venv dir
	previousWorkonHome, hadWorkonHome := os.LookupEnv("WORKON_HOME")
	err = os.Setenv("WORKON_HOME", ".jfrog")
	if err != nil {
		return
	}
	restoreEnv = func() error {
		if hadWorkonHome {
			return os.Setenv("WORKON_HOME", previousWorkonHome)
		}
		return os.Unsetenv("WORKON_HOME")
	}
	if params.IsCurationCmd {
		restorePipenvEnv, protectErr := protectPipenvCurationEnvironment(pipfileFile)
		if protectErr != nil {
			return false, restoreEnv, protectErr
		}
		restoreWorkonHome := restoreEnv
		restoreEnv = func() error {
			return errors.Join(restorePipenvEnv(), restoreWorkonHome())
		}
	}
	server := params.ServerDetails
	repo := params.DependenciesRepository
	if repo == "" && params.IsCurationCmd {
		pipConfServer, pipConfRepo, _, pipConfErr := ParsePipConfigIndexUrl(DefaultPipConfPaths()...)
		if pipConfErr != nil {
			return false, restoreEnv, pipConfErr
		}
		server, repo, err = ResolvePipfileArtifactorySource(pipfileFile, pipConfServer, pipConfRepo, params.ServerDetails)
		if err != nil {
			return false, restoreEnv, err
		}
	}
	if repo != "" {
		return false, restoreEnv, runPipenvInstallFromRemoteRegistry(server, repo, params.IsCurationCmd)
	}
	if params.IsCurationCmd {
		return false, restoreEnv, errorutils.CheckErrorf(
			"curation-audit for pipenv requires an Artifactory PyPI resolver. " +
				"Either run 'jf pipenv-config', configure index-url in your user pip.conf via " +
				"Artifactory 'Set me up', or add an Artifactory [[source]] entry to your Pipfile.")
	}
	_, err = executeCommand("pipenv", "install", "-d")
	return false, restoreEnv, err
}

type environmentValue struct {
	name    string
	value   string
	present bool
}

func protectPipenvCurationEnvironment(pipfilePath string) (restore func() error, err error) {
	absolutePipfile, err := filepath.Abs(pipfilePath)
	if err != nil {
		return nil, fmt.Errorf("pipenv: failed to resolve protected Pipfile path: %w", err)
	}
	names := []string{"PIPENV_PIPFILE", "PIPENV_SKIP_LOCK", "PIPENV_IGNORE_PIPFILE"}
	previous := make([]environmentValue, 0, len(names))
	for _, name := range names {
		value, present := os.LookupEnv(name)
		previous = append(previous, environmentValue{name: name, value: value, present: present})
	}
	restore = func() error {
		var restoreErr error
		for _, item := range previous {
			if item.present {
				restoreErr = errors.Join(restoreErr, os.Setenv(item.name, item.value))
			} else {
				restoreErr = errors.Join(restoreErr, os.Unsetenv(item.name))
			}
		}
		return restoreErr
	}
	if err = os.Setenv("PIPENV_PIPFILE", absolutePipfile); err != nil {
		return nil, errors.Join(err, restore())
	}
	for _, name := range names[1:] {
		if err = os.Unsetenv(name); err != nil {
			return nil, errors.Join(err, restore())
		}
	}
	return restore, nil
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

func runPipenvInstallFromRemoteRegistry(server *config.ServerDetails, depsRepoName string, isCurationCmd bool) (err error) {
	if !isCurationCmd {
		rtURL, err := artifactoryutils.GetPypiRepoUrl(server, depsRepoName, false)
		if err != nil {
			return err
		}
		_, err = executeCommand("pipenv", "install", "-d",
			artifactoryutils.GetPypiRemoteRegistryFlag(pythonutils.Pipenv), rtURL)
		return err
	}
	if err = validateMinimumPipenvVersion(); err != nil {
		return err
	}

	rtURL, username, password, err := artifactoryutils.GetPypiRepoUrlWithCredentials(server, depsRepoName, true)
	if err != nil {
		return err
	}
	safeURL := rtURL.String()
	if password != "" {
		rtURL.User = url.UserPassword(username, password)
	}
	credentialURL := rtURL.String()
	found, rewriteErr := rewriteCurationSourceInPipfile(pipfileFile, depsRepoName, credentialURL)
	if rewriteErr != nil {
		return rewriteErr
	}
	if !found {
		return errorutils.CheckErrorf("pipenv: no effective Pipfile source could be configured for repository %q", depsRepoName)
	}

	args := []string{"install", "-d"}
	output, installErr := executeCommandSanitized("pipenv", args, safeURL, credentialURL, password, server.GetAccessToken())
	if installErr != nil {
		combined := output + " " + installErr.Error()
		if isCvsVersionFilteredOutput(combined) {
			return &CvsBlockedError{Packages: parseCvsFailedPackages(combined), Cause: installErr}
		}
		// build-info-go's IsForbiddenOutput has no pipenv case yet; check directly.
		if strings.Contains(strings.ToLower(combined), "http error 403") {
			msgToUser := fmt.Sprintf(technologies.CurationErrorMsgToUserTemplate, techutils.Pipenv)
			return errors.Join(installErr, errors.New(msgToUser))
		}
	}
	return installErr
}

func executeCommandSanitized(executable string, args []string, safeURL string, secrets ...string) (string, error) {
	installCmd := exec.Command(executable, args...) // #nosec G204 -- internal executable and arguments
	environment, err := pipenvCurationEnvironment(pipfileFile)
	if err != nil {
		return "", err
	}
	installCmd.Env = environment
	maskedCmdString := coreutils.GetMaskedCommandString(installCmd)
	log.Debug("Running", maskedCmdString)
	output, err := installCmd.CombinedOutput()
	sanitized := string(output)
	if safeURL != "" {
		for _, secretURL := range secrets {
			if strings.Contains(secretURL, "://") {
				sanitized = strings.ReplaceAll(sanitized, secretURL, safeURL)
			}
		}
	}
	sanitized = utils.MaskSensitiveData("url", sanitized)
	for _, secret := range secrets {
		if secret == "" || strings.Contains(secret, "://") {
			continue
		}
		sanitized = strings.ReplaceAll(sanitized, secret, "****")
		sanitized = strings.ReplaceAll(sanitized, url.PathEscape(secret), "****")
		sanitized = strings.ReplaceAll(sanitized, url.QueryEscape(secret), "****")
	}
	if err != nil {
		technologies.LogExecutableVersion(executable)
		return sanitized, errorutils.CheckErrorf("%q command failed: %s - %s", maskedCmdString, err.Error(), sanitized)
	}
	return sanitized, nil
}

func pipenvCurationEnvironment(pipfilePath string) ([]string, error) {
	absolutePipfile, err := filepath.Abs(pipfilePath)
	if err != nil {
		return nil, fmt.Errorf("pipenv: failed to resolve protected Pipfile path: %w", err)
	}
	blocked := []string{"PIPENV_PIPFILE", "PIPENV_SKIP_LOCK", "PIPENV_IGNORE_PIPFILE"}
	environment := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		remove := false
		for _, blockedName := range blocked {
			if strings.EqualFold(name, blockedName) {
				remove = true
				break
			}
		}
		if !remove {
			environment = append(environment, entry)
		}
	}
	return append(environment, "PIPENV_PIPFILE="+absolutePipfile), nil
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
