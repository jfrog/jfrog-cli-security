package uv

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/gofrog/version"
	artifactoryutils "github.com/jfrog/jfrog-cli-artifactory/artifactory/commands/python"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/python"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	clientutils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

const (
	uvLockFile               = "uv.lock"
	uvTomlConfigRelPath      = ".config/uv/uv.toml"
	CurationUvMinimumVersion = "0.6.17"
)

var (
	depEntryRegex  = regexp.MustCompile(`name\s*=\s*"([^"]+)"(?:[^{}]*?\bversion\s*=\s*"([^"]+)")?`)
	urlInlineRegex = regexp.MustCompile(`\burl\s*=\s*"([^"]+)"`)
)

// uvDependency is one dependency edge from a package's "dependencies" array.
type uvDependency struct {
	Name    string
	Version string
}

// UvRegistryConfig holds the Artifactory URL and repo name resolved for the current uv project.
type UvRegistryConfig struct {
	ArtifactoryUrl string
	RepoName       string
}

type uvPackage struct {
	Name         string
	Version      string
	IsRoot       bool
	IsWorkspace  bool
	Dependencies []uvDependency
	DownloadURLs []string
}

// GetNativeUvRegistryConfig returns the Artifactory URL and repo name for the current uv project.
func GetNativeUvRegistryConfig() (*UvRegistryConfig, error) {
	// 1. Try pyproject.toml [[tool.uv.index]] first.
	if wd, err := os.Getwd(); err == nil {
		if data, err := os.ReadFile(filepath.Join(wd, "pyproject.toml")); err == nil {
			candidates := parsePyprojectUvIndexUrls(string(data))
			switch len(candidates) {
			case 0:
				// Nothing declared here — fall through to uv.toml.
			case 1:
				if cfg, ok := firstArtifactoryPypiConfig(candidates); ok {
					log.Info(fmt.Sprintf("uv: using Artifactory URL %q and repository %q from pyproject.toml", cfg.ArtifactoryUrl, cfg.RepoName))
					return cfg, nil
				}
			default:
				log.Warn(fmt.Sprintf(
					"uv: pyproject.toml declares %d [[tool.uv.index]] entries — ignoring them and using ~/.config/uv/uv.toml instead, "+
						"since picking one from a project-declared list can't be done safely", len(candidates)))
			}
		}
	}

	// 2. Fall back to ~/.config/uv/uv.toml.
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("uv: could not determine home directory: %w", err)
	}
	configPath := filepath.Join(home, uvTomlConfigRelPath)
	content, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("uv: no Artifactory index found in pyproject.toml and could not read %s: %w", configPath, err)
	}
	cfg, ok := firstArtifactoryPypiConfig(parseUvTomlIndexUrls(string(content)))
	if !ok {
		return nil, errorutils.CheckErrorf(
			"uv: no Artifactory index url found in pyproject.toml or %s — "+
				"add [[tool.uv.index]] to pyproject.toml or configure via the Artifactory 'Set Me Up' page for uv",
			configPath,
		)
	}
	log.Info(fmt.Sprintf("uv: using Artifactory URL %q and repository %q from uv.toml", cfg.ArtifactoryUrl, cfg.RepoName))
	return cfg, nil
}

// firstArtifactoryPypiConfig returns the config for the first Artifactory-shaped
// URL among candidates (in order), or ok=false if none match.
func firstArtifactoryPypiConfig(candidates []string) (cfg *UvRegistryConfig, ok bool) {
	for _, indexUrl := range candidates {
		if artiUrl, repoName, err := parseArtifactoryPypiUrl(indexUrl); err == nil {
			return &UvRegistryConfig{ArtifactoryUrl: artiUrl, RepoName: repoName}, true
		}
	}
	return nil, false
}

// parsePyprojectUvIndexUrls returns the urls of all non-explicit [[tool.uv.index]]
// sections in pyproject.toml, in file order.
func parsePyprojectUvIndexUrls(content string) []string {
	return parseIndexSectionUrls(content, "[[tool.uv.index]]")
}

// parseUvTomlIndexUrls returns the url values of all non-explicit [[index]]
// sections in uv.toml, in file order.
func parseUvTomlIndexUrls(content string) []string {
	return parseIndexSectionUrls(content, "[[index]]")
}

// parseIndexSectionUrls extracts the urls of every non-explicit sectionHeader
// block in content, in file order. An index marked `explicit = true` is uv's
// documented way to pin one package to it via [tool.uv.sources] — it's never
// used for general resolution, so it's excluded here.
func parseIndexSectionUrls(content, sectionHeader string) []string {
	var urls []string
	var currentUrl string
	var currentExplicit bool
	inSection := false

	flush := func() {
		if inSection && !currentExplicit && currentUrl != "" {
			urls = append(urls, currentUrl)
		}
	}

	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == sectionHeader {
			flush()
			inSection = true
			currentUrl = ""
			currentExplicit = false
			continue
		}
		if inSection && strings.HasPrefix(line, "[") {
			flush()
			inSection = false
			continue
		}
		if !inSection {
			continue
		}
		if strings.HasPrefix(line, "url") {
			if _, val, ok := strings.Cut(line, "="); ok {
				val = strings.TrimSpace(val)
				val = strings.Trim(val, `"'`)
				if val != "" {
					currentUrl = val
				}
			}
			continue
		}
		if strings.HasPrefix(line, "explicit") {
			if _, val, ok := strings.Cut(line, "="); ok && strings.TrimSpace(val) == "true" {
				currentExplicit = true
			}
			continue
		}
	}
	flush()
	return urls
}

// parseArtifactoryPypiUrl splits an Artifactory PyPI URL into its base URL and repo name.
func parseArtifactoryPypiUrl(rawUrl string) (artiUrl, repoName string, err error) {
	const marker = "/api/pypi/"
	idx := strings.Index(rawUrl, marker)
	if idx < 0 {
		err = fmt.Errorf("URL %q does not match Artifactory PyPI format (.../api/pypi/<repo>/...)", rawUrl)
		return
	}
	artiUrl = rawUrl[:idx]
	rest := rawUrl[idx+len(marker):]
	repoName = strings.SplitN(rest, "/", 2)[0]
	if repoName == "" {
		err = fmt.Errorf("could not extract repo name from URL %q", rawUrl)
	}
	return
}

// BuildDependencyTree is supported only for jf curation-audit. It verifies the uv
// version, ensures a temp copy of the project has an up-to-date uv.lock,
// parses it, and returns the dependency tree and download URLs.
// When params.ScriptPath is set, it audits that single PEP 723 inline script instead
func BuildDependencyTree(params technologies.BuildInfoBomGeneratorParams) (
	depTree []*clientutils.GraphNode,
	uniqueDeps []string,
	downloadUrls map[string]string,
	err error,
) {
	if !params.IsCurationCmd {
		err = errorutils.CheckErrorf("uv is supported only for 'jf curation-audit', not 'jf audit'")
		return
	}

	if err = verifyUvVersionSupportedForCuration(); err != nil {
		return
	}

	if params.ScriptPath != "" {
		return buildDependencyTreeForScript(params)
	}

	artiIndexUrl, artifactoryUrl, repoName := "", "", ""
	if params.ServerDetails != nil && params.DependenciesRepository != "" {
		artifactoryUrl = params.ServerDetails.GetArtifactoryUrl()
		repoName = params.DependenciesRepository
		var buildErr error
		artiIndexUrl, buildErr = buildUvCurationIndexUrl(params.ServerDetails, params.DependenciesRepository)
		if buildErr != nil {
			log.Warn(fmt.Sprintf("uv: failed to build curation index URL: %v — will fall back to public PyPI", buildErr))
		}
	}

	lockContent, err := generateUvLockForCuration(artifactoryUrl, repoName, artiIndexUrl)
	if err != nil {
		return
	}

	packages := parseUvLock(lockContent)
	if len(packages) == 0 {
		err = errorutils.CheckErrorf("uv.lock is empty or could not be parsed")
		return
	}

	depTree, uniqueDeps = buildUvDepTree(packages)

	if params.ServerDetails == nil || params.ServerDetails.GetArtifactoryUrl() == "" || params.DependenciesRepository == "" {
		log.Warn("uv: skipping download URL resolution — Artifactory server details or repository not configured")
		return
	}
	downloadUrls = buildUvDownloadUrlsMap(params, packages)
	return
}

// generateUvLockForCuration ensures a temp copy of the project has a uv.lock that is
// trustworthy for curation — regenerating it against Artifactory unless it's already
// verified as resolved from this exact repo — see generateUvLockInTempDir.
func generateUvLockForCuration(artifactoryUrl, repoName, artiIndexUrl string) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", errorutils.CheckError(err)
	}
	log.Info("uv: copying project to a temporary directory and validating uv.lock for curation")
	lockContent, genErr := generateUvLockInTempDir(wd, artifactoryUrl, repoName, artiIndexUrl)
	if genErr != nil {
		return "", fmt.Errorf("uv: lock generation failed: %w", genErr)
	}
	return lockContent, nil
}

// buildDependencyTreeForScript audits a single PEP 723 script (jf ca --script). It
// resolves the script in isolation from any surrounding project, always fresh through
// the curation gateway (there's no existing lock to reuse).
func buildDependencyTreeForScript(params technologies.BuildInfoBomGeneratorParams) (
	depTree []*clientutils.GraphNode,
	uniqueDeps []string,
	downloadUrls map[string]string,
	err error,
) {
	absScriptPath, pathErr := filepath.Abs(params.ScriptPath)
	if pathErr != nil {
		err = errorutils.CheckError(pathErr)
		return
	}
	data, readErr := os.ReadFile(absScriptPath)
	if readErr != nil {
		err = errorutils.CheckErrorf("uv: could not read script %q: %s", params.ScriptPath, readErr)
		return
	}
	if !strings.HasSuffix(absScriptPath, ".py") || !techutils.HasPep723ScriptMetadata(string(data)) {
		err = errorutils.CheckErrorf(
			"uv: %q is not a PEP 723 inline script — it must be a .py file with a "+
				"'# /// script' ... '# ///' metadata block", params.ScriptPath)
		return
	}

	artiIndexUrl, artifactoryUrl, repoName := "", "", ""
	if params.ServerDetails != nil && params.DependenciesRepository != "" {
		artifactoryUrl = params.ServerDetails.GetArtifactoryUrl()
		repoName = params.DependenciesRepository
		var buildErr error
		artiIndexUrl, buildErr = buildUvCurationIndexUrl(params.ServerDetails, params.DependenciesRepository)
		if buildErr != nil {
			log.Warn(fmt.Sprintf("uv: failed to build curation index URL: %v — will fall back to public PyPI", buildErr))
		}
	}

	lockContent, genErr := generateUvScriptLockForCuration(absScriptPath, artiIndexUrl)
	if genErr != nil {
		err = genErr
		return
	}

	packages := parseUvLock(lockContent)
	if len(packages) == 0 {
		err = errorutils.CheckErrorf("script %q has no dependencies to audit", params.ScriptPath)
		return
	}

	depTree, uniqueDeps = buildUvDepTree(packages)

	if artifactoryUrl == "" || repoName == "" {
		log.Warn("uv: skipping download URL resolution — Artifactory server details or repository not configured")
		return
	}
	downloadUrls = buildUvDownloadUrlsMap(params, packages)
	return
}

// generateUvScriptLockForCuration copies scriptPath into an isolated temp dir and runs
// 'uv lock --script' there through the curation gateway, returning the lock content.
func generateUvScriptLockForCuration(scriptPath, artiIndexUrl string) (string, error) {
	tempDir, err := fileutils.CreateTempDir()
	if err != nil {
		return "", err
	}
	defer func() {
		if rmErr := fileutils.RemoveTempDir(tempDir); rmErr != nil {
			log.Warn(fmt.Sprintf("uv: could not remove temp dir %s: %v", tempDir, rmErr))
		}
	}()

	scriptName := filepath.Base(scriptPath)
	data, readErr := os.ReadFile(scriptPath)
	if readErr != nil {
		return "", errorutils.CheckErrorf("uv: could not read script %q: %s", scriptPath, readErr)
	}
	tempScriptPath := filepath.Join(tempDir, scriptName)
	if writeErr := os.WriteFile(tempScriptPath, data, 0644); writeErr != nil {
		return "", errorutils.CheckErrorf("uv: could not copy script to temp dir: %s", writeErr)
	}

	log.Info(fmt.Sprintf("uv: generating a lock for script %q through the curation gateway", scriptName))
	if err = generateUvLock(tempDir, artiIndexUrl, scriptName); err != nil {
		return "", err
	}

	content, readErr := os.ReadFile(tempScriptPath + ".lock")
	if readErr != nil {
		return "", errorutils.CheckErrorf("uv: could not read script lock file: %s", readErr)
	}
	return string(content), nil
}

// generateUvLockInTempDir copies the project into a temp dir and makes sure uv.lock there
// is trustworthy for curation, then returns its content:
//   - Missing, or stale per `uv lock --check` -> always re-resolve through the curation
//     gateway.
//   - In sync, but not verified as already resolved from this exact Artifactory repo ->
//     also re-resolve. "In sync" only means pyproject.toml didn't change — it says nothing
//     about which index produced the lock, so an unverified lock could have been resolved
//     against public PyPI, skipping curation for every package it pins.
//   - In sync AND every package's recorded source is already this Artifactory repo (plain
//     or curation pass-through URL) -> reuse as-is. Nothing is lost by skipping `uv lock`
//     here: the later HEAD-probe step re-checks each package's current policy status
//     straight from these URLs regardless of whether the lock was just regenerated.
func generateUvLockInTempDir(projectDir, artifactoryUrl, repoName, artiIndexUrl string) (string, error) {
	tempDir, err := fileutils.CreateTempDir()
	if err != nil {
		return "", err
	}
	defer func() {
		if rmErr := fileutils.RemoveTempDir(tempDir); rmErr != nil {
			log.Warn(fmt.Sprintf("uv: could not remove temp dir %s: %v", tempDir, rmErr))
		}
	}()

	if err = biutils.CopyDir(projectDir, tempDir, true, []string{technologies.DotVsRepoSuffix}); err != nil {
		return "", fmt.Errorf("uv: could not copy project to temp dir: %w", err)
	}
	// Neutralize the project's own indexes before checking staleness, not just before
	// generating: otherwise "uv lock --check" compares against the project's ambient
	// index (e.g. its own uv.toml), not the curation gateway, and a lock that's genuinely
	// in sync with Artifactory gets misreported as stale.
	if err = neutralizeTempPyprojectIndexes(tempDir); err != nil {
		return "", err
	}

	lockNeedsGenerate, lockIsStale, err := checkUvLockState(tempDir, artiIndexUrl)
	if err != nil {
		return "", err
	}
	lockPath := filepath.Join(tempDir, uvLockFile)

	switch {
	case lockNeedsGenerate:
		log.Debug("uv: no uv.lock found — generating through the curation gateway")
	case lockIsStale:
		log.Debug("uv: uv.lock is stale — updating it through the curation gateway")
	default:
		verified, verifyErr := lockAlreadyResolvedFromArtifactory(lockPath, artifactoryUrl, repoName)
		if verifyErr != nil {
			return "", verifyErr
		}
		if verified {
			log.Debug("uv: uv.lock is up to date and every package is already sourced from this Artifactory repo — reusing as-is")
			content, readErr := os.ReadFile(lockPath)
			if readErr != nil {
				return "", errorutils.CheckErrorf("uv: could not read lock file: %s", readErr)
			}
			return string(content), nil
		}
		log.Debug("uv: uv.lock is up to date but not verified as resolved from this Artifactory repo — re-resolving through the curation gateway")
	}
	if err = generateUvLock(tempDir, artiIndexUrl, ""); err != nil {
		return "", err
	}

	content, err := os.ReadFile(lockPath)
	if err != nil {
		return "", errorutils.CheckErrorf("uv: could not read lock file: %s", err)
	}
	return string(content), nil
}

// lockAlreadyResolvedFromArtifactory reports whether every registry-backed package in the
// uv.lock at lockPath is already sourced from the given Artifactory PyPI repo — either its
// plain URL or its curation pass-through variant (see uvArtifactoryRegistryBases). Returns
// ok=false, nil when artifactoryUrl or repoName is empty, since there's nothing to verify
// against in that case (curation index config could not be resolved).
func lockAlreadyResolvedFromArtifactory(lockPath, artifactoryUrl, repoName string) (ok bool, err error) {
	if artifactoryUrl == "" || repoName == "" {
		return false, nil
	}
	content, readErr := os.ReadFile(lockPath)
	if readErr != nil {
		return false, readErr
	}
	plainBase, passThroughBase := uvArtifactoryRegistryBases(artifactoryUrl, repoName)
	return allPackagesUseRegistry(string(content), plainBase, passThroughBase), nil
}

// uvArtifactoryRegistryBases returns the two URL forms a package's uv.lock
// "source = { registry = ... }" can legitimately have when resolved through this
// Artifactory PyPI repo: the plain repo URL, and its curation pass-through variant
// (the one generateUvLock's UV_DEFAULT_INDEX override actually resolves against).
func uvArtifactoryRegistryBases(artifactoryUrl, repoName string) (plain, passThrough string) {
	base := strings.TrimRight(artifactoryUrl, "/")
	plain = base + "/api/pypi/" + repoName + "/simple"
	passThrough = base + "/" + strings.Trim(coreutils.CurationPassThroughApi, "/") + "/api/pypi/" + repoName + "/simple"
	return
}

// allPackagesUseRegistry reports whether every "source = { ... }" line in uv.lock content
// is either a registry matching one of allowedRegistries, or a source curation doesn't
// apply to (the project root or a workspace member, or a local path/git dependency — none
// of these are resolved from a package index). A registry not in allowedRegistries, or any
// "source" shape not recognized here (e.g. a direct url = "..." dependency), makes the
// whole lock unverified — the caller falls back to a full re-resolution in that case.
func allPackagesUseRegistry(content string, allowedRegistries ...string) bool {
	allowed := make(map[string]bool, len(allowedRegistries))
	for _, r := range allowedRegistries {
		allowed[r] = true
	}
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "source") {
			continue
		}
		switch {
		case strings.Contains(line, "virtual"), strings.Contains(line, "editable"),
			strings.Contains(line, "path ="), strings.Contains(line, "git ="), strings.Contains(line, "directory ="):
			continue // not resolved from a package index — curation doesn't apply
		case strings.Contains(line, "registry"):
			registry, found := extractQuotedField(line, "registry")
			if !found || !allowed[registry] {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// extractQuotedField returns the quoted value of `key = "..."` within line, e.g.
// extractQuotedField(`source = { registry = "https://x" }`, "registry") -> "https://x", true.
func extractQuotedField(line, key string) (string, bool) {
	marker := key + ` = "`
	idx := strings.Index(line, marker)
	if idx < 0 {
		return "", false
	}
	rest := line[idx+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}

// checkUvLockState reports whether uv.lock is missing or stale relative to pyproject.toml,
// via `uv lock --check`. artiIndexUrl is set as UV_DEFAULT_INDEX for the check too, matching
// generateUvLock — otherwise the check would compare against the project's ambient index
// instead of the curation gateway, and a lock genuinely in sync with Artifactory would be
// misreported as stale.
func checkUvLockState(tempDir, artiIndexUrl string) (lockNeedsGenerate, lockIsStale bool, err error) {
	lockExists, existErr := fileutils.IsFileExists(filepath.Join(tempDir, uvLockFile), false)
	if existErr != nil {
		return false, false, existErr
	}
	log.Debug(fmt.Sprintf("uv: uv.lock exists in temp dir: %v", lockExists))
	if !lockExists {
		log.Debug("uv: no uv.lock found — will generate a fresh lock")
		return true, false, nil
	}
	cmd := exec.Command("uv", "lock", "--check")
	cmd.Dir = tempDir
	env, envErr := curationCacheEnv()
	if envErr != nil {
		return false, false, envErr
	}
	if artiIndexUrl != "" {
		env = append(envWithoutKey(env, "UV_DEFAULT_INDEX"), "UV_DEFAULT_INDEX="+artiIndexUrl)
	}
	cmd.Env = env
	out, checkErr := cmd.CombinedOutput()
	lockIsStale = checkErr != nil
	if lockIsStale {
		outStr := maskPassword(string(out), artiIndexUrl)
		log.Debug(fmt.Sprintf("uv: 'uv lock --check' failed, treating uv.lock as stale: %v — %s", checkErr, outStr))
	}
	log.Debug(fmt.Sprintf("uv: stale check result: stale=%v", lockIsStale))
	return false, lockIsStale, nil
}

// neutralizeTempPyprojectIndexes strips the temp copy's own non-explicit
// [[tool.uv.index]] entries so `uv lock` can only resolve through the
// UV_DEFAULT_INDEX we inject. Without this, a project's own index (or a
// mirrored public one) could bypass the curation gateway entirely — either
// a raw 403 or silently resolving packages Artifactory never checked
// (XRAY-146949). Explicit entries are kept — they're only used for
// per-package pinning via [tool.uv.sources].
func neutralizeTempPyprojectIndexes(tempDir string) error {
	pyprojectPath := filepath.Join(tempDir, "pyproject.toml")
	data, err := os.ReadFile(pyprojectPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return errorutils.CheckErrorf("uv: could not read %s: %s", pyprojectPath, err)
	}
	stripped := stripNonExplicitPyprojectIndexes(string(data))
	if stripped == string(data) {
		return nil
	}
	if err = os.WriteFile(pyprojectPath, []byte(stripped), 0644); err != nil {
		return errorutils.CheckErrorf("uv: could not rewrite %s: %s", pyprojectPath, err)
	}
	log.Debug("uv: removed non-explicit [[tool.uv.index]] entries from the temp pyproject.toml copy to force curation-gateway resolution")
	return nil
}

// stripNonExplicitPyprojectIndexes removes every non-explicit [[tool.uv.index]]
// block from content, leaving explicit ([tool.uv.sources]-pinned) blocks untouched.
func stripNonExplicitPyprojectIndexes(content string) string {
	lines := strings.Split(content, "\n")
	var out []string
	i := 0
	for i < len(lines) {
		if strings.TrimSpace(lines[i]) != "[[tool.uv.index]]" {
			out = append(out, lines[i])
			i++
			continue
		}
		blockEnd := i + 1
		explicit := false
		for blockEnd < len(lines) {
			line := strings.TrimSpace(lines[blockEnd])
			if strings.HasPrefix(line, "[") {
				break
			}
			if strings.HasPrefix(line, "explicit") {
				if _, val, ok := strings.Cut(line, "="); ok && strings.TrimSpace(val) == "true" {
					explicit = true
				}
			}
			blockEnd++
		}
		if explicit {
			out = append(out, lines[i:blockEnd]...)
		}
		i = blockEnd
	}
	return strings.Join(out, "\n")
}

// generateUvLock runs `uv lock` in workDir for curation-audit. When scriptName is set,
// it runs `uv lock --script <scriptName>` instead, locking that single PEP 723 inline
// script rather than the project in workDir.
// When artiIndexUrl is set, UV_DEFAULT_INDEX is overridden so uv resolves through Artifactory;
// CVS failures (version stripped from the simple index) become CvsBlockedError.
// When artiIndexUrl is empty (index URL could not be built), uv lock runs with its own config.
func generateUvLock(workDir, artiIndexUrl, scriptName string) error {
	technologies.LogExecutableVersion("uv")
	args := []string{"lock"}
	if scriptName != "" {
		args = append(args, "--script", scriptName)
	}

	if artiIndexUrl != "" {
		cmd := exec.Command("uv", args...)
		cmd.Dir = workDir
		env, envErr := curationCacheEnv()
		if envErr != nil {
			return envErr
		}
		env = append(envWithoutKey(env, "UV_DEFAULT_INDEX"), "UV_DEFAULT_INDEX="+artiIndexUrl)
		cmd.Env = env
		log.Debug("Running uv lock (against Artifactory curation pass-through endpoint)")
		out, err := cmd.CombinedOutput()
		if err == nil {
			return nil
		}
		outStr := maskPassword(string(out), artiIndexUrl)
		log.Debug(fmt.Sprintf("uv: curation lock output (exit %v):\n%s", err, outStr))
		cause := fmt.Errorf("'uv lock' against Artifactory failed: %s — %s", err, outStr)
		return classifyUvCurationLockError(outStr, cause)
	}

	cmd := exec.Command("uv", args...)
	cmd.Dir = workDir
	env, envErr := curationCacheEnv()
	if envErr != nil {
		return envErr
	}
	cmd.Env = env
	log.Debug("Running", coreutils.GetMaskedCommandString(cmd))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("'uv lock' failed: %s — %s", err, out)
	}
	return nil
}

// classifyUvCurationLockError decides how to surface a failed `uv lock` run.
// A CVS-stripped version (removed from the simple index) becomes a
// *CvsBlockedError, routed to the metadata-API fallback for a policy table.
func classifyUvCurationLockError(outStr string, cause error) error {
	wrapped := python.WrapUvCurationErr(outStr, cause)
	if wrapped != cause {
		return wrapped
	}
	if msgToUser := technologies.GetMsgToUserForCurationBlock(true, techutils.Uv, outStr); msgToUser != "" {
		return errors.Join(cause, errors.New(msgToUser))
	}
	return cause
}

// maskPassword replaces the password from rawIndexUrl with "***" in s.
// Prevents credentials from leaking into logs or error output.
func maskPassword(s, rawIndexUrl string) string {
	u, err := url.Parse(rawIndexUrl)
	if err != nil {
		return s
	}
	pw, hasPw := u.User.Password()
	if !hasPw || pw == "" {
		return s
	}
	return strings.ReplaceAll(s, pw, "***")
}

// envWithoutKey returns env with all "KEY=value" entries for the given key removed.
func envWithoutKey(env []string, key string) []string {
	prefix := key + "="
	filtered := make([]string, 0, len(env))
	for _, e := range env {
		if !strings.HasPrefix(e, prefix) {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// curationCacheEnv returns os.Environ() with UV_CACHE_DIR pointed at a dedicated
// curation cache folder, so `uv lock` never reads from or writes to the developer's
// real, shared uv cache (~/.cache/uv by default). Same cache-isolation pattern used by
// maven and go curation via utils.GetCurationCacheFolderByTech (pip and nuget use their
// own dedicated cache-folder helpers, but isolate for the same reason).
func curationCacheEnv() ([]string, error) {
	cacheDir, err := utils.GetCurationCacheFolderByTech(techutils.Uv.String())
	if err != nil {
		return nil, errorutils.CheckErrorf("uv: could not resolve isolated curation cache folder: %s", err)
	}
	return append(envWithoutKey(os.Environ(), "UV_CACHE_DIR"), "UV_CACHE_DIR="+cacheDir), nil
}

// verifyUvVersionSupportedForCuration returns an error if uv isn't installed or is
// below CurationUvMinimumVersion.
func verifyUvVersionSupportedForCuration() error {
	out, err := exec.Command("uv", "--version").CombinedOutput()
	if err != nil {
		return errorutils.CheckErrorf("JFrog CLI uv curation requires uv %s or higher to be installed.", CurationUvMinimumVersion)
	}
	raw := strings.TrimSpace(string(out))
	versionStr := parseUvVersionFromOutput(raw)
	if versionStr == "" {
		log.Debug(fmt.Sprintf("uv: could not parse version from %q — skipping minimum version check", raw))
		return nil
	}
	if !version.NewVersion(versionStr).AtLeast(CurationUvMinimumVersion) {
		return errorutils.CheckErrorf("JFrog CLI uv curation requires uv %s or higher. The current version is: %s", CurationUvMinimumVersion, versionStr)
	}
	return nil
}

// parseUvVersionFromOutput extracts the semver from `uv --version` output ("uv 0.11.21 (...)").
func parseUvVersionFromOutput(raw string) string {
	parts := strings.Fields(raw)
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

// buildUvCurationIndexUrl returns the Artifactory curation pass-through simple-index URL
// with embedded credentials, ready to be set as UV_DEFAULT_INDEX.
func buildUvCurationIndexUrl(serverDetails *config.ServerDetails, repo string) (string, error) {
	rtUrl, username, password, err := artifactoryutils.GetPypiRepoUrlWithCredentials(serverDetails, repo, true)
	if err != nil {
		return "", err
	}
	if password != "" {
		rtUrl.User = url.UserPassword(username, password)
	}
	return rtUrl.String(), nil
}

// parseUvLock parses uv.lock content into a list of uvPackage structs.
func parseUvLock(content string) []uvPackage {
	var packages []uvPackage
	var current *uvPackage
	var inDepsArray, inWheelsArray, inGroupDeps bool

	flush := func() {
		if current != nil {
			packages = append(packages, *current)
			current = nil
		}
		inDepsArray = false
		inWheelsArray = false
		inGroupDeps = false
	}

	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if line == "[[package]]" {
			flush()
			current = &uvPackage{}
			continue
		}
		// Extras and PEP 735 dependency-groups resolve into these sub-tables
		// instead of the plain "dependencies" array — audit them the same way.
		if line == "[package.optional-dependencies]" || line == "[package.dev-dependencies]" {
			inGroupDeps = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			flush()
			continue
		}

		if current == nil {
			continue
		}

		if inGroupDeps && !inDepsArray {
			if strings.Contains(line, "[") {
				current.Dependencies = append(current.Dependencies, parseDepEntries(line)...)
				if !strings.Contains(line, "]") {
					inDepsArray = true
				}
				continue
			}
		}

		if inDepsArray {
			if line == "]" {
				inDepsArray = false
				continue
			}
			current.Dependencies = append(current.Dependencies, parseDepEntries(line)...)
			continue
		}
		if inWheelsArray {
			if line == "]" {
				inWheelsArray = false
				continue
			}
			for _, m := range urlInlineRegex.FindAllStringSubmatch(line, -1) {
				current.DownloadURLs = append(current.DownloadURLs, m[1])
			}
			continue
		}

		if v, ok := parseTomlScalar(line, "name"); ok && current.Name == "" {
			current.Name = v
			continue
		}
		if v, ok := parseTomlScalar(line, "version"); ok && current.Version == "" {
			current.Version = v
			continue
		}
		// The audited project's own package is always at path "." (`editable = "."`
		// or `virtual = "."`). Other workspace members live at their own paths and
		// must not be mistaken for the root, but still need auditing (buildUvDepTree).
		if strings.HasPrefix(line, "source") && (strings.Contains(line, "editable = ") || strings.Contains(line, "virtual = ")) {
			current.IsWorkspace = true
			if strings.Contains(line, `editable = "."`) || strings.Contains(line, `virtual = "."`) {
				current.IsRoot = true
			}
			continue
		}
		if strings.HasPrefix(line, "sdist") {
			for _, m := range urlInlineRegex.FindAllStringSubmatch(line, -1) {
				current.DownloadURLs = append(current.DownloadURLs, m[1])
			}
			continue
		}
		if strings.HasPrefix(line, "wheels") {
			if strings.Contains(line, "]") {
				for _, m := range urlInlineRegex.FindAllStringSubmatch(line, -1) {
					current.DownloadURLs = append(current.DownloadURLs, m[1])
				}
			} else {
				inWheelsArray = true
			}
			continue
		}
		if strings.HasPrefix(line, "dependencies") {
			if strings.Contains(line, "]") {
				current.Dependencies = append(current.Dependencies, parseDepEntries(line)...)
			} else {
				inDepsArray = true
			}
			continue
		}
	}
	flush()
	return packages
}

// parseDepEntries extracts every dependency entry (name and, when present,
// its disambiguating version) found in line.
func parseDepEntries(line string) []uvDependency {
	var deps []uvDependency
	for _, m := range depEntryRegex.FindAllStringSubmatch(line, -1) {
		deps = append(deps, uvDependency{Name: m[1], Version: m[2]})
	}
	return deps
}

func parseTomlScalar(line, key string) (string, bool) {
	rest := strings.TrimSpace(strings.TrimPrefix(line, key))
	if !strings.HasPrefix(rest, "=") {
		return "", false
	}
	rest = strings.TrimSpace(rest[1:])
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

// resolveUvDependency returns the package(s) a dependency edge refers to. uv's
// universal resolver can fork a package into multiple versions (one [[package]]
// block each); when the edge names an exact version (see depEntryRegex), match
// it precisely. Otherwise fall back to every version under that name, so a
// blocked fork is never silently dropped (XRAY-146962).
func resolveUvDependency(byName map[string][]*uvPackage, dep uvDependency) []*uvPackage {
	candidates := byName[python.NormalizePypiName(dep.Name)]
	if dep.Version == "" || len(candidates) <= 1 {
		return candidates
	}
	for _, c := range candidates {
		if c.Version == dep.Version {
			return []*uvPackage{c}
		}
	}
	// Disambiguating version didn't match any known package — stay safe and check every fork.
	return candidates
}

// buildUvDepTree builds an Xray GraphNode dependency tree from the parsed package list.
func buildUvDepTree(packages []uvPackage) ([]*clientutils.GraphNode, []string) {
	byName := make(map[string][]*uvPackage, len(packages))
	for i := range packages {
		key := python.NormalizePypiName(packages[i].Name)
		byName[key] = append(byName[key], &packages[i])
	}

	var rootPkg *uvPackage
	for i := range packages {
		if packages[i].IsRoot {
			rootPkg = &packages[i]
			break
		}
	}

	uniqueDeps := datastructures.MakeSet[string]()

	if rootPkg == nil {
		// No editable root found — wrap all packages under a synthetic root.
		syntheticRoot := &clientutils.GraphNode{Id: "root"}
		for i := range packages {
			if packages[i].Version == "" {
				continue
			}
			id := python.PythonPackageTypeIdentifier + python.NormalizePypiName(packages[i].Name) + ":" + packages[i].Version
			uniqueDeps.Add(id)
			child := &clientutils.GraphNode{Id: id, Parent: syntheticRoot}
			appendUvChildren(child, &packages[i], byName, uniqueDeps)
			syntheticRoot.Nodes = append(syntheticRoot.Nodes, child)
		}
		return []*clientutils.GraphNode{syntheticRoot}, uniqueDeps.ToSlice()
	}

	rootId := python.PythonPackageTypeIdentifier + python.NormalizePypiName(rootPkg.Name) + ":" + rootPkg.Version
	rootNode := &clientutils.GraphNode{Id: rootId}

	for _, depEdge := range rootPkg.Dependencies {
		for _, dep := range resolveUvDependency(byName, depEdge) {
			id := python.PythonPackageTypeIdentifier + python.NormalizePypiName(dep.Name) + ":" + dep.Version
			uniqueDeps.Add(id)
			child := &clientutils.GraphNode{Id: id, Parent: rootNode}
			rootNode.Nodes = append(rootNode.Nodes, child)
			appendUvChildren(child, dep, byName, uniqueDeps)
		}
	}

	depTree := []*clientutils.GraphNode{rootNode}

	// Other workspace members may not be reachable from the root's dependencies
	// (e.g. a shared tool the root app doesn't itself depend on). Audit them too,
	// as sibling roots, instead of silently skipping their dependencies.
	for i := range packages {
		member := &packages[i]
		if !member.IsWorkspace || member.IsRoot || member.Version == "" {
			continue
		}
		id := python.PythonPackageTypeIdentifier + python.NormalizePypiName(member.Name) + ":" + member.Version
		if uniqueDeps.Exists(id) {
			continue
		}
		uniqueDeps.Add(id)
		memberNode := &clientutils.GraphNode{Id: id}
		appendUvChildren(memberNode, member, byName, uniqueDeps)
		depTree = append(depTree, memberNode)
	}

	return depTree, uniqueDeps.ToSlice()
}

// appendUvChildren adds pkg's dependencies as children of node. pkg is the exact
// resolved package node represents; byName resolves each dependency edge via
// resolveUvDependency (see buildUvDepTree).
func appendUvChildren(node *clientutils.GraphNode, pkg *uvPackage, byName map[string][]*uvPackage, uniqueDeps *datastructures.Set[string]) {
	if node.NodeHasLoop() {
		return
	}
	for _, depEdge := range pkg.Dependencies {
		for _, dep := range resolveUvDependency(byName, depEdge) {
			id := python.PythonPackageTypeIdentifier + python.NormalizePypiName(dep.Name) + ":" + dep.Version
			uniqueDeps.Add(id)
			child := &clientutils.GraphNode{Id: id, Parent: node}
			node.Nodes = append(node.Nodes, child)
			appendUvChildren(child, dep, byName, uniqueDeps)
		}
	}
}

// buildUvDownloadUrlsMap returns a package-id → download URL map from uv.lock.
// Strips the curation pass-through prefix and any URL hash fragment when present.
func buildUvDownloadUrlsMap(params technologies.BuildInfoBomGeneratorParams, packages []uvPackage) map[string]string {
	artiBase := strings.TrimSuffix(params.ServerDetails.GetArtifactoryUrl(), "/")
	urls := map[string]string{}
	skipped := 0

	for _, pkg := range packages {
		if pkg.IsRoot || pkg.Name == "" || pkg.Version == "" || len(pkg.DownloadURLs) == 0 {
			skipped++
			continue
		}
		rawURL := pickWheelURL(pkg.DownloadURLs)
		if rawURL == "" {
			log.Debug(fmt.Sprintf("uv: no download URL for %s:%s — skipping HEAD check", pkg.Name, pkg.Version))
			skipped++
			continue
		}
		direct := strings.Replace(rawURL, "api/curation/audit/", "", 1)
		if idx := strings.Index(direct, "#"); idx >= 0 {
			direct = direct[:idx]
		}
		if !strings.HasPrefix(direct, artiBase) {
			log.Debug(fmt.Sprintf("uv: %s:%s URL %q is not an Artifactory URL — skipping HEAD check", pkg.Name, pkg.Version, direct))
			skipped++
			continue
		}
		compId := python.PythonPackageTypeIdentifier + python.NormalizePypiName(pkg.Name) + ":" + pkg.Version
		urls[compId] = direct
		log.Debug(fmt.Sprintf("uv: %s:%s -> %s", pkg.Name, pkg.Version, direct))
	}

	expected := len(packages) - skipped
	resolved := len(urls)
	if resolved < expected {
		log.Warn(fmt.Sprintf(
			"uv: resolved download URLs for %d/%d packages — %d package(s) will not be HEAD-checked. "+
				"Re-run with JFROG_CLI_LOG_LEVEL=DEBUG to see per-package details.",
			resolved, expected, expected-resolved,
		))
	}
	log.Debug(fmt.Sprintf("uv: resolved %d download URLs (skipped %d entries)", resolved, skipped))
	return urls
}

// pickWheelURL returns the first .whl URL, or the first sdist URL if no wheel is present.
func pickWheelURL(downloadURLs []string) string {
	sdist := ""
	for _, u := range downloadURLs {
		base := path.Base(strings.SplitN(u, "#", 2)[0])
		if strings.HasSuffix(base, ".whl") {
			return u
		}
		if sdist == "" {
			sdist = u
		}
	}
	return sdist
}
