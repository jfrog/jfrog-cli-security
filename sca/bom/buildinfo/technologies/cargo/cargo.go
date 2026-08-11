package cargo

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

const (
	PackageTypeIdentifier = "cargo://"

	cargoLockFileName  = "Cargo.lock"
	cargoTomlFileName  = "Cargo.toml"
	cargoTargetDirName = "target"
	cargoConfigDirName = ".cargo"

	// Cargo matches credentials by index URL, not by this name, so one canonical name suffices.
	cargoRegistryName = "artifactory"
)

// ErrCargoWorkspaceAlreadyAudited signals a duplicate --working-dirs entry for an already-audited workspace.
var ErrCargoWorkspaceAlreadyAudited = errors.New("cargo: workspace already audited in this run")

var (
	// Keyed by the audited directory, not the workspace root -- each member still gets its own report.
	cargoAuditedDirs   = map[string]bool{}
	cargoAuditedDirsMu sync.Mutex
)

// alreadyAuditedDir records dir as audited and reports whether it already was.
func alreadyAuditedDir(dir string) bool {
	cargoAuditedDirsMu.Lock()
	defer cargoAuditedDirsMu.Unlock()
	if cargoAuditedDirs[dir] {
		return true
	}
	cargoAuditedDirs[dir] = true
	return false
}

// CargoRegistryConfig holds the Artifactory URL and repo name resolved for the current cargo project.
type CargoRegistryConfig struct {
	ArtifactoryUrl string
	RepoName       string

	// Name of an existing [registries.<name>] entry (strategy 2 or 4), if any.
	AmbientRegistriesName string
}

// GetNativeCargoRegistryConfig reads .cargo/config.toml directly -- there is no 'jf cargo-config' command.
func GetNativeCargoRegistryConfig() (*CargoRegistryConfig, error) {
	content, sourcePath, err := readEffectiveCargoConfig()
	if err != nil {
		return nil, err
	}
	cfg, ok := parseCargoConfigRegistry(content)
	if !ok {
		return nil, errorutils.CheckErrorf(
			"cargo: no Artifactory registry found in %s — configure Cargo to resolve through "+
				"Artifactory via the 'Set Me Up' instructions for your Cargo repository "+
				"([source.crates-io] replace-with, or [registry] default)", sourcePath)
	}
	log.Info(fmt.Sprintf("cargo: using Artifactory URL %q and repository %q from %s", cfg.ArtifactoryUrl, cfg.RepoName, sourcePath))
	return cfg, nil
}

// readEffectiveCargoConfig mirrors Cargo's own config-discovery order: project-local walk-up first, then $CARGO_HOME.
func readEffectiveCargoConfig() (content, sourcePath string, err error) {
	if wd, wdErr := os.Getwd(); wdErr == nil {
		if path, found := findProjectCargoConfig(wd); found {
			if data, readErr := os.ReadFile(path); readErr == nil {
				return string(data), path, nil
			}
		}
	}

	home := os.Getenv("CARGO_HOME")
	if home == "" {
		userHome, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return "", "", errorutils.CheckErrorf("cargo: could not determine home directory: %s", homeErr)
		}
		home = filepath.Join(userHome, ".cargo")
	}
	for _, name := range []string{"config.toml", "config"} {
		path := filepath.Join(home, name)
		if data, readErr := os.ReadFile(path); readErr == nil {
			return string(data), path, nil
		}
	}
	return "", "", errorutils.CheckErrorf(
		"cargo: no .cargo/config.toml found (project-local or in %s) — configure Cargo to resolve "+
			"through Artifactory via the 'Set Me Up' instructions for your Cargo repository", home)
}

// findProjectCargoConfig walks up from dir to $HOME looking for .cargo/config.toml (or legacy .cargo/config).
func findProjectCargoConfig(dir string) (string, bool) {
	home, _ := os.UserHomeDir()
	for {
		for _, name := range []string{"config.toml", "config"} {
			path := filepath.Join(dir, ".cargo", name)
			if _, statErr := os.Stat(path); statErr == nil {
				return path, true
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir || (home != "" && dir == home) {
			return "", false
		}
		dir = parent
	}
}

// cargoConfigFile models the .cargo/config.toml fields needed to discover an Artifactory registry.
type cargoConfigFile struct {
	Registry struct {
		Default string `toml:"default"`
	} `toml:"registry"`
	Registries map[string]struct {
		Index string `toml:"index"`
	} `toml:"registries"`
	Source map[string]struct {
		ReplaceWith string `toml:"replace-with"`
		Registry    string `toml:"registry"`
	} `toml:"source"`
}

// parseCargoConfigRegistry prefers the [source.crates-io] replace-with chain since that's what governs resolution, then [registry] default, then any Artifactory-shaped entry.
func parseCargoConfigRegistry(content string) (*CargoRegistryConfig, bool) {
	var cfg cargoConfigFile
	if _, err := toml.Decode(content, &cfg); err != nil {
		return nil, false
	}

	if cratesIo, ok := cfg.Source["crates-io"]; ok && cratesIo.ReplaceWith != "" {
		if target, ok := cfg.Source[cratesIo.ReplaceWith]; ok && target.Registry != "" {
			if regCfg, err := parseArtifactoryCargoIndexUrl(target.Registry); err == nil {
				return regCfg, true
			}
		}
	}

	if cfg.Registry.Default != "" {
		if target, ok := cfg.Registries[cfg.Registry.Default]; ok && target.Index != "" {
			if regCfg, err := parseArtifactoryCargoIndexUrl(target.Index); err == nil {
				regCfg.AmbientRegistriesName = cfg.Registry.Default
				return regCfg, true
			}
		}
	}

	for name, src := range cfg.Source {
		if name == "crates-io" || src.Registry == "" {
			continue
		}
		if regCfg, err := parseArtifactoryCargoIndexUrl(src.Registry); err == nil {
			return regCfg, true
		}
	}
	for name, reg := range cfg.Registries {
		if reg.Index == "" {
			continue
		}
		if regCfg, err := parseArtifactoryCargoIndexUrl(reg.Index); err == nil {
			regCfg.AmbientRegistriesName = name
			return regCfg, true
		}
	}
	return nil, false
}

// parseArtifactoryCargoIndexUrl splits a Cargo sparse-index URL into its Artifactory base URL and repo name.
func parseArtifactoryCargoIndexUrl(rawUrl string) (*CargoRegistryConfig, error) {
	trimmed := strings.TrimPrefix(strings.TrimSpace(rawUrl), "sparse+")
	const marker = "/api/cargo/"
	idx := strings.Index(trimmed, marker)
	if idx < 0 {
		return nil, fmt.Errorf("URL %q does not match Artifactory Cargo format (.../api/cargo/<repo>/index/)", rawUrl)
	}
	artiUrl := trimmed[:idx]
	rest := strings.TrimPrefix(trimmed[idx:], marker)
	repoName := strings.SplitN(rest, "/", 2)[0]
	if repoName == "" || artiUrl == "" {
		return nil, fmt.Errorf("could not extract Artifactory URL/repo from %q", rawUrl)
	}
	return &CargoRegistryConfig{ArtifactoryUrl: artiUrl, RepoName: repoName}, nil
}

// DetectConflictingCargoSources catches the same repo configured under different names across project-local and global .cargo/config.toml.
func DetectConflictingCargoSources() error {
	type ref struct {
		name, path string
	}
	// "<table>/<url>" -- source and registries names are never compared to each other.
	byTableAndUrl := map[string][]ref{}

	addRefs := func(content, path string) {
		var cfg cargoConfigFile
		if _, err := toml.Decode(content, &cfg); err != nil {
			return
		}
		for name, src := range cfg.Source {
			if name == "crates-io" || src.Registry == "" {
				continue
			}
			if regCfg, err := parseArtifactoryCargoIndexUrl(src.Registry); err == nil {
				key := "source/" + regCfg.ArtifactoryUrl + "/" + regCfg.RepoName
				byTableAndUrl[key] = append(byTableAndUrl[key], ref{name, path})
			}
		}
		for name, reg := range cfg.Registries {
			if reg.Index == "" {
				continue
			}
			if regCfg, err := parseArtifactoryCargoIndexUrl(reg.Index); err == nil {
				key := "registries/" + regCfg.ArtifactoryUrl + "/" + regCfg.RepoName
				byTableAndUrl[key] = append(byTableAndUrl[key], ref{name, path})
			}
		}
	}

	if wd, wdErr := os.Getwd(); wdErr == nil {
		if path, found := findProjectCargoConfig(wd); found {
			if data, readErr := os.ReadFile(path); readErr == nil {
				addRefs(string(data), path)
			}
		}
	}
	home := os.Getenv("CARGO_HOME")
	if home == "" {
		if userHome, homeErr := os.UserHomeDir(); homeErr == nil {
			home = filepath.Join(userHome, ".cargo")
		}
	}
	if home != "" {
		for _, fname := range []string{"config.toml", "config"} {
			if data, readErr := os.ReadFile(filepath.Join(home, fname)); readErr == nil {
				addRefs(string(data), filepath.Join(home, fname))
				break
			}
		}
	}

	for _, refs := range byTableAndUrl {
		byName := map[string][]string{}
		for _, r := range refs {
			byName[r.name] = append(byName[r.name], r.path)
		}
		if len(byName) < 2 {
			continue
		}
		names := make([]string, 0, len(byName))
		for n := range byName {
			names = append(names, n)
		}
		sort.Strings(names)
		var details []string
		for _, name := range names {
			details = append(details, fmt.Sprintf("%q (in %s)", name, strings.Join(byName[name], ", ")))
		}
		return errorutils.CheckErrorf(
			"cargo: the same Artifactory Cargo repo is configured under different names across your "+
				".cargo/config.toml files: %s. Cargo does not allow this and it will also break a plain "+
				"'cargo build' -- align the names used in both files, or remove the redundant entry.",
			strings.Join(details, "; "))
	}
	return nil
}

// cargoLockFile models the [[package]] shape shared by every Cargo.lock format version (V1-V4).
type cargoLockFile struct {
	Version  int            `toml:"version"`
	Packages []cargoPackage `toml:"package"`
}

type cargoPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
	// Source is empty for the audited project's own package and any local path/workspace member.
	Source       string   `toml:"source"`
	Dependencies []string `toml:"dependencies"`
}

type cargoManifest struct {
	Package *struct {
		Name string `toml:"name"`
	} `toml:"package"`
	Workspace         *struct{}              `toml:"workspace"`
	Dependencies      map[string]interface{} `toml:"dependencies"`
	DevDependencies   map[string]interface{} `toml:"dev-dependencies"`
	BuildDependencies map[string]interface{} `toml:"build-dependencies"`
}

// extractVersionReq pulls the version requirement out of a dependency value (plain string or table); "" for path/git deps.
func extractVersionReq(raw interface{}) string {
	switch v := raw.(type) {
	case string:
		return v
	case map[string]interface{}:
		if ver, ok := v["version"].(string); ok {
			return ver
		}
	}
	return ""
}

// collectDeclaredDependenciesByPackage walks every Cargo.toml under root and returns each package's declared dependency names and version requirements.
func collectDeclaredDependenciesByPackage(root string) (map[string]map[string]string, error) {
	byPackage := map[string]map[string]string{}
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != cargoTomlFileName {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		var manifest cargoManifest
		if _, decErr := toml.Decode(string(data), &manifest); decErr != nil {
			return nil
		}
		if manifest.Package == nil || manifest.Package.Name == "" {
			return nil // virtual workspace root -- nothing of its own to check; members are visited separately
		}
		reqs := map[string]string{}
		for _, deps := range []map[string]interface{}{manifest.Dependencies, manifest.DevDependencies, manifest.BuildDependencies} {
			for name, raw := range deps {
				reqs[name] = extractVersionReq(raw)
			}
		}
		byPackage[manifest.Package.Name] = reqs
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return byPackage, nil
}

// lockMatchesDeclaredDependencies reports whether Cargo.lock still matches Cargo.toml's declared deps.
// Only exact pins are verified against the locked version; any other requirement forces regeneration.
func lockMatchesDeclaredDependencies(lockPath string, declaredByPackage map[string]map[string]string) bool {
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return false
	}
	var lock cargoLockFile
	if _, decErr := toml.Decode(string(data), &lock); decErr != nil {
		return false
	}
	byName := make(map[string][]*cargoPackage, len(lock.Packages))
	pkgs := make([]cargoPackage, len(lock.Packages))
	copy(pkgs, lock.Packages)
	for i := range pkgs {
		byName[pkgs[i].Name] = append(byName[pkgs[i].Name], &pkgs[i])
	}

	for pkgName, declaredReqs := range declaredByPackage {
		self := findLocalPackage(byName[pkgName])
		if self == nil {
			return false
		}
		lockedEdges := map[string]string{} // dep name -> raw lock edge string
		for _, edge := range self.Dependencies {
			name, _ := parseCargoDependencyEntry(edge)
			lockedEdges[name] = edge
		}
		if len(lockedEdges) != len(declaredReqs) {
			return false
		}
		for depName, req := range declaredReqs {
			edge, ok := lockedEdges[depName]
			if !ok {
				return false
			}
			trimmed := strings.TrimSpace(req)
			resolved := resolveCargoDependency(byName, edge)
			if exactVersion, ok := strings.CutPrefix(trimmed, "="); ok {
				if len(resolved) != 1 || resolved[0].Version != exactVersion {
					return false
				}
				continue
			}
			lower, upper, ok := caretBounds(trimmed)
			if !ok {
				return false // tilde, wildcard, comparison operator, multi-req, or none (path/git dep) -- can't verify, so regenerate
			}
			if len(resolved) != 1 || !versionSatisfiesCaret(resolved[0].Version, lower, upper) {
				return false
			}
		}
	}
	return true
}

// caretBounds computes the inclusive lower and exclusive upper bound of a default/caret Cargo version
// requirement ("1.2.3", "^1.2.3", "1.2", "1", ...); ok is false for anything else (tilde, wildcard,
// comparison operators, multiple comma-separated requirements, or a pre-release/build-metadata suffix).
func caretBounds(req string) (lower, upper [3]int, ok bool) {
	req = strings.TrimPrefix(req, "^")
	if req == "" {
		return lower, upper, false
	}
	parts := strings.Split(req, ".")
	if len(parts) > 3 {
		return lower, upper, false
	}
	var comps [3]int
	incrementAt := len(parts) - 1
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return lower, upper, false
		}
		comps[i] = n
	}
	for i := 0; i < len(parts); i++ {
		if comps[i] != 0 {
			incrementAt = i
			break
		}
	}
	lower = comps
	upper = comps
	upper[incrementAt]++
	for i := incrementAt + 1; i < 3; i++ {
		upper[i] = 0
	}
	return lower, upper, true
}

// versionSatisfiesCaret reports whether a plain "X.Y.Z" version falls within [lower, upper).
func versionSatisfiesCaret(version string, lower, upper [3]int) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	var v [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return false
		}
		v[i] = n
	}
	return compareVersionTriples(v, lower) >= 0 && compareVersionTriples(v, upper) < 0
}

func compareVersionTriples(a, b [3]int) int {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// findCargoWorkspaceRoot walks up from dir for an ancestor Cargo.toml with a [workspace] table.
func findCargoWorkspaceRoot(dir string) string {
	home, _ := os.UserHomeDir()
	for {
		if data, err := os.ReadFile(filepath.Join(dir, cargoTomlFileName)); err == nil {
			var manifest cargoManifest
			if _, decErr := toml.Decode(string(data), &manifest); decErr == nil && manifest.Workspace != nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir || (home != "" && dir == home) {
			return ""
		}
		dir = parent
	}
}

// BuildDependencyTree uses 'cargo generate-lockfile', not 'cargo metadata', since metadata fails outright when any package is curation-blocked at download time.
func BuildDependencyTree(params technologies.BuildInfoBomGeneratorParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	if !params.IsCurationCmd {
		err = errorutils.CheckErrorf("cargo is supported only for 'jf curation-audit', not 'jf audit'")
		return
	}
	currentDir, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return
	}

	if alreadyAuditedDir(currentDir) {
		err = ErrCargoWorkspaceAlreadyAudited
		return
	}

	// Resolved as part of the whole workspace; the reported tree stays scoped via rootName below.
	copyRoot := currentDir
	if wsRoot := findCargoWorkspaceRoot(currentDir); wsRoot != "" {
		copyRoot = wsRoot
	}

	cargoExecPath, err := exec.LookPath("cargo")
	if err != nil {
		err = errorutils.CheckErrorf("could not find the 'cargo' executable in the system PATH")
		return
	}

	if params.IsCurationCmd && params.ServerDetails != nil && params.DependenciesRepository != "" {
		var restore func() error
		if restore, err = protectCargoCurationEnvironment(params.ServerDetails, params.DependenciesRepository); err != nil {
			return
		}
		defer func() {
			if restoreErr := restore(); restoreErr != nil {
				log.Warn(fmt.Sprintf("cargo: failed to restore CARGO_HOME: %v", restoreErr))
			}
		}()
	}

	// Resolve in a temp copy, never the real project -- same non-destructiveness guarantee as uv's generateUvLockInTempDir.
	tempDir, tempErr := fileutils.CreateTempDir()
	if tempErr != nil {
		err = tempErr
		return
	}
	defer func() {
		if rmErr := fileutils.RemoveTempDir(tempDir); rmErr != nil {
			log.Warn(fmt.Sprintf("cargo: could not remove temp dir %s: %v", tempDir, rmErr))
		}
	}()
	// Exclude .cargo: a project-shipped config.toml would otherwise take precedence over the isolated CARGO_HOME below.
	if err = biutils.CopyDir(copyRoot, tempDir, true, []string{technologies.DotVsRepoSuffix, cargoTargetDirName, cargoConfigDirName}); err != nil {
		err = fmt.Errorf("cargo: could not copy project to temp dir: %w", err)
		return
	}

	// A checked-in lock is used as-is unless it's missing or stale relative to Cargo.toml.
	lockPath := filepath.Join(tempDir, cargoLockFileName)
	_, statErr := os.Stat(lockPath)
	lockIsStale := true
	if statErr == nil {
		if declaredByPackage, namesErr := collectDeclaredDependenciesByPackage(tempDir); namesErr == nil {
			lockIsStale = !lockMatchesDeclaredDependencies(lockPath, declaredByPackage)
		}
	}
	if lockIsStale {
		if err = ensureCargoLockfile(cargoExecPath, tempDir); err != nil {
			return
		}
	}

	lockContent, err := os.ReadFile(lockPath)
	if err != nil {
		err = errorutils.CheckErrorf("cargo: could not read %s: %s", cargoLockFileName, err)
		return
	}
	var lock cargoLockFile
	if _, tomlErr := toml.Decode(string(lockContent), &lock); tomlErr != nil {
		err = errorutils.CheckErrorf("cargo: could not parse %s: %s", cargoLockFileName, tomlErr)
		return
	}
	if len(lock.Packages) == 0 {
		err = errorutils.CheckErrorf("cargo: %s has no packages", cargoLockFileName)
		return
	}

	// currentDir, not tempDir/copyRoot -- the tree must stay scoped to the directory actually audited.
	rootName := readRootPackageName(currentDir)
	dependencyTrees, uniqueDeps, err = buildCargoDepTree(lock, rootName)
	return
}

// ensureCargoLockfile regenerates Cargo.lock without downloading/verifying any .crate archive (resolve-only).
func ensureCargoLockfile(cargoExecPath, workingDir string) error {
	technologies.LogExecutableVersion("cargo")
	cmd := exec.Command(cargoExecPath, "generate-lockfile") // #nosec G204 -- cargoExecPath resolved via exec.LookPath
	cmd.Dir = workingDir
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	outStr := string(out)
	if strings.Contains(outStr, "authenticated registries require a credential-provider to be configured") {
		// Cargo's own error for a pre-1.74 version that predates global-credential-providers.
		return fmt.Errorf("'cargo generate-lockfile' failed: %w - %s (this usually means your local Cargo is older than 1.74 — upgrade with 'rustup update')", err, outStr)
	}
	return fmt.Errorf("'cargo generate-lockfile' failed: %w - %s", err, outStr)
}

// readRootPackageName returns Cargo.toml's [package].name, or "" for a virtual workspace manifest.
func readRootPackageName(workingDir string) string {
	data, err := os.ReadFile(filepath.Join(workingDir, cargoTomlFileName))
	if err != nil {
		return ""
	}
	var manifest cargoManifest
	if _, err = toml.Decode(string(data), &manifest); err != nil || manifest.Package == nil {
		return ""
	}
	return manifest.Package.Name
}

// buildCargoDepTree builds the tree from a parsed Cargo.lock, falling back to a synthetic root over every local package when there's no single [package] (virtual workspace).
func buildCargoDepTree(lock cargoLockFile, rootName string) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	byName := make(map[string][]*cargoPackage, len(lock.Packages))
	pkgs := make([]cargoPackage, len(lock.Packages))
	copy(pkgs, lock.Packages)
	for i := range pkgs {
		byName[pkgs[i].Name] = append(byName[pkgs[i].Name], &pkgs[i])
	}
	uniqueDepsSet := datastructures.MakeSet[string]()

	if rootName != "" {
		if root := findLocalPackage(byName[rootName]); root != nil {
			rootNode := &xrayUtils.GraphNode{Id: PackageTypeIdentifier + root.Name + ":" + root.Version}
			appendCargoChildren(rootNode, root, byName, uniqueDepsSet)
			return []*xrayUtils.GraphNode{rootNode}, uniqueDepsSet.ToSlice(), nil
		}
	}

	syntheticRoot := &xrayUtils.GraphNode{Id: "root"}
	for i := range pkgs {
		if pkgs[i].Source != "" {
			continue
		}
		appendCargoChildren(syntheticRoot, &pkgs[i], byName, uniqueDepsSet)
	}
	if len(syntheticRoot.Nodes) == 0 {
		return nil, nil, errorutils.CheckErrorf("cargo: could not identify the project's package(s) in %s", cargoLockFileName)
	}
	return []*xrayUtils.GraphNode{syntheticRoot}, uniqueDepsSet.ToSlice(), nil
}

// findLocalPackage returns the local (Source == "") candidate among same-named packages, falling back to the first.
func findLocalPackage(candidates []*cargoPackage) *cargoPackage {
	for _, c := range candidates {
		if c.Source == "" {
			return c
		}
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	return nil
}

// appendCargoChildren recursively adds pkg's dependency edges as children of node.
func appendCargoChildren(node *xrayUtils.GraphNode, pkg *cargoPackage, byName map[string][]*cargoPackage, uniqueDeps *datastructures.Set[string]) {
	if node.NodeHasLoop() {
		return
	}
	for _, edge := range pkg.Dependencies {
		deps := resolveCargoDependency(byName, edge)
		if len(deps) == 0 {
			log.Debug(fmt.Sprintf("cargo: dependency edge %q from %s:%s not found in %s — skipping", edge, pkg.Name, pkg.Version, cargoLockFileName))
			continue
		}
		for _, dep := range deps {
			id := PackageTypeIdentifier + dep.Name + ":" + dep.Version
			uniqueDeps.Add(id)
			child := &xrayUtils.GraphNode{Id: id, Parent: node}
			node.Nodes = append(node.Nodes, child)
			appendCargoChildren(child, dep, byName, uniqueDeps)
		}
	}
}

// resolveCargoDependency matches an exact version when the edge disambiguates one, else returns every same-named candidate so a blocked fork isn't dropped.
func resolveCargoDependency(byName map[string][]*cargoPackage, edge string) []*cargoPackage {
	name, version := parseCargoDependencyEntry(edge)
	candidates := byName[name]
	if len(candidates) == 0 {
		return nil
	}
	if version == "" || len(candidates) == 1 {
		return candidates
	}
	for _, c := range candidates {
		if c.Version == version {
			return []*cargoPackage{c}
		}
	}
	return candidates
}

// parseCargoDependencyEntry splits a Cargo.lock dependency edge into name and optional disambiguating version.
func parseCargoDependencyEntry(edge string) (name, version string) {
	fields := strings.Fields(edge)
	if len(fields) == 0 {
		return "", ""
	}
	name = fields[0]
	if len(fields) > 1 {
		version = fields[1]
	}
	return
}

// protectCargoCurationEnvironment points CARGO_HOME at an isolated temp dir for the duration of resolution, same pattern pipenv curation uses.
func protectCargoCurationEnvironment(server *config.ServerDetails, repoName string) (restore func() error, err error) {
	tempHome, err := fileutils.CreateTempDir()
	if err != nil {
		return nil, err
	}
	cleanup := func() error { return fileutils.RemoveTempDir(tempHome) }

	sparseUrl := "sparse+" + strings.TrimRight(server.GetArtifactoryUrl(), "/") + "/api/cargo/" + repoName + "/index/"

	// Reuse the ambient config's own registries name -- a mismatched duplicate for the same URL makes real cargo fail.
	registriesName := cargoRegistryName
	if ambient, ambientErr := GetNativeCargoRegistryConfig(); ambientErr == nil && ambient != nil && ambient.AmbientRegistriesName != "" {
		registriesName = ambient.AmbientRegistriesName
	}
	// Always self-contained: the ambient config's own crates-io replacement is invisible once CARGO_HOME is redirected below.
	sourceBlock := fmt.Sprintf("\n[source.%s-remote]\nregistry = %q\n\n[source.crates-io]\nreplace-with = %q\n",
		cargoRegistryName, sparseUrl, cargoRegistryName+"-remote")

	configContent := fmt.Sprintf(`[registry]
default = %q
global-credential-providers = ["cargo:token"]

[registries.%s]
index = %q
%s`, registriesName, registriesName, sparseUrl, sourceBlock)

	if err = os.WriteFile(filepath.Join(tempHome, "config.toml"), []byte(configContent), 0600); err != nil { // #nosec G306 -- isolated temp CARGO_HOME, not the user's real config
		return nil, errors.Join(err, cleanup())
	}

	token, tokenErr := cargoBasicAuthToken(server)
	if tokenErr != nil {
		return nil, errors.Join(tokenErr, cleanup())
	}
	credsContent := fmt.Sprintf("[registries.%s]\ntoken = %q\n", registriesName, token)
	if err = os.WriteFile(filepath.Join(tempHome, "credentials.toml"), []byte(credsContent), 0600); err != nil { // #nosec G306 -- isolated temp CARGO_HOME
		return nil, errors.Join(err, cleanup())
	}

	previousHome, hadHome := os.LookupEnv("CARGO_HOME")
	if err = os.Setenv("CARGO_HOME", tempHome); err != nil {
		return nil, errors.Join(err, cleanup())
	}
	restore = func() error {
		var restoreErr error
		if hadHome {
			restoreErr = os.Setenv("CARGO_HOME", previousHome)
		} else {
			restoreErr = os.Unsetenv("CARGO_HOME")
		}
		return errors.Join(restoreErr, cleanup())
	}
	return restore, nil
}

// cargoBasicAuthToken builds the Basic-auth token Artifactory expects, using an access token as the password if no password is set.
func cargoBasicAuthToken(server *config.ServerDetails) (string, error) {
	if server == nil {
		return "", errorutils.CheckErrorf("cargo: no Artifactory server details available for authentication")
	}
	password := server.GetPassword()
	if password == "" {
		password = server.GetAccessToken()
	}
	if password == "" {
		return "", errorutils.CheckErrorf("cargo: Artifactory server has no password or access token configured for curation authentication")
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(server.GetUser()+":"+password)), nil
}
