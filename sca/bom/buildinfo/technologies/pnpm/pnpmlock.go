package pnpm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// pnpmLockFile is the top-level structure of pnpm-lock.yaml.
type pnpmLockFile struct {
	LockfileVersion string                      `yaml:"lockfileVersion"`
	Importers       map[string]pnpmLockImporter `yaml:"importers"`
	Snapshots       map[string]pnpmLockSnapshot `yaml:"snapshots"`
}

// pnpmLockImporter represents a workspace member (or the root project at ".").
type pnpmLockImporter struct {
	Dependencies         map[string]pnpmLockDep `yaml:"dependencies"`
	DevDependencies      map[string]pnpmLockDep `yaml:"devDependencies"`
	OptionalDependencies map[string]pnpmLockDep `yaml:"optionalDependencies"`
}

// pnpmLockDep holds the resolved version and original specifier for a direct dependency.
type pnpmLockDep struct {
	Specifier string `yaml:"specifier"`
	Version   string `yaml:"version"`
}

// pnpmLockSnapshot is one entry in the snapshots block.
// The key format is "<name>@<version>(<peer1>@<v>)(<peer2>@<v>)..." but we
// strip the peer suffix when building Xray dependency IDs.
type pnpmLockSnapshot struct {
	// Dependencies are keyed by bare package name; values are either a plain
	// version string or a version+peer-suffix string (e.g. "3.0.5(@foo/bar@1.2)").
	Dependencies map[string]string `yaml:"dependencies"`
}

// parsePnpmLockFile reads workingDir/pnpm-lock.yaml and converts it into []pnpmLsProject,
// scoped by importer:
//   - importer "." (or "") collapses the whole workspace into a single project rooted at
//     the "." importer, with each member attached as a direct dependency — mirroring how
//     npm records root→workspace edges, so a root-level `jf ca` audits the whole workspace.
//   - a member importer (e.g. "packages/app") returns only that member as its own project,
//     used when `jf ca --working-dirs=<member>` targets a single workspace package.
//
// Names/versions come from each importer's package.json when available.
func parsePnpmLockFile(workingDir, importer string) ([]pnpmLsProject, error) {
	lockPath := filepath.Join(workingDir, "pnpm-lock.yaml")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("reading pnpm-lock.yaml: %w", err)
	}

	var lf pnpmLockFile
	if err = yaml.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("parsing pnpm-lock.yaml: %w", err)
	}

	if err = validateLockfileVersion(lf.LockfileVersion); err != nil {
		return nil, err
	}

	if len(lf.Importers) == 0 {
		return nil, fmt.Errorf("pnpm-lock.yaml has no importers block; run 'pnpm install --lockfile-only' first")
	}

	if importer != "" && importer != "." {
		return parseSingleImporter(workingDir, importer, lf)
	}

	rootName, rootVersion := readPackageNameVersion(workingDir, ".")
	root := pnpmLsProject{Name: rootName, Version: rootVersion}
	if rootImporter, ok := lf.Importers["."]; ok {
		visited := map[string]bool{}
		root.Dependencies = buildProdDepsMap(rootImporter, lf.Snapshots, visited)
		root.DevDependencies = buildDepsMap(rootImporter.DevDependencies, lf.Snapshots, visited)
	}

	// Nest every workspace member (any importer other than ".") as a direct dependency
	// of the root so the whole workspace is audited under a single npm-like tree.
	for importerPath, importer := range lf.Importers {
		if importerPath == "." {
			continue
		}
		memberName, memberVersion := readPackageNameVersion(workingDir, importerPath)
		visited := map[string]bool{}
		memberDeps := buildProdDepsMap(importer, lf.Snapshots, visited)
		for depName, dep := range buildDepsMap(importer.DevDependencies, lf.Snapshots, visited) {
			if memberDeps == nil {
				memberDeps = map[string]pnpmLsDependency{}
			}
			memberDeps[depName] = dep
		}
		if root.Dependencies == nil {
			root.Dependencies = map[string]pnpmLsDependency{}
		}
		root.Dependencies[memberName] = pnpmLsDependency{
			From:         memberName,
			Version:      memberVersion,
			Dependencies: memberDeps,
			Local:        true,
		}
	}
	return []pnpmLsProject{root}, nil
}

// buildProdDepsMap merges an importer's regular and optional dependencies into one
// production dependency map. pnpm installs optionalDependencies by default (when the
// platform matches), so curation must evaluate them alongside regular dependencies.
func buildProdDepsMap(imp pnpmLockImporter, snapshots map[string]pnpmLockSnapshot, visited map[string]bool) map[string]pnpmLsDependency {
	prod := buildDepsMap(imp.Dependencies, snapshots, visited)
	for name, dep := range buildDepsMap(imp.OptionalDependencies, snapshots, visited) {
		if prod == nil {
			prod = map[string]pnpmLsDependency{}
		}
		prod[name] = dep
	}
	return prod
}

// parseSingleImporter returns only the given workspace member as its own project (its
// own deps and devDeps, with transitives), used when a run is scoped to one member via
// --working-dirs. The member is the tree root here, so it is skipped from the curation
// HEAD-check the same way any project root is.
func parseSingleImporter(workingDir, importerPath string, lf pnpmLockFile) ([]pnpmLsProject, error) {
	imp, ok := lf.Importers[importerPath]
	if !ok {
		return nil, fmt.Errorf("pnpm workspace member %q is not recorded in pnpm-lock.yaml; run 'pnpm install --lockfile-only' to refresh it", importerPath)
	}
	name, version := readPackageNameVersion(workingDir, importerPath)
	project := pnpmLsProject{Name: name, Version: version}
	visited := map[string]bool{}
	project.Dependencies = buildProdDepsMap(imp, lf.Snapshots, visited)
	project.DevDependencies = buildDepsMap(imp.DevDependencies, lf.Snapshots, visited)
	return []pnpmLsProject{project}, nil
}

// buildDepsMap converts a direct-dependency map from the importers block into
// the nested pnpmLsDependency tree, walking the snapshots block for transitive deps.
func buildDepsMap(deps map[string]pnpmLockDep, snapshots map[string]pnpmLockSnapshot, visited map[string]bool) map[string]pnpmLsDependency {
	if len(deps) == 0 {
		return nil
	}
	result := make(map[string]pnpmLsDependency)
	for name, dep := range deps {
		// dep.Version may contain a peer-dep suffix: "2.0.0(@peer/dep@1.0.0)"
		// Strip it for the Xray ID; keep the raw form for snapshot lookup.
		rawRef := dep.Version
		_, cleanVersion := splitPnpmRef(rawRef)
		depKey := buildSnapshotKey(name, rawRef)

		entry := pnpmLsDependency{
			From:    name,
			Version: cleanVersion,
		}
		if !visited[depKey] {
			visited[depKey] = true
			entry.Dependencies = walkSnapshot(depKey, snapshots, visited)
			visited[depKey] = false // allow same package at different depths
		}
		result[name] = entry
	}
	return result
}

// walkSnapshot recursively resolves transitive dependencies from the snapshots block.
func walkSnapshot(snapshotKey string, snapshots map[string]pnpmLockSnapshot, visited map[string]bool) map[string]pnpmLsDependency {
	snap, ok := snapshots[snapshotKey]
	if !ok || len(snap.Dependencies) == 0 {
		return nil
	}
	result := make(map[string]pnpmLsDependency)
	for name, rawRef := range snap.Dependencies {
		_, cleanVersion := splitPnpmRef(rawRef)
		childKey := buildSnapshotKey(name, rawRef)
		entry := pnpmLsDependency{
			From:    name,
			Version: cleanVersion,
		}
		if !visited[childKey] {
			visited[childKey] = true
			entry.Dependencies = walkSnapshot(childKey, snapshots, visited)
			visited[childKey] = false
		}
		result[name] = entry
	}
	return result
}

// splitPnpmRef splits a pnpm ref into (name, version), stripping any peer-dep suffix.
// Splits on the last '@' so scoped names like "@scope/pkg" are handled correctly.
func splitPnpmRef(ref string) (name, version string) {
	if i := strings.IndexByte(ref, '('); i >= 0 {
		ref = ref[:i]
	}
	i := strings.LastIndexByte(ref, '@')
	if i <= 0 {
		return "", ref
	}
	return ref[:i], ref[i+1:]
}

// buildSnapshotKey returns the snapshots-map key for a dependency. rawRef is usually a
// bare version, giving "<name>@<rawRef>". For an aliased dep ("npm:<target>@<range>"),
// rawRef is the target ref (e.g. "@babel/code-frame@7.29.7") which is itself the key, so
// it is returned as-is — detected by '@' in the version part (ignoring the peer suffix).
func buildSnapshotKey(name, rawRef string) string {
	base := rawRef
	if i := strings.IndexByte(base, '('); i >= 0 {
		base = base[:i]
	}
	if strings.Contains(base, "@") {
		return rawRef
	}
	return name + "@" + rawRef
}

// readPackageNameVersion reads name and version from the package.json at
// workingDir/<importerPath>/package.json. Falls back to the importer path as
// the name and "0.0.0" as the version if the file is absent or unreadable.
func readPackageNameVersion(workingDir, importerPath string) (name, version string) {
	dir := workingDir
	if importerPath != "." {
		dir = filepath.Join(workingDir, importerPath)
	}
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return importerPath, "0.0.0"
	}
	var pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err = json.Unmarshal(data, &pkg); err != nil || pkg.Name == "" {
		return importerPath, "0.0.0"
	}
	if pkg.Version == "" {
		pkg.Version = "0.0.0"
	}
	return pkg.Name, pkg.Version
}

// lockfileSpecifiersDrift reports whether workingDir's package.json declares a
// different set of direct-dependency specifiers than its pnpm-lock.yaml records —
// covering added, removed, and changed specifiers. jf ca operates on the given
// directory, whose lockfile records that project under the "." importer, so the
// comparison is against "." only. Returns false on any read/parse error so the
// caller falls back to mtime-only.
func lockfileSpecifiersDrift(workingDir, lockPath string) bool {
	pkgData, err := os.ReadFile(filepath.Join(workingDir, "package.json"))
	if err != nil {
		return false
	}
	var pkg struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err = json.Unmarshal(pkgData, &pkg); err != nil {
		return false
	}

	lockData, err := os.ReadFile(lockPath)
	if err != nil {
		return false
	}
	var lf pnpmLockFile
	if err = yaml.Unmarshal(lockData, &lf); err != nil {
		return false
	}

	rootImporter, ok := lf.Importers["."]
	if !ok {
		return false
	}
	return specifiersDiffer(pkg.Dependencies, rootImporter.Dependencies) ||
		specifiersDiffer(pkg.DevDependencies, rootImporter.DevDependencies) ||
		specifiersDiffer(pkg.OptionalDependencies, rootImporter.OptionalDependencies)
}

// specifiersDiffer reports whether the package.json dependency specifiers differ
// from the lockfile importer entry in EITHER direction — a differing count catches
// added or removed deps, and the per-name check catches changed or missing specifiers.
func specifiersDiffer(pkgDeps map[string]string, lockDeps map[string]pnpmLockDep) bool {
	if len(pkgDeps) != len(lockDeps) {
		return true
	}
	for name, specifier := range pkgDeps {
		lockDep, ok := lockDeps[name]
		if !ok || lockDep.Specifier != specifier {
			return true
		}
	}
	return false
}

// validateLockfileVersion accepts only lockfileVersion 9.0+, which introduced the
// 'snapshots' block this parser reads. Older formats (5.x–8.x) use a differently-shaped
// 'packages' block and would yield an empty snapshots map, silently dropping transitives.
func validateLockfileVersion(v string) error {
	// Strip surrounding quotes if present (pnpm 9 writes lockfileVersion: '9.0').
	v = strings.Trim(v, "'\"")
	if v == "" {
		return fmt.Errorf("pnpm-lock.yaml is missing lockfileVersion; run 'pnpm install --lockfile-only' to regenerate")
	}
	major, _, _ := strings.Cut(v, ".")
	majorNum, err := strconv.Atoi(major)
	if err != nil {
		return fmt.Errorf("pnpm-lock.yaml has an unrecognized lockfileVersion %q; run 'pnpm install --lockfile-only' to regenerate", v)
	}
	if majorNum < 9 {
		return fmt.Errorf("pnpm-lock.yaml lockfileVersion %q is not supported (only 9.0 and later, written by pnpm 9/10, are parseable); run 'pnpm install --lockfile-only' with pnpm %d to regenerate", v, supportedPnpmMajorVersion)
	}
	return nil
}
