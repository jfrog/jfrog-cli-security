package pnpm

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Minimum supported pnpm lockfile version. Versions below this use a different
// format (flat packages map with no snapshots block) that we do not support.
const minSupportedLockfileVersion = "6.0"

// pnpmLockFile is the top-level structure of pnpm-lock.yaml.
type pnpmLockFile struct {
	LockfileVersion string                         `yaml:"lockfileVersion"`
	Importers       map[string]pnpmLockImporter    `yaml:"importers"`
	Snapshots       map[string]pnpmLockSnapshot    `yaml:"snapshots"`
}

// pnpmLockImporter represents a workspace member (or the root project at ".").
type pnpmLockImporter struct {
	Dependencies    map[string]pnpmLockDep `yaml:"dependencies"`
	DevDependencies map[string]pnpmLockDep `yaml:"devDependencies"`
}

// pnpmLockDep holds the resolved version for a direct dependency.
type pnpmLockDep struct {
	Version string `yaml:"version"`
}

// pnpmLockSnapshot is one entry in the snapshots block.
// The key format is "<name>@<version>(<peer1>@<v>)(<peer2>@<v>)..." but we
// strip the peer suffix when building Xray dependency IDs.
type pnpmLockSnapshot struct {
	// Dependencies are keyed by bare package name; values are either a plain
	// version string or a version+peer-suffix string (e.g. "3.0.5(@foo/bar@1.2)").
	Dependencies map[string]string `yaml:"dependencies"`
}

// parsePnpmLockFile reads workingDir/pnpm-lock.yaml and converts it into the
// same []pnpmLsProject shape that the old `pnpm ls --json` path produced.
// The name and version for each importer entry are taken from
// workingDir/<importerPath>/package.json when available; importer paths other
// than "." are treated as workspace members.
func parsePnpmLockFile(workingDir string) ([]pnpmLsProject, error) {
	lockPath := workingDir + "/pnpm-lock.yaml"
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

	// Root-only project (no importers block) — treat the whole file as a single importer.
	if len(lf.Importers) == 0 {
		return nil, fmt.Errorf("pnpm-lock.yaml has no importers block; run 'pnpm install --lockfile-only' first")
	}

	var projects []pnpmLsProject
	for importerPath, importer := range lf.Importers {
		name, version := readPackageNameVersion(workingDir, importerPath)
		project := pnpmLsProject{
			Name:    name,
			Version: version,
		}

		visited := map[string]bool{}
		project.Dependencies = buildDepsMap(importer.Dependencies, lf.Snapshots, visited)
		project.DevDependencies = buildDepsMap(importer.DevDependencies, lf.Snapshots, visited)
		projects = append(projects, project)
	}
	return projects, nil
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

// splitPnpmRef splits a pnpm lockfile reference into (name, version).
// The reference may be either a snapshot key like "@scope/pkg@2.0.0(@peer@1.0)"
// or a plain version string like "2.0.0(@peer@1.0)".
// In both cases the peer-dep suffix (everything from the first '(' onward) is stripped.
// The split is always on the LAST '@' so scoped names like "@scope/pkg" are handled correctly.
func splitPnpmRef(ref string) (name, version string) {
	// Strip peer-dep suffix.
	if i := strings.IndexByte(ref, '('); i >= 0 {
		ref = ref[:i]
	}
	i := strings.LastIndexByte(ref, '@')
	if i <= 0 {
		// No '@' or starts with '@' but has no version — treat the whole thing as a version.
		return "", ref
	}
	return ref[:i], ref[i+1:]
}

// buildSnapshotKey constructs the key used to look up an entry in the snapshots map.
// pnpm stores snapshots under the full "<name>@<version>(<peers>)" key, so we need
// to combine the package name with its raw (possibly peer-suffixed) version ref.
// For plain version strings (no name in the ref) the name is prepended.
func buildSnapshotKey(name, rawRef string) string {
	// If rawRef already contains an '@' after the first character (i.e. it's a full
	// "<name>@<version>..." key rather than a bare version), use it as-is.
	if strings.Count(rawRef, "@") >= 1 && !strings.HasPrefix(rawRef, "@") {
		return name + "@" + rawRef
	}
	// Scoped packages (@scope/pkg) always start with '@'; their version refs look like
	// "2.0.0" or "2.0.0(@peer@1.0)" — never "<name>@<version>".
	if strings.HasPrefix(rawRef, "@") {
		// rawRef is itself a full scoped key e.g. "@scope/pkg@2.0.0(@peer@1.0)"
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
		dir = workingDir + "/" + importerPath
	}
	data, err := os.ReadFile(dir + "/package.json")
	if err != nil {
		return importerPath, "0.0.0"
	}
	// Minimal JSON extraction — avoid a full unmarshal dependency just for two fields.
	var pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	// Use yaml decoder as a light JSON superset parser (json is valid yaml).
	if err = yaml.Unmarshal(data, &pkg); err != nil || pkg.Name == "" {
		return importerPath, "0.0.0"
	}
	if pkg.Version == "" {
		pkg.Version = "0.0.0"
	}
	return pkg.Name, pkg.Version
}

// validateLockfileVersion rejects lockfile versions older than minSupportedLockfileVersion.
// pnpm v5 used "5.x" and had a different flat format; v6+ uses the current structure.
func validateLockfileVersion(v string) error {
	// Strip surrounding quotes if present (pnpm 9 writes lockfileVersion: '9.0').
	v = strings.Trim(v, "'\"")
	if v == "" {
		return fmt.Errorf("pnpm-lock.yaml is missing lockfileVersion; run 'pnpm install --lockfile-only' to regenerate")
	}
	// Only reject clearly old formats (5.x). Anything >= 6.0 shares the same structure.
	if strings.HasPrefix(v, "5.") {
		return fmt.Errorf("pnpm-lock.yaml lockfileVersion %q requires pnpm v6 or later to parse; please upgrade pnpm and re-run 'pnpm install --lockfile-only'", v)
	}
	return nil
}
