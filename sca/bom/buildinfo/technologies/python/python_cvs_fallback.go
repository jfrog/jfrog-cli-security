package python

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/jfrog/gofrog/version"
)

// PinnedRequirement is a blocker extracted from pip, poetry, or uv failure output.
type PinnedRequirement struct {
	Name          string
	Version       string
	VersionRange  string
	ParentName    string
	ParentVersion string
}

// CvsBlockedError is returned when CVS hides a pinned version from the simple index.
// Packages lists the blockers so the curation-audit command can recover policy details via the metadata-API fallback.
type CvsBlockedError struct {
	Packages []PinnedRequirement
	Cause    error
}

func (e *CvsBlockedError) Error() string {
	return errors.Join(e.Cause, errors.New(formatCvsBlockedRequirementsMessage(e.Packages))).Error()
}

func (e *CvsBlockedError) Unwrap() error { return e.Cause }

// pipFailedPinnedReqRegex matches exact == pins in pip's error output.
// Groups: (1) name, (2) version.
var pipFailedPinnedReqRegex = regexp.MustCompile(
	`(?:No matching distribution found for|satisfies the requirement)\s+` +
		`([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s(,;]+)`)

// pipFailedRangeReqRegex matches range-based failures in pip's error output.
// Groups: (1) name, (2) range-spec, (3) parent-name (optional), (4) parent-version (optional).
var pipFailedRangeReqRegex = regexp.MustCompile(
	`(?:No matching distribution found for|satisfies the requirement)\s+` +
		`([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?((?:(?:~=|!=|>=|<=|>|<)[^\s,(]+(?:,(?:~=|!=|>=|<=|>|<)[^\s,(]+)*))` +
		`(?:\s+\(from\s+([A-Za-z0-9][A-Za-z0-9._-]*)(?:==([^\s)]+))?\))?`)

// pipCollectingRegex matches packages pip collected before failing; used to recover parent version omitted in "(from <parent>)".
// Groups: (1) name, (2) version.
var pipCollectingRegex = regexp.MustCompile(
	`Collecting\s+([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s(,;]+)`)

// pipResolutionImpossibleRegex matches the indented package list in a ResolutionImpossible error; stops at the first blank line.
// Group: (1) block of indented package lines.
var pipResolutionImpossibleRegex = regexp.MustCompile(
	`no matching distributions available for your environment:\r?\n((?:[ \t]+[A-Za-z0-9][A-Za-z0-9._-]*[ \t]*\r?\n)+)`)

// pipDirectFromRequirementsRegex matches a top-level dep from requirements.txt; used to attribute a ResolutionImpossible blocker to the direct dep.
// Groups: (1) name, (2) version.
var pipDirectFromRequirementsRegex = regexp.MustCompile(
	`Collecting\s+([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s(,;]+)\s+\(from\s+-r\s`)

// poetryCvsBlockedReqRegex extracts a pinned `name (version)` from poetry's
// "X (Y) which doesn't match any versions" error lines. Both `name (X.Y.Z)`
// and `name (==X.Y.Z)` notations are accepted.
var poetryCvsBlockedReqRegex = regexp.MustCompile(
	`([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s+\((?:==)?\s*([0-9][0-9A-Za-z._+\-]*)\)\s+which doesn't match any versions`)

// poetryCvsBlockedRangeRegex extracts a range-constrained blocker (e.g.
// "langchain-core (>=1.4.0,<2.0.0) which doesn't match any versions"), the form
// poetry uses for a transitive dependency's constraint rather than an exact pin.
var poetryCvsBlockedRangeRegex = regexp.MustCompile(
	`([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s+\(([~^!]?[<>=][^)]+)\)\s+which doesn't match any versions`)

// poetryDependsOnParentRegex extracts "parent (parentVersion) depends on
// name (...)" clauses from poetry's derivation chain, to recover the real
// parent of a transitively CVS-stripped package. Keyed by child name only,
// since poetry may restate the constraint slightly differently between clauses.
var poetryDependsOnParentRegex = regexp.MustCompile(
	`([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s+\(([0-9][0-9A-Za-z._+\-]*)\)\s+depends on\s+` +
		`([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s+\([^)]+\)`)

// uvCvsBlockedReqRegex extracts a pinned name==version from uv's
// "there is no version of name==version" error line, emitted when CVS has
// stripped the release from Artifactory's simple index.
var uvCvsBlockedReqRegex = regexp.MustCompile(
	`there is no version of ([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([0-9][0-9A-Za-z._+\-]*)`)

// uvNotFoundInRegistryRegex extracts the package name from uv's
// "<name> was not found in the package registry" error line, emitted when CVS
// has stripped all versions of a package so that the package entry itself is absent.
var uvNotFoundInRegistryRegex = regexp.MustCompile(
	`([A-Za-z0-9][A-Za-z0-9._-]*) was not found in the package registry`)

// uvDependsOnPinnedRegex extracts name==version from uv's "depends on name==version" clause,
// used to recover the pinned version when paired with uvNotFoundInRegistryRegex.
var uvDependsOnPinnedRegex = regexp.MustCompile(
	`depends on ([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([0-9][0-9A-Za-z._+\-]*)`)

// uvDependsOnParentRegex extracts "parent==parentVersion depends on name==version"
// clauses from uv's derivation chain, to recover the real parent of a transitively
// CVS-stripped package (e.g. "deepagents==0.6.12 depends on langchain-core==1.4.7").
// Doesn't match "your project depends on ..." (no version), leaving direct-dependency
// attribution to the caller.
var uvDependsOnParentRegex = regexp.MustCompile(
	`([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([0-9][0-9A-Za-z._+\-]*)\s+depends on\s+` +
		`([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([0-9][0-9A-Za-z._+\-]*)`)

// parseCvsFailedPackages extracts blockers from pip, poetry, and uv failure output.
// Only packages that caused the failure are returned, not every requirements entry.
func parseCvsFailedPackages(pipOutput string) []PinnedRequirement {
	seen := map[string]bool{}
	var failed []PinnedRequirement

	// collected versions: recover parent version when pip omits it in "(from X)".
	collected := map[string]string{}
	for _, m := range pipCollectingRegex.FindAllStringSubmatch(pipOutput, -1) {
		collected[normalizePyPIName(m[1])] = strings.TrimRight(m[2], ")")
	}

	// Exact pins first.
	for _, m := range pipFailedPinnedReqRegex.FindAllStringSubmatch(pipOutput, -1) {
		name := normalizePyPIName(m[1])
		ver := strings.TrimRight(m[2], ")")
		key := name + "==" + ver
		if !seen[key] {
			seen[key] = true
			failed = append(failed, PinnedRequirement{
				Name:          name,
				Version:       ver,
				ParentName:    name,
				ParentVersion: ver,
			})
		}
	}

	// Range specs (transitive or ranged direct deps).
	for _, m := range pipFailedRangeReqRegex.FindAllStringSubmatch(pipOutput, -1) {
		name := normalizePyPIName(m[1])
		rangeSpec := m[2]
		key := name + rangeSpec
		if seen[key] {
			continue
		}
		seen[key] = true
		pr := PinnedRequirement{
			Name:         name,
			VersionRange: rangeSpec,
		}
		if m[3] != "" {
			pr.ParentName = normalizePyPIName(m[3])
			pr.ParentVersion = m[4]
			// pip omitted parent version in "(from X)" — recover from its Collecting line.
			if pr.ParentVersion == "" {
				pr.ParentVersion = collected[pr.ParentName]
			}
		} else {
			// No "(from X)" captured — treat as direct dep; parent resolved later.
			pr.ParentName = name
		}
		failed = append(failed, pr)
	}

	// ResolutionImpossible: deep transitive deps stripped by CVS never appear in a
	// "No matching distribution found" line, so add them as name-only entries.
	if m := pipResolutionImpossibleRegex.FindStringSubmatch(pipOutput); len(m) > 1 {
		// Attribute to the single direct dep from requirements.txt when unambiguous;
		// with multiple direct deps the attribution is unclear so leave self-attributed.
		var directName, directVer string
		if dm := pipDirectFromRequirementsRegex.FindAllStringSubmatch(pipOutput, -1); len(dm) == 1 {
			directName = normalizePyPIName(dm[0][1])
			directVer = strings.TrimRight(dm[0][2], ")")
		}
		for _, raw := range strings.Fields(m[1]) {
			name := normalizePyPIName(strings.TrimSpace(raw))
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			pr := PinnedRequirement{Name: name, ParentName: name}
			if directName != "" && directName != name {
				pr.ParentName = directName
				pr.ParentVersion = directVer
			}
			failed = append(failed, pr)
		}
	}

	// Poetry: recover the real parent from "parent (v) depends on name (...)" clauses.
	// Falls back to self-attribution when none found (a direct dependency).
	poetryParentByChild := map[string]PinnedRequirement{}
	for _, m := range poetryDependsOnParentRegex.FindAllStringSubmatch(pipOutput, -1) {
		n := normalizePyPIName(m[3])
		if _, already := poetryParentByChild[n]; !already {
			poetryParentByChild[n] = PinnedRequirement{Name: normalizePyPIName(m[1]), Version: m[2]}
		}
	}

	// Poetry: "name (version) which doesn't match any versions" — exact pin.
	for _, m := range poetryCvsBlockedReqRegex.FindAllStringSubmatch(pipOutput, -1) {
		name := normalizePyPIName(m[1])
		ver := strings.TrimRight(m[2], ")")
		key := name + "==" + ver
		if !seen[key] {
			seen[key] = true
			pr := PinnedRequirement{Name: name, Version: ver, ParentName: name, ParentVersion: ver}
			if parent, ok := poetryParentByChild[name]; ok {
				pr.ParentName, pr.ParentVersion = parent.Name, parent.Version
			}
			failed = append(failed, pr)
		}
	}

	// Poetry: "name (range) which doesn't match any versions" — a transitive
	// dependency's constraint, attributed to its real parent when recoverable.
	for _, m := range poetryCvsBlockedRangeRegex.FindAllStringSubmatch(pipOutput, -1) {
		name := normalizePyPIName(m[1])
		rangeSpec := strings.TrimSpace(m[2])
		key := name + rangeSpec
		if seen[key] {
			continue
		}
		seen[key] = true
		pr := PinnedRequirement{Name: name, VersionRange: rangeSpec, ParentName: name}
		if parent, ok := poetryParentByChild[name]; ok {
			pr.ParentName, pr.ParentVersion = parent.Name, parent.Version
		}
		failed = append(failed, pr)
	}

	// uv: recover the real parent from "parent==v depends on name==v" clauses.
	// Order-independent — uv's derivation chain doesn't guarantee this appears
	// before or after the "no version of" / "was not found" clause it pairs with.
	uvParentByChild := map[string]PinnedRequirement{}
	for _, m := range uvDependsOnParentRegex.FindAllStringSubmatch(pipOutput, -1) {
		childKey := normalizePyPIName(m[3]) + "==" + m[4]
		if _, already := uvParentByChild[childKey]; !already {
			uvParentByChild[childKey] = PinnedRequirement{Name: normalizePyPIName(m[1]), Version: m[2]}
		}
	}

	// uv: "there is no version of name==version" (CVS stripped the release from the simple index)
	for _, m := range uvCvsBlockedReqRegex.FindAllStringSubmatch(pipOutput, -1) {
		name := normalizePyPIName(m[1])
		ver := m[2]
		key := name + "==" + ver
		if !seen[key] {
			seen[key] = true
			pr := PinnedRequirement{Name: name, Version: ver, ParentName: name, ParentVersion: ver}
			if parent, ok := uvParentByChild[key]; ok {
				pr.ParentName, pr.ParentVersion = parent.Name, parent.Version
			}
			failed = append(failed, pr)
		}
	}

	// uv: "<name> was not found in the package registry" — CVS stripped all versions so the
	// package entry itself is absent. Recover the pinned version from the adjacent
	// "depends on <name>==<version>" clause in the same error message.
	dependsOnByName := map[string]string{}
	for _, m := range uvDependsOnPinnedRegex.FindAllStringSubmatch(pipOutput, -1) {
		n := normalizePyPIName(m[1])
		if _, already := dependsOnByName[n]; !already {
			dependsOnByName[n] = m[2]
		}
	}
	for _, m := range uvNotFoundInRegistryRegex.FindAllStringSubmatch(pipOutput, -1) {
		name := normalizePyPIName(m[1])
		ver := dependsOnByName[name]
		key := name + "==" + ver
		if !seen[key] {
			seen[key] = true
			pr := PinnedRequirement{Name: name, Version: ver, ParentName: name, ParentVersion: ver}
			if parent, ok := uvParentByChild[key]; ok {
				pr.ParentName, pr.ParentVersion = parent.Name, parent.Version
			}
			failed = append(failed, pr)
		}
	}

	return failed
}

var pypiNameNormalizeRegex = regexp.MustCompile(`[-_.]+`)

func normalizePyPIName(name string) string {
	return strings.ToLower(pypiNameNormalizeRegex.ReplaceAllString(name, "-"))
}

func formatCvsBlockedRequirementsMessage(pins []PinnedRequirement) string {
	var b strings.Builder
	b.WriteString("Curation audit failed: one or more pinned package versions were unavailable during dependency resolution, so the corresponding curation policy violations could not be evaluated.")
	if len(pins) > 0 {
		b.WriteString("\n\nAffected package(s):\n")
		for _, p := range pins {
			switch {
			case p.VersionRange != "":
				fmt.Fprintf(&b, " - %s%s\n", p.Name, p.VersionRange)
			case p.Version != "":
				fmt.Fprintf(&b, " - %s==%s\n", p.Name, p.Version)
			default:
				fmt.Fprintf(&b, " - %s (version unknown)\n", p.Name)
			}
		}
	}
	return b.String()
}

func isCvsVersionFilteredOutput(output string) bool {
	return strings.Contains(output, "No matching distribution found") ||
		strings.Contains(output, "Could not find a version that satisfies the requirement") ||
		strings.Contains(output, "doesn't match any versions") ||
		// ResolutionImpossible: direct dep resolved but a transitive dep was stripped by CVS.
		(strings.Contains(output, "ResolutionImpossible") &&
			strings.Contains(output, "no matching distributions available for your environment")) ||
		strings.Contains(output, "there is no version of") ||
		strings.Contains(output, "was not found in the package registry")
}

// WrapUvCurationErr checks a failed `uv lock` run's output for a CVS-stripped
// version, wrapping it as a *CvsBlockedError so the caller can recover policy
// details via the metadata-API fallback. A generic download-blocked 403 (e.g. uv
// fetching a wheel for metadata) is NOT treated as CVS-blocked, matching
// pip/poetry — cause is returned unchanged, leaving the caller to decide how to
// present it (see classifyUvCurationLockError, which falls through to a plain
// "contact admin" message for that case).
func WrapUvCurationErr(combinedOutput string, cause error) error {
	if cause == nil {
		return nil
	}
	if isCvsVersionFilteredOutput(combinedOutput) {
		return &CvsBlockedError{Packages: parseCvsFailedPackages(combinedOutput), Cause: cause}
	}
	return cause
}

// ResolveVersionRange returns the newest version from candidates satisfying rangeSpec.
// Returns "" if no candidate matches.
func ResolveVersionRange(rangeSpec string, candidates []string) string {
	var matching []string
	for _, v := range candidates {
		if versionMatchesRange(v, rangeSpec) {
			matching = append(matching, v)
		}
	}
	if len(matching) == 0 {
		return ""
	}
	slices.SortFunc(matching, func(a, b string) int {
		va := version.NewVersion(a)
		switch {
		case va.Compare(b) < 0:
			return -1
		case va.Compare(b) > 0:
			return 1
		default:
			return 0
		}
	})
	return matching[0]
}

// versionMatchesRange reports whether v satisfies all constraints in rangeSpec.
func versionMatchesRange(v, rangeSpec string) bool {
	ver := version.NewVersion(v)
	for _, part := range strings.Split(rangeSpec, ",") {
		if !versionMatchesConstraint(ver, strings.TrimSpace(part)) {
			return false
		}
	}
	return true
}

// versionMatchesConstraint reports whether v satisfies a single PEP 440 specifier.
func versionMatchesConstraint(ver *version.Version, constraint string) bool {
	for _, op := range []string{"~=", "!=", ">=", "<=", ">", "<", "=="} {
		if !strings.HasPrefix(constraint, op) {
			continue
		}
		c := constraint[len(op):]
		switch op {
		case ">=":
			return ver.Compare(c) <= 0
		case ">":
			return ver.Compare(c) < 0
		case "<=":
			return ver.Compare(c) >= 0
		case "<":
			return ver.Compare(c) > 0
		case "==":
			return ver.Compare(c) == 0
		case "!=":
			return ver.Compare(c) != 0
		case "~=":
			// PEP 440: ~= X.Y means >= X.Y AND < (X+1).0; ~= X.Y.Z means >= X.Y.Z AND < X.(Y+1).0
			if !ver.AtLeast(c) {
				return false
			}
			parts := strings.Split(c, ".")
			if len(parts) < 2 {
				return false
			}
			upperParts := make([]string, len(parts)-1)
			copy(upperParts, parts[:len(parts)-1])
			last, err := strconv.Atoi(upperParts[len(upperParts)-1])
			if err != nil {
				return false
			}
			upperParts[len(upperParts)-1] = strconv.Itoa(last + 1)
			upper := strings.Join(upperParts, ".") + ".0"
			return !ver.AtLeast(upper)
		}
	}
	return false
}
