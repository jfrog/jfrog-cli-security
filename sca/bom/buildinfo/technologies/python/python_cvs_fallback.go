package python

import (
	"fmt"
	"regexp"
	"strings"
)

type pinnedRequirement struct {
	Name    string
	Version string
}

// pipFailedPinnedReqRegex extracts a pinned name==version from pip's "No
// matching distribution found for X==Y" and "satisfies the requirement X==Y"
// error lines. Only exact == pins are captured; range specifiers are skipped
// because they represent transitive constraints, not the user's direct pin.
var pipFailedPinnedReqRegex = regexp.MustCompile(
	`(?:No matching distribution found for|satisfies the requirement)\s+` +
		`([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s(,;]+)`)

// parseCvsFailedPackages extracts the pinned packages that pip explicitly
// reported as unresolvable from pip's error output. This ensures only the
// packages that actually caused the failure are listed, not every pin in the
// requirements file.
func parseCvsFailedPackages(pipOutput string) []pinnedRequirement {
	var failed []pinnedRequirement
	seen := map[string]bool{}
	for _, m := range pipFailedPinnedReqRegex.FindAllStringSubmatch(pipOutput, -1) {
		name := normalizePyPIName(m[1])
		version := strings.TrimRight(m[2], ")")
		key := name + "==" + version
		if !seen[key] {
			seen[key] = true
			failed = append(failed, pinnedRequirement{Name: name, Version: version})
		}
	}
	return failed
}

var pypiNameNormalizeRegex = regexp.MustCompile(`[-_.]+`)

func normalizePyPIName(name string) string {
	return strings.ToLower(pypiNameNormalizeRegex.ReplaceAllString(name, "-"))
}

func formatCvsBlockedRequirementsMessage(pins []pinnedRequirement) string {
	var b strings.Builder
	b.WriteString("Curation audit failed: one or more pinned package versions were unavailable during dependency resolution, so the corresponding curation policy violations could not be evaluated.")
	if len(pins) > 0 {
		b.WriteString("\n\nAffected package(s):\n")
		for _, p := range pins {
			fmt.Fprintf(&b, " - %s==%s\n", p.Name, p.Version)
		}
	}
	return b.String()
}

func isCvsVersionFilteredOutput(output string) bool {
	return strings.Contains(output, "No matching distribution found") ||
		strings.Contains(output, "Could not find a version that satisfies the requirement")
}
