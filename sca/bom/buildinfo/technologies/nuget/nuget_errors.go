package nuget

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

// nugetErrorLinePattern matches "<path>.<cs|fs|vb>proj : error NU<NNNN>: <msg>".
// Path is non-greedy so Windows drive-letter colons are handled.
var nugetErrorLinePattern = regexp.MustCompile(`(?m)^(.+?\.(?:cs|fs|vb)proj)\s*:\s*error\s+(NU\d{4})\s*:\s*(.*?)\s*$`)

// cpmMismatchCodes are NuGet codes signalling a Central Package Management
// mismatch (PackageReference without matching PackageVersion). NU1010 is the
// general case; NU1008 fires when every reference in a project is missing one.
var cpmMismatchCodes = map[string]bool{
	"NU1010": true,
	"NU1008": true,
}

type nugetErrorEntry struct {
	csproj  string
	code    string
	message string
}

// parseNugetErrors extracts per-project NuGet error entries from raw restore output.
func parseNugetErrors(output string) []nugetErrorEntry {
	matches := nugetErrorLinePattern.FindAllStringSubmatch(output, -1)
	entries := make([]nugetErrorEntry, 0, len(matches))
	for _, m := range matches {
		entries = append(entries, nugetErrorEntry{
			csproj:  m[1],
			code:    m[2],
			message: strings.TrimSpace(m[3]),
		})
	}
	return entries
}

// extractCPMMismatchPackages returns the package names embedded in a CPM
// mismatch message. Recognised templates (returns nil if none match):
//
//	.NET 10 NU1010 — "...PackageVersion item: A, B, C. Projects using..."
//	.NET 6-9 NU1008 — "...PackageVersion items: A;B;C."
//	.NET 6-8 NU1010 — "The PackageReference items A;B;C do not have..."
func extractCPMMismatchPackages(message string) []string {
	if idx := strings.Index(message, "PackageVersion item:"); idx >= 0 {
		return splitPackageNames(trimToFirstSentence(message[idx+len("PackageVersion item:"):]))
	}
	if idx := strings.Index(message, "PackageVersion items:"); idx >= 0 {
		return splitPackageNames(trimToFirstSentence(message[idx+len("PackageVersion items:"):]))
	}
	if start := strings.Index(message, "PackageReference items "); start >= 0 {
		tail := message[start+len("PackageReference items "):]
		if end := strings.Index(tail, " do not have"); end > 0 {
			return splitPackageNames(tail[:end])
		}
	}
	return nil
}

// splitPackageNames splits a comma- or semicolon-separated list (NuGet IDs
// can't contain either) and trims whitespace; empty entries are dropped.
func splitPackageNames(s string) []string {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// trimToFirstSentence returns s up to the first ". " (sentence boundary),
// trimming any trailing "." otherwise. Isolates the name list from prose tails.
func trimToFirstSentence(s string) string {
	if i := strings.Index(s, ". "); i >= 0 {
		return s[:i]
	}
	return strings.TrimSuffix(strings.TrimSpace(s), ".")
}

// formatCPMMismatchError renders the friendly per-package error.
// packages must be non-empty; caller deduplicates.
func formatCPMMismatchError(packages []string) error {
	sort.Strings(packages)
	var b strings.Builder
	b.WriteString("Central Package Management mismatch:\n")
	if len(packages) == 1 {
		fmt.Fprintf(&b,
			"PackageReference '%s' does not have a corresponding PackageVersion entry. "+
				"Ensure '%s' is defined in Directory.Packages.props, then try again.",
			packages[0], packages[0])
	} else {
		quoted := make([]string, len(packages))
		for i, p := range packages {
			quoted[i] = "'" + p + "'"
		}
		fmt.Fprintf(&b,
			"PackageReferences %s do not have corresponding PackageVersion entries. "+
				"Ensure they are defined in Directory.Packages.props, then try again.",
			strings.Join(quoted, ", "))
	}
	return errorutils.CheckErrorf("%s", b.String())
}

// formatGenericCPMMismatchError is the safety-net used when a CPM code is
// seen but no package names could be extracted (unknown wording, localised
// output). The actionable advice is the same; only per-package detail is dropped.
func formatGenericCPMMismatchError() error {
	const msg = "Central Package Management mismatch:\n" +
		"One or more PackageReferences in this solution do not have corresponding PackageVersion entries. " +
		"Ensure every PackageReference is declared in Directory.Packages.props with a matching <PackageVersion> entry, then try again."
	return errorutils.CheckErrorf("%s", msg)
}

// translateRestoreError maps raw `dotnet restore` output to an actionable error:
//  1. CPM code + extractable names → friendly per-package message.
//  2. CPM code only (unknown/localised wording) → generic CPM message.
//  3. anything else → original verbose `'dotnet restore' command failed: ...`.
//
// tmpWd is currently used only for debug logging context; kept for future
// translators that may need to rewrite paths.
func translateRestoreError(output []byte, restoreErr error, tmpWd string) error {
	_ = tmpWd

	entries := parseNugetErrors(string(output))
	pkgSet := datastructures.MakeSet[string]()
	sawCPMCode := false
	for _, e := range entries {
		if !cpmMismatchCodes[e.code] {
			continue
		}
		sawCPMCode = true
		for _, pkg := range extractCPMMismatchPackages(e.message) {
			pkgSet.Add(pkg)
		}
	}

	if pkgSet.Size() > 0 {
		log.Debug(fmt.Sprintf("Raw 'dotnet restore' output:\n%s", output))
		return formatCPMMismatchError(pkgSet.ToSlice())
	}
	if sawCPMCode {
		log.Debug(fmt.Sprintf("Raw 'dotnet restore' output:\n%s", output))
		return formatGenericCPMMismatchError()
	}
	return errorutils.CheckErrorf("'dotnet restore' command failed: %s - %s", restoreErr.Error(), output)
}
