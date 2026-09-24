package githubactions

import "strings"

// archiveExtensions are the download APIs' archive formats, longest first so ".tar.gz" is not
// mistaken for ".gz".
var archiveExtensions = []string{".tar.gz", ".tgz", ".zip", ".tar"}

// ExtractResolvedSHA returns the object ID Artifactory resolved a download to, taken from the
// archive filename it reports in X-Artifactory-Filename, or "" when the name carries none.
//
// The SHA is read from the filename rather than the archive, because only the filename has it:
// a branch archive's top-level directory is "<repo>-<branch>" with no SHA, and a tag's has GitHub's
// leading "v" stripped. The filename's shape varies - "<repo>-<sha>" for a commit,
// "<repo>-<branch>-<sha>" for a branch, "<lastSegment>-<sha>" for a slashed branch, where the repo
// is dropped - so the SHA is recognized by being a trailing 40- or 64-hex segment, not by
// position. Tags carry no SHA yet ("<repo>-<tag>"); one appears here without a code change once
// Artifactory adds it.
//
// Best-effort by design: a missing or unexpected name costs the report its SHA note, never the
// curation, since the action's content was already replaced.
func ExtractResolvedSHA(filename string) string {
	stem := filename
	for _, ext := range archiveExtensions {
		if trimmed, ok := strings.CutSuffix(stem, ext); ok {
			stem = trimmed
			break
		}
	}
	idx := strings.LastIndexByte(stem, '-')
	if idx < 0 {
		return ""
	}
	if sha := stem[idx+1:]; isFullObjectID(sha) {
		return strings.ToLower(sha)
	}
	return ""
}
