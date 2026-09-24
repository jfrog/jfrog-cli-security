package githubactions

import (
	"errors"
	"fmt"
	"strings"
)

// RefKind is which Artifactory VCS download API serves a ref.
type RefKind int

const (
	RefKindTag RefKind = iota + 1
	RefKindBranch
	RefKindCommit
)

func (k RefKind) String() string {
	switch k {
	case RefKindTag:
		return "tag"
	case RefKindBranch:
		return "branch"
	case RefKindCommit:
		return "commit"
	}
	return fmt.Sprintf("RefKind(%d)", int(k))
}

// ResolvedRef is a ref classified for download: which API to call, and what to put in its path.
type ResolvedRef struct {
	Kind RefKind
	// APIRef is the download API's path argument: a short tag or branch name, never carrying a
	// refs/ prefix, or a lowercase object ID.
	APIRef string
}

// NeedsRefs reports whether ClassifyRef needs the repository's ref advertisement for ref. Only a
// full object ID does not: GitHub refuses a 40- or 64-hex string as a branch or tag name, so such
// a ref can only be an object ID, and there is no name to look up.
func NeedsRefs(ref string) bool {
	return !isFullObjectID(ref)
}

// ClassifyRef decides how to download ref - the literal ref a workflow pinned an action to, as
// the runner named its cache directory - so that Artifactory serves the tree the runner ran.
//
// refAdv may be nil only when NeedsRefs(ref) is false.
//
// The ref appears in three spellings, each with one use, and they must not be crossed: the
// literal ref names the directory on disk; the fully-qualified refs/... name is the key into
// refAdv, which is the only place a tag and a branch of the same short name can be told apart; and
// the short name goes in the download URL.
//
// Tags are checked before branches for a bare name, matching git and the Actions service.
func ClassifyRef(ref string, refAdv *RefAdvertisement) (ResolvedRef, error) {
	if isFullObjectID(ref) {
		// Hex is case-insensitive, so lower-casing is normalization, not a change of identity. The
		// ID is not peeled: Artifactory's downloadCommit peels an annotated tag object itself.
		return ResolvedRef{Kind: RefKindCommit, APIRef: strings.ToLower(ref)}, nil
	}
	if refAdv == nil {
		return ResolvedRef{}, fmt.Errorf("classifying ref %q needs the repository's git refs", ref)
	}
	if name, ok := strings.CutPrefix(ref, tagsPrefix); ok {
		if _, found := refAdv.Refs[ref]; !found {
			return ResolvedRef{}, errRefNotAdvertised(ref)
		}
		return ResolvedRef{Kind: RefKindTag, APIRef: name}, nil
	}
	if name, ok := strings.CutPrefix(ref, headsPrefix); ok {
		tip, found := refAdv.Refs[ref]
		if !found {
			return ResolvedRef{}, errRefNotAdvertised(ref)
		}
		if _, collides := refAdv.Refs[tagsPrefix+name]; collides {
			// Artifactory fetches a branch from GitHub by its bare name, and GitHub cannot tell a
			// bare name shared by a tag and a branch apart - it answers 300, which downloadBranch
			// surfaces as a 404. Downloading the branch's tip commit sidesteps the ambiguity.
			return ResolvedRef{Kind: RefKindCommit, APIRef: tip}, nil
		}
		return ResolvedRef{Kind: RefKindBranch, APIRef: name}, nil
	}
	if strings.HasPrefix(ref, refsPrefix) {
		// refs/pull/<n>/head and /merge, or any other namespace: there is no download API by
		// name for these, so download the commit the ref points at.
		oid, found := refAdv.Refs[ref]
		if !found {
			return ResolvedRef{}, errRefNotAdvertised(ref)
		}
		return ResolvedRef{Kind: RefKindCommit, APIRef: oid}, nil
	}
	if _, isTag := refAdv.Refs[tagsPrefix+ref]; isTag {
		return ResolvedRef{Kind: RefKindTag, APIRef: ref}, nil
	}
	if _, isBranch := refAdv.Refs[headsPrefix+ref]; isBranch {
		return ResolvedRef{Kind: RefKindBranch, APIRef: ref}, nil
	}
	return ResolvedRef{}, errRefNotAdvertised(ref)
}

// ErrRefNotAdvertised is wrapped when a ref names nothing in the repository's advertisement. The
// runner has already resolved every ref in its cache, so this means the ref moved or was deleted
// after the job started.
var ErrRefNotAdvertised = errors.New("ref is not advertised by the repository")

func errRefNotAdvertised(ref string) error {
	return fmt.Errorf("%w: %q", ErrRefNotAdvertised, ref)
}

// isFullObjectID reports whether s is exactly 40 or 64 hex characters.
func isFullObjectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	return isLowerHex(strings.ToLower(s))
}
