package githubactions

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	pullHead  = "8ec026fcc56986f3aa17d1decdc76eb1da691aad"
	pullMerge = "364faa99ef5c9a25c95660f1b2f07f3843638e05"
	// c15aeb3Tip is the tip of the branch literally named "c15aeb3" (probe-sha-branch).
	c15aeb3Tip = "0d516460167e6ef8683b219cab58dee8317aa7c2"
)

// testAdvertisement mirrors the measured shapes: a lightweight tag, slashed branches, the
// tag/branch collision from probe-tag-branch-collision, a branch named like a short SHA, and
// pull refs.
func testAdvertisement() *RefAdvertisement {
	return &RefAdvertisement{
		ObjectFormat: "sha1",
		Refs: map[string]string{
			"refs/tags/v4":                          "11d5960a326750d5838078e36cf38b85af677262",
			"refs/heads/main":                       branchTip,
			"refs/heads/feature/x":                  branchTip,
			"refs/heads/releases/v3":                "a37ce9120846195fa4ece8f58b268e6043cb2f26",
			"refs/heads/releases/v4":                "11d5960a326750d5838078e36cf38b85af677262",
			"refs/heads/Feature/X":                  tagCommit,
			"refs/tags/collision":                   tagObject,
			"refs/heads/collision":                  branchTip,
			"refs/heads/c15aeb3":                    c15aeb3Tip,
			"refs/heads/" + strings.Repeat("a", 39): branchTip,
			"refs/pull/2264/head":                   pullHead,
			"refs/pull/2264/merge":                  pullMerge,
		},
		Peeled: map[string]string{"refs/tags/collision": tagCommit},
	}
}

func TestClassifyRef(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want ResolvedRef
	}{
		{name: "verify when a bare name is a tag then it downloads by tag", ref: "v4", want: ResolvedRef{Kind: RefKindTag, APIRef: "v4"}},
		{name: "verify when a bare name is a branch then it downloads by branch", ref: "main", want: ResolvedRef{Kind: RefKindBranch, APIRef: "main"}},
		{name: "verify when a bare branch name has a slash then the slash is kept", ref: "feature/x", want: ResolvedRef{Kind: RefKindBranch, APIRef: "feature/x"}},
		{name: "verify when a bare name reads like a release but is a branch then it downloads by branch", ref: "releases/v4", want: ResolvedRef{Kind: RefKindBranch, APIRef: "releases/v4"}},
		{name: "verify when a tag is fully qualified then the prefix is stripped", ref: "refs/tags/v4", want: ResolvedRef{Kind: RefKindTag, APIRef: "v4"}},
		{name: "verify when a branch is fully qualified then the prefix is stripped", ref: "refs/heads/main", want: ResolvedRef{Kind: RefKindBranch, APIRef: "main"}},
		{name: "verify when a slashed branch is fully qualified then only the prefix is stripped", ref: "refs/heads/releases/v3", want: ResolvedRef{Kind: RefKindBranch, APIRef: "releases/v3"}},
		{name: "verify when a bare name is both a tag and a branch then the tag wins", ref: "collision", want: ResolvedRef{Kind: RefKindTag, APIRef: "collision"}},
		{name: "verify when a fully-qualified tag collides with a branch then it downloads by tag", ref: "refs/tags/collision", want: ResolvedRef{Kind: RefKindTag, APIRef: "collision"}},
		{name: "verify when a fully-qualified branch collides with a tag then it downloads the branch tip commit", ref: "refs/heads/collision", want: ResolvedRef{Kind: RefKindCommit, APIRef: branchTip}},
		{name: "verify when a pull head ref is used then it downloads the commit it points at", ref: "refs/pull/2264/head", want: ResolvedRef{Kind: RefKindCommit, APIRef: pullHead}},
		{name: "verify when a pull merge ref is used then it downloads its own distinct commit", ref: "refs/pull/2264/merge", want: ResolvedRef{Kind: RefKindCommit, APIRef: pullMerge}},
		{name: "verify when a ref is a full 40-hex ID then it downloads by commit", ref: branchTip, want: ResolvedRef{Kind: RefKindCommit, APIRef: branchTip}},
		{name: "verify when a ref is a mixed-case 40-hex ID then it is lower-cased", ref: strings.ToUpper(branchTip), want: ResolvedRef{Kind: RefKindCommit, APIRef: branchTip}},
		{name: "verify when a ref is a 64-hex ID then it downloads by commit", ref: sha256Object, want: ResolvedRef{Kind: RefKindCommit, APIRef: sha256Object}},
		{name: "verify when a ref is an annotated tag object ID then it is passed through unpeeled", ref: tagObject, want: ResolvedRef{Kind: RefKindCommit, APIRef: tagObject}},
		{name: "verify when a 7-hex string is a real branch name then it downloads by branch", ref: "c15aeb3", want: ResolvedRef{Kind: RefKindBranch, APIRef: "c15aeb3"}},
		{name: "verify when a 39-hex string is a real branch name then it downloads by branch", ref: strings.Repeat("a", 39), want: ResolvedRef{Kind: RefKindBranch, APIRef: strings.Repeat("a", 39)}},
		{name: "verify when a branch name is mixed case then its casing is kept", ref: "Feature/X", want: ResolvedRef{Kind: RefKindBranch, APIRef: "Feature/X"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ClassifyRef(tt.ref, testAdvertisement())

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.False(t, strings.HasPrefix(got.APIRef, refsPrefix), "ClassifyRef(%q).APIRef = %q carries a refs/ prefix", tt.ref, got.APIRef)
		})
	}
}

func TestClassifyRefErrors(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		adv  *RefAdvertisement
	}{
		{name: "verify when a bare name is neither a tag nor a branch then it errors", ref: "no-such-ref", adv: testAdvertisement()},
		{name: "verify when a fully-qualified tag is not advertised then it errors", ref: "refs/tags/v99", adv: testAdvertisement()},
		{name: "verify when a fully-qualified branch is not advertised then it errors", ref: "refs/heads/gone", adv: testAdvertisement()},
		{name: "verify when a pull ref is not advertised then it errors", ref: "refs/pull/1/head", adv: testAdvertisement()},
		{name: "verify when a branch name matches in another case only then it errors", ref: "MAIN", adv: testAdvertisement()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ClassifyRef(tt.ref, tt.adv)

			assert.True(t, errors.Is(err, ErrRefNotAdvertised), "ClassifyRef(%q) error = %v, want ErrRefNotAdvertised", tt.ref, err)
		})
	}
}

func TestClassifyRefWithoutAdvertisement(t *testing.T) {
	t.Run("verify when a full object ID is classified then no advertisement is needed", func(t *testing.T) {
		got, err := ClassifyRef(branchTip, nil)

		require.NoError(t, err)
		assert.Equal(t, ResolvedRef{Kind: RefKindCommit, APIRef: branchTip}, got)
	})
	t.Run("verify when a name is classified without an advertisement then it errors", func(t *testing.T) {
		_, err := ClassifyRef("main", nil)

		assert.Error(t, err)
	})
}

func TestNeedsRefs(t *testing.T) {
	tests := []struct {
		ref  string
		want bool
	}{
		{ref: branchTip, want: false},
		{ref: strings.ToUpper(branchTip), want: false},
		{ref: sha256Object, want: false},
		{ref: "v4", want: true},
		{ref: "refs/heads/main", want: true},
		{ref: "c15aeb3", want: true},
		{ref: strings.Repeat("a", 39), want: true},
		{ref: strings.Repeat("a", 41), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			assert.Equal(t, tt.want, NeedsRefs(tt.ref), "NeedsRefs(%q)", tt.ref)
		})
	}
}
