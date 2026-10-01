package githubactions

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractResolvedSHA(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     string
	}{
		// Filenames measured from Artifactory 7.171.1, github-vcs remote, 2026-09-24.
		{name: "verify when a commit archive is named repo-sha then the sha is returned", filename: "checkout-11d5960a326750d5838078e36cf38b85af677262.tar.gz", want: "11d5960a326750d5838078e36cf38b85af677262"},
		{name: "verify when a commit archive echoes an uppercase sha then it is lower-cased", filename: "checkout-11D5960A326750D5838078E36CF38B85AF677262.tar.gz", want: "11d5960a326750d5838078e36cf38b85af677262"},
		{name: "verify when an annotated tag object is downloaded by commit then its id is returned", filename: "checkout-95784fc5bbede4a44d9abcfbde7a64f16e6dbedd.tar.gz", want: "95784fc5bbede4a44d9abcfbde7a64f16e6dbedd"},
		{name: "verify when a branch archive is named repo-branch-sha then the sha is returned", filename: "checkout-main-f548e57e544e1ff5a4c46bf1e1b8685f8e4a348a.tar.gz", want: "f548e57e544e1ff5a4c46bf1e1b8685f8e4a348a"},
		{name: "verify when a branch archive is a zip then the sha is returned", filename: "checkout-main-f548e57e544e1ff5a4c46bf1e1b8685f8e4a348a.zip", want: "f548e57e544e1ff5a4c46bf1e1b8685f8e4a348a"},
		{name: "verify when a slashed branch drops the repo prefix then the sha is returned", filename: "v3-a37ce9120846195fa4ece8f58b268e6043cb2f26.tar.gz", want: "a37ce9120846195fa4ece8f58b268e6043cb2f26"},
		{name: "verify when a slashed branch has a dotted last segment then the sha is returned", filename: "v4.0.0-1e31de5234b9f8995739874a8ce0492dc87873e2.tar.gz", want: "1e31de5234b9f8995739874a8ce0492dc87873e2"},
		{name: "verify when a slashed branch last segment has many hyphens then the sha is returned", filename: "backport-2518-releases-v4-d8f3cc5f1d15b597568d4448eefa4c62ae2df48e.tar.gz", want: "d8f3cc5f1d15b597568d4448eefa4c62ae2df48e"},
		{name: "verify when a deeply nested branch is downloaded then the sha is returned", filename: "submodule-ssh-url-level-2-bff576b9eb271dd75b27ccce2966454cd24a85a7.tar.gz", want: "bff576b9eb271dd75b27ccce2966454cd24a85a7"},
		{name: "verify when a four-segment branch is downloaded then the sha is returned", filename: "node-26.1.1-8c5626a6bb42f2988242fead6e87c288a26f2ad8.tar.gz", want: "8c5626a6bb42f2988242fead6e87c288a26f2ad8"},
		{name: "verify when a lightweight tag archive carries no sha then none is returned", filename: "checkout-v4.tar.gz", want: ""},
		{name: "verify when a dotted tag archive carries no sha then none is returned", filename: "checkout-v4.2.2.tar.gz", want: ""},
		{name: "verify when an annotated hyphenated tag archive carries no sha then none is returned", filename: "checkout-v2-beta.tar.gz", want: ""},
		{name: "verify when a short sha is echoed in the name then it is not taken as resolved", filename: "checkout-11d5960.tar.gz", want: ""},
		{name: "verify when the collision tag archive carries no sha then none is returned", filename: "probe-tag-branch-collision-collision.tar.gz", want: ""},
		// Shapes not measured, covering the edges of the rule.
		{name: "verify when a tag gains a sha then it is picked up", filename: "checkout-release-1.2-" + branchTip + ".tar.gz", want: branchTip},
		{name: "verify when a 64-hex id trails the name then it is returned", filename: "probe-" + sha256Object + ".tar.gz", want: sha256Object},
		{name: "verify when the trailing segment is 39 hex then none is returned", filename: "checkout-" + strings.Repeat("a", 39) + ".tar.gz", want: ""},
		{name: "verify when the trailing segment is 41 hex then none is returned", filename: "checkout-" + strings.Repeat("a", 41) + ".tar.gz", want: ""},
		{name: "verify when the trailing segment is not hex then none is returned", filename: "checkout-" + strings.Repeat("g", 40) + ".tar.gz", want: ""},
		{name: "verify when the name has no hyphen then none is returned", filename: "checkout.tar.gz", want: ""},
		{name: "verify when the filename is empty then none is returned", filename: "", want: ""},
		{name: "verify when the name is a bare sha with no hyphen then none is returned", filename: branchTip + ".tar.gz", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ExtractResolvedSHA(tt.filename), "ExtractResolvedSHA(%q)", tt.filename)
		})
	}
}
