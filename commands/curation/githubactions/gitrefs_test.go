package githubactions

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Object IDs from the VCS API contract's fixture and the collision probe repository.
const (
	branchTip     = "7f65769ec680267df910d1bfb02caec92f614ac7"
	tagObject     = "e7b6efb26415b1da9a89ab3b4b984d9ff6da253f"
	tagCommit     = "5430086921c83cbf70d42154051b1917c0c4a2d8"
	sha256Object  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sha256Object2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	zeroSHA1      = "0000000000000000000000000000000000000000"
	zeroSHA256    = "0000000000000000000000000000000000000000000000000000000000000000"
)

// pkt frames payload as one pkt-line data packet.
func pkt(payload string) string {
	return fmt.Sprintf("%04x%s", len(payload)+pktHeaderLen, payload)
}

const flushPkt = "0000"

// advertisement assembles a stream: the service header and its flush, the given packets, and
// the terminating flush.
func advertisement(packets ...string) string {
	return pkt(uploadPackServiceLine+"\n") + flushPkt + strings.Join(packets, "") + flushPkt
}

func TestParseGitRefsContractFixture(t *testing.T) {
	validGitRefs := []byte(
		"001e# service=git-upload-pack\n" +
			"0000" +
			"00617f65769ec680267df910d1bfb02caec92f614ac7 HEAD\x00symref=HEAD:refs/heads/main object-format=sha1\n" +
			"003d7f65769ec680267df910d1bfb02caec92f614ac7 refs/heads/main\n" +
			"0041e7b6efb26415b1da9a89ab3b4b984d9ff6da253f refs/tags/collision\n" +
			"00445430086921c83cbf70d42154051b1917c0c4a2d8 refs/tags/collision^{}\n" +
			"0000",
	)

	got, err := ParseGitRefs(bytes.NewReader(validGitRefs))

	require.NoError(t, err)
	assert.Equal(t, &RefAdvertisement{
		ObjectFormat:  "sha1",
		HEAD:          branchTip,
		DefaultBranch: "main",
		Refs: map[string]string{
			"refs/heads/main":     branchTip,
			"refs/tags/collision": tagObject,
		},
		Peeled: map[string]string{"refs/tags/collision": tagCommit},
	}, got)
}

func TestParseGitRefsValid(t *testing.T) {
	tests := []struct {
		name   string
		stream string
		want   *RefAdvertisement
	}{
		{
			name: "verify when branch names contain slashes and pull refs are present then all are stored under their full names",
			stream: advertisement(
				pkt(branchTip+" HEAD\x00symref=HEAD:refs/heads/main\n"),
				pkt(branchTip+" refs/heads/feature/x\n"),
				pkt(branchTip+" refs/heads/releases/v4.0.0\n"),
				pkt(tagCommit+" refs/pull/123/head\n"),
				pkt(tagObject+" refs/pull/123/merge\n"),
			),
			want: &RefAdvertisement{
				ObjectFormat: "sha1", HEAD: branchTip, DefaultBranch: "main",
				Refs: map[string]string{
					"refs/heads/feature/x":       branchTip,
					"refs/heads/releases/v4.0.0": branchTip,
					"refs/pull/123/head":         tagCommit,
					"refs/pull/123/merge":        tagObject,
				},
				Peeled: map[string]string{},
			},
		},
		{
			name: "verify when payloads carry no trailing LF then they parse the same",
			stream: advertisement(
				pkt(branchTip+" HEAD\x00symref=HEAD:refs/heads/main"),
				pkt(branchTip+" refs/heads/main"),
			),
			want: &RefAdvertisement{
				ObjectFormat: "sha1", HEAD: branchTip, DefaultBranch: "main",
				Refs: map[string]string{"refs/heads/main": branchTip}, Peeled: map[string]string{},
			},
		},
		{
			name: "verify when object-format is omitted then it defaults to sha1",
			stream: advertisement(
				pkt(branchTip + " HEAD\x00multi_ack thin-pack\n"),
			),
			want: &RefAdvertisement{ObjectFormat: "sha1", HEAD: branchTip, Refs: map[string]string{}, Peeled: map[string]string{}},
		},
		{
			name: "verify when object-format is sha256 then 64-hex object IDs are accepted",
			stream: advertisement(
				pkt(sha256Object+" HEAD\x00object-format=sha256 symref=HEAD:refs/heads/main\n"),
				pkt(sha256Object+" refs/heads/main\n"),
				pkt(sha256Object2+" refs/tags/v1\n"),
				pkt(sha256Object+" refs/tags/v1^{}\n"),
			),
			want: &RefAdvertisement{
				ObjectFormat: "sha256", HEAD: sha256Object, DefaultBranch: "main",
				Refs:   map[string]string{"refs/heads/main": sha256Object, "refs/tags/v1": sha256Object2},
				Peeled: map[string]string{"refs/tags/v1": sha256Object},
			},
		},
		{
			name:   "verify when the repository is empty then the synthetic capabilities record yields no refs",
			stream: advertisement(pkt(zeroSHA1 + " capabilities^{}\x00multi_ack object-format=sha1\n")),
			want:   &RefAdvertisement{ObjectFormat: "sha1", Refs: map[string]string{}, Peeled: map[string]string{}},
		},
		{
			name:   "verify when an empty sha256 repository is advertised then its 64-character zero ID is accepted",
			stream: advertisement(pkt(zeroSHA256 + " capabilities^{}\x00object-format=sha256\n")),
			want:   &RefAdvertisement{ObjectFormat: "sha256", Refs: map[string]string{}, Peeled: map[string]string{}},
		},
		{
			name: "verify when a ref is outside heads, tags and pull then it is preserved",
			stream: advertisement(
				pkt(branchTip+" HEAD\x00agent=git/2\n"),
				pkt(tagCommit+" refs/notes/commits\n"),
			),
			want: &RefAdvertisement{
				ObjectFormat: "sha1", HEAD: branchTip,
				Refs: map[string]string{"refs/notes/commits": tagCommit}, Peeled: map[string]string{},
			},
		},
		{
			name: "verify when a version 1 line precedes the refs then it is accepted",
			stream: advertisement(
				pkt("version 1\n"),
				pkt(branchTip+" HEAD\x00symref=HEAD:refs/heads/main\n"),
			),
			want: &RefAdvertisement{
				ObjectFormat: "sha1", HEAD: branchTip, DefaultBranch: "main",
				Refs: map[string]string{}, Peeled: map[string]string{},
			},
		},
		{
			name: "verify when unknown well-formed capabilities are present then they are ignored",
			stream: advertisement(
				pkt(branchTip + " HEAD\x00future-cap future-kv=some:value symref=OTHER:refs/heads/x\n"),
			),
			want: &RefAdvertisement{ObjectFormat: "sha1", HEAD: branchTip, Refs: map[string]string{}, Peeled: map[string]string{}},
		},
		{
			name: "verify when the first record is a ref rather than HEAD then it is stored as a ref",
			stream: advertisement(
				pkt(branchTip + " refs/heads/main\x00object-format=sha1\n"),
			),
			want: &RefAdvertisement{
				ObjectFormat: "sha1",
				Refs:         map[string]string{"refs/heads/main": branchTip}, Peeled: map[string]string{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseGitRefs(strings.NewReader(tt.stream))

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseGitRefsInvalid(t *testing.T) {
	service := pkt(uploadPackServiceLine+"\n") + flushPkt
	head := pkt(branchTip + " HEAD\x00object-format=sha1\n")

	tests := []struct {
		name   string
		stream string
	}{
		{name: "verify when the body is empty then it is rejected", stream: ""},
		{name: "verify when a length header is not hex then it is rejected", stream: "00zz" + service},
		{name: "verify when a length header uses uppercase hex then it is rejected", stream: "001E# service=git-upload-pack\n" + flushPkt},
		{name: "verify when the length header is truncated then it is rejected", stream: "00"},
		{name: "verify when the invalid length 0003 appears then it is rejected", stream: service + "0003" + flushPkt},
		{name: "verify when an empty data packet 0004 appears then it is rejected", stream: service + "0004" + flushPkt},
		{name: "verify when a length exceeds 65520 then it is rejected", stream: service + "fff1" + strings.Repeat("x", 65517) + flushPkt},
		{name: "verify when a payload is shorter than its declared length then it is rejected", stream: service + "0040" + branchTip + " refs/heads/main"},
		{name: "verify when the control packet 0001 appears then it is rejected", stream: service + "0001" + flushPkt},
		{name: "verify when the control packet 0002 appears then it is rejected", stream: service + "0002" + flushPkt},
		{name: "verify when the service header is missing then it is rejected", stream: head + flushPkt},
		{name: "verify when the service header names another service then it is rejected", stream: pkt("# service=git-receive-pack\n") + flushPkt + head + flushPkt},
		{name: "verify when the service header is not followed by a flush then it is rejected", stream: pkt(uploadPackServiceLine+"\n") + head + flushPkt},
		{name: "verify when the terminating flush is missing then it is rejected", stream: service + head},
		{name: "verify when bytes follow the terminating flush then it is rejected", stream: service + head + flushPkt + "x"},
		{name: "verify when a packet follows the terminating flush then it is rejected", stream: service + head + flushPkt + head},
		{name: "verify when protocol version 2 is announced then it is rejected", stream: advertisement(pkt("version 2\n"), head)},
		{name: "verify when the first record has no NUL then it is rejected", stream: advertisement(pkt(branchTip + " HEAD\n"))},
		{name: "verify when the first record has two NULs then it is rejected", stream: advertisement(pkt(branchTip + " HEAD\x00multi_ack\x00thin-pack\n"))},
		{name: "verify when a later record carries a NUL then it is rejected", stream: advertisement(head, pkt(branchTip+" refs/heads/main\x00x\n"))},
		{name: "verify when a capability token is empty then it is rejected", stream: advertisement(pkt(branchTip + " HEAD\x00multi_ack  thin-pack\n"))},
		{name: "verify when a capability has no key then it is rejected", stream: advertisement(pkt(branchTip + " HEAD\x00=value\n"))},
		{name: "verify when object formats conflict then it is rejected", stream: advertisement(pkt(branchTip + " HEAD\x00object-format=sha1 object-format=sha256\n"))},
		{name: "verify when the object format is unsupported then it is rejected", stream: advertisement(pkt(branchTip + " HEAD\x00object-format=md5\n"))},
		{name: "verify when the HEAD symref targets a tag then it is rejected", stream: advertisement(pkt(branchTip + " HEAD\x00symref=HEAD:refs/tags/v1\n"))},
		{name: "verify when a symref has no target then it is rejected", stream: advertisement(pkt(branchTip + " HEAD\x00symref=HEAD\n"))},
		{name: "verify when HEAD has two symrefs then it is rejected", stream: advertisement(pkt(branchTip + " HEAD\x00symref=HEAD:refs/heads/a symref=HEAD:refs/heads/b\n"))},
		{name: "verify when an object ID is too short then it is rejected", stream: advertisement(head, pkt(branchTip[:39]+" refs/heads/main\n"))},
		{name: "verify when an object ID is non-hex then it is rejected", stream: advertisement(head, pkt(strings.Repeat("g", 40)+" refs/heads/main\n"))},
		{name: "verify when an object ID is uppercase then it is rejected", stream: advertisement(head, pkt(strings.ToUpper(branchTip)+" refs/heads/main\n"))},
		{name: "verify when an object ID is the zero ID then it is rejected", stream: advertisement(head, pkt(zeroSHA1+" refs/heads/main\n"))},
		{name: "verify when a sha1 ID appears in a sha256 stream then it is rejected", stream: advertisement(pkt(sha256Object+" HEAD\x00object-format=sha256\n"), pkt(branchTip+" refs/heads/main\n"))},
		{name: "verify when a record has no space then it is rejected", stream: advertisement(head, pkt(branchTip+"\n"))},
		{name: "verify when a ref name contains two dots then it is rejected", stream: advertisement(head, pkt(branchTip+" refs/heads/a..b\n"))},
		{name: "verify when a ref name ends in .lock then it is rejected", stream: advertisement(head, pkt(branchTip+" refs/heads/x.lock\n"))},
		{name: "verify when a ref name contains a space then it is rejected", stream: advertisement(head, pkt(branchTip+" refs/heads/a b\n"))},
		{name: "verify when a name is outside refs/ then it is rejected", stream: advertisement(head, pkt(branchTip+" main\n"))},
		{name: "verify when a ref is duplicated then it is rejected", stream: advertisement(head, pkt(branchTip+" refs/heads/main\n"), pkt(tagCommit+" refs/heads/main\n"))},
		{name: "verify when HEAD is duplicated then it is rejected", stream: advertisement(head, pkt(branchTip+" HEAD\n"))},
		{name: "verify when a peeled ref is duplicated then it is rejected", stream: advertisement(head, pkt(tagObject+" refs/tags/v1\n"), pkt(tagCommit+" refs/tags/v1^{}\n"), pkt(tagCommit+" refs/tags/v1^{}\n"))},
		{name: "verify when a peeled ref has no earlier tag then it is rejected", stream: advertisement(head, pkt(tagCommit+" refs/tags/v1^{}\n"))},
		{name: "verify when a branch carries a peeled suffix then it is rejected", stream: advertisement(head, pkt(branchTip+" refs/heads/main\n"), pkt(tagCommit+" refs/heads/main^{}\n"))},
		{name: "verify when the empty-repository record has a non-zero ID then it is rejected", stream: advertisement(pkt(branchTip + " capabilities^{}\x00object-format=sha1\n"))},
		{name: "verify when a ref follows the empty-repository record then it is rejected", stream: advertisement(pkt(zeroSHA1+" capabilities^{}\x00object-format=sha1\n"), pkt(branchTip+" refs/heads/main\n"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseGitRefs(strings.NewReader(tt.stream))

			assert.Error(t, err)
			assert.Nil(t, got)
		})
	}
}

// refCounts tallies an advertisement's refs by namespace. Peeled entries are counted separately.
type refCounts struct {
	heads, tags, pull, other, peeled int
}

func countRefs(adv *RefAdvertisement) refCounts {
	c := refCounts{peeled: len(adv.Peeled)}
	for name := range adv.Refs {
		switch {
		case strings.HasPrefix(name, headsPrefix):
			c.heads++
		case strings.HasPrefix(name, tagsPrefix):
			c.tags++
		case strings.HasPrefix(name, "refs/pull/"):
			c.pull++
		default:
			c.other++
		}
	}
	return c
}

func TestParseGitRefsCapturedAdvertisements(t *testing.T) {
	tests := []struct {
		fixture     string
		wantHEAD    string
		wantDefault string
		wantCounts  refCounts
		wantRefs    map[string]string
		wantPeeled  map[string]string
		// wantLightweight are tags that must have no peeled entry.
		wantLightweight []string
	}{
		{
			// Slashed branch names up to four levels deep, annotated and lightweight tags mixed,
			// and PRs both open (head and merge) and closed (head only).
			fixture: "actions-checkout", wantHEAD: "f548e57e544e1ff5a4c46bf1e1b8685f8e4a348a", wantDefault: "main",
			wantCounts: refCounts{heads: 10, tags: 10, pull: 10, peeled: 4},
			wantRefs: map[string]string{
				"refs/tags/v4":           "11d5960a326750d5838078e36cf38b85af677262",
				"refs/heads/releases/v4": "11d5960a326750d5838078e36cf38b85af677262",
				"refs/heads/copilot/backport-2518-releases-v4": "d8f3cc5f1d15b597568d4448eefa4c62ae2df48e",
				"refs/tags/v2-beta":                            "95784fc5bbede4a44d9abcfbde7a64f16e6dbedd",
				"refs/pull/1/head":                             "bf8f62083c41b3cb36f52c4100ad20ba98400ea6",
			},
			wantPeeled:      map[string]string{"refs/tags/v2-beta": "a6747255bd19d7a757dbdda8c654a9f84db19839"},
			wantLightweight: []string{"refs/tags/v4", "refs/tags/1.0.0"},
		},
		{
			// Lightweight tags only - no ^{} records at all - and a master default branch.
			fixture: "docker-build-push-action", wantHEAD: "c3c9e263c25d99ce0380d002d59b67737d91b0dc", wantDefault: "master",
			wantCounts: refCounts{heads: 10, tags: 10, pull: 10},
			wantRefs: map[string]string{
				"refs/tags/v1":     "3e7a4f6646880c6f63758d73ac32392d323eaf8f",
				"refs/pull/1/head": "3b4339199e7eafa9901d48d4c7b25c322b17e69a",
				"refs/heads/dependabot/github_actions/aws-actions/configure-aws-credentials-6.3.0": "7317d27643a2ae3e03a44368f44858e458b031ab",
			},
			wantLightweight: []string{"refs/tags/v1"},
		},
		{
			// Almost all annotated tags, a master default branch, and a git notes namespace.
			fixture: "softprops-action-gh-release", wantHEAD: "a4f117a9dd5572319a486154ec1147aebabd285c", wantDefault: "master",
			wantCounts: refCounts{heads: 7, tags: 10, pull: 10, other: 1, peeled: 9},
			wantRefs: map[string]string{
				"refs/notes/ai":              "e7b8e96167294fe6738a65137a2add3d78b2555f",
				"refs/heads/releases/v0.1.2": "b28d8151ad6190ad35959a52fb26b9433c69009f",
				"refs/tags/v0.1.10":          "16802b167dff57ea72975d185723829f034e4142",
			},
			wantPeeled:      map[string]string{"refs/tags/v0.1.10": "487fcd94425dd56e168af76ef300c3b4bd2a46fa"},
			wantLightweight: []string{"refs/tags/v0.1.0"},
		},
		{
			// Not GitHub: the same protocol from GitLab, whose host-specific namespaces are
			// refs/merge-requests, refs/environments and refs/pipelines rather than refs/pull.
			fixture: "gitlab-org-cli", wantHEAD: "52f5335927b17e041e1613cbfc4de3be35ffa3c0", wantDefault: "main",
			wantCounts: refCounts{heads: 10, tags: 10, other: 10, peeled: 3},
			wantRefs: map[string]string{
				"refs/merge-requests/10/head":                    "58f6836c84e3382ae4140cc80c16461ff35e1103",
				"refs/heads/acalder/fix-hostname-port-stripping": "9067893000a88f7082bfb562d18e0eae38310e27",
				"refs/tags/v1.103.0":                             "7bcc1cd9717c3b6dcd37e9cdc01a5537b2a904de",
			},
			wantPeeled:      map[string]string{"refs/tags/v1.103.0": "c724bea5fca299c989b0b27b2b24cd1cbe7136af"},
			wantLightweight: []string{"refs/tags/v0.1.0"},
		},
	}
	for _, tt := range tests {
		t.Run("verify when the "+tt.fixture+" advertisement is parsed then its refs are read exactly", func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(fixturesRoot, "gitrefs", tt.fixture+".pktline"))
			require.NoError(t, err)

			got, err := ParseGitRefs(bytes.NewReader(body))

			require.NoError(t, err)
			assert.Equal(t, "sha1", got.ObjectFormat)
			assert.Equal(t, tt.wantHEAD, got.HEAD)
			assert.Equal(t, tt.wantDefault, got.DefaultBranch)
			assert.Equal(t, tt.wantCounts, countRefs(got))
			for ref, oid := range tt.wantRefs {
				assert.Equal(t, oid, got.Refs[ref], "ParseGitRefs(%s).Refs[%q]", tt.fixture, ref)
			}
			for ref, oid := range tt.wantPeeled {
				assert.Equal(t, oid, got.Peeled[ref], "ParseGitRefs(%s).Peeled[%q]", tt.fixture, ref)
			}
			for _, ref := range tt.wantLightweight {
				assert.Contains(t, got.Refs, ref, "ParseGitRefs(%s) is missing tag %q", tt.fixture, ref)
				assert.NotContains(t, got.Peeled, ref, "ParseGitRefs(%s) peeled lightweight tag %q", tt.fixture, ref)
			}
			// Every peeled entry belongs to a tag the advertisement also lists.
			for ref := range got.Peeled {
				assert.Contains(t, got.Refs, ref, "ParseGitRefs(%s) peeled %q has no tag record", tt.fixture, ref)
			}
		})
	}
}
