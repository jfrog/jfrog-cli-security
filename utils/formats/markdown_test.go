package formats

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEscapeMarkdownTableCell(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"verify when the text is ordinary then it is untouched", "actions/checkout", "actions/checkout"},
		{"verify when the value is empty then it stays empty", "", ""},
		{"verify when the value contains a pipe then the pipe is escaped", "refs|heads", `refs\|heads`},
		{"verify when the value contains several pipes then every one is escaped", "a|b|c", `a\|b\|c`},
		{"verify when the value contains a backslash then it is escaped first", `a\b`, `a\\b`},
		{"verify when the value contains an already-escaped pipe then both characters stay literal", `a\|b`, `a\\\|b`},
		{"verify when the value contains a newline then it becomes a line break", "first\nsecond", "first<br>second"},
		{"verify when the value contains a carriage return newline then it becomes one line break", "first\r\nsecond", "first<br>second"},
		{"verify when the value contains a bare carriage return then it becomes a line break", "first\rsecond", "first<br>second"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, EscapeMarkdownTableCell(tt.value))
		})
	}
}

func TestRenderActionsException(t *testing.T) {
	// One renderer serves the console report and the job summary, so these strings are the whole
	// statement of what an all-Approved GitHub Actions table does not cover. It is given the
	// curated-actions data rather than a caller's reading of it, so every case here is expressed
	// as the facts a run produced.
	attributed := func(localUses ...LocalCompositeAction) CuratedActions {
		return CuratedActions{Attributed: true, LocalCompositeActions: localUses}
	}
	unattributed := func(localUses ...LocalCompositeAction) CuratedActions {
		return CuratedActions{Attributed: false, LocalCompositeActions: localUses}
	}
	tests := []struct {
		name            string
		actions         []CuratedActions
		wantEmpty       bool
		wantContains    []string
		wantNotContains []string
	}{
		{
			name:      "verify when there is no data then nothing is said",
			actions:   nil,
			wantEmpty: true,
		},
		{
			name:      "verify when attribution succeeded and no local action is declared then nothing is said",
			actions:   []CuratedActions{attributed()},
			wantEmpty: true,
		},
		{
			name:    "verify when one local action is declared then it is named in the singular",
			actions: []CuratedActions{attributed(LocalCompositeAction{Path: "./.github/actions/setup"})},
			// The path is the only thing a reader can act on: it is the step whose own references
			// this report never saw.
			wantContains: []string{"a local composite action", `"./.github/actions/setup"`, "not curated here"},
		},
		{
			name: "verify when several local actions are declared then every one is named",
			actions: []CuratedActions{attributed(
				LocalCompositeAction{Path: "./.github/actions/setup"},
				LocalCompositeAction{Path: "./.github/actions/teardown", DeclaredBy: "some-org/wrapper@v1"},
			)},
			wantContains: []string{
				"local composite actions",
				`"./.github/actions/setup"`,
				`"./.github/actions/teardown" declared by some-org/wrapper@v1`,
			},
		},
		{
			name: "verify when a composite action declares the local step then the declaring action is named",
			// The path points into the caller's repository, not into the composite action, so
			// without the declarer a reader has no way to tell where the reference came from.
			actions: []CuratedActions{attributed(LocalCompositeAction{Path: "./scripts/build", DeclaredBy: "some-org/wrapper@v1"})},
			wantContains: []string{
				"a local composite action",
				`"./scripts/build" declared by some-org/wrapper@v1`,
			},
		},
		{
			name: "verify when attribution failed then the caveat is unconditional rather than a detection",
			// The ordinary case on a runner: the check runs before the checkout, so there is no
			// workflow file to read and no way to tell whether a local action is declared at all.
			// Saying nothing here would be the one case where an all-Approved table is most
			// likely to be incomplete and least likely to admit it.
			actions:      []CuratedActions{unattributed()},
			wantContains: []string{"no workflow file was available", "uses: ./...", "not curated"},
		},
		{
			// Two runs merged into one section: one found a local step, the other had no workflow
			// file. Reporting only the second discards a path that IS known, in the case with the
			// most to report - which is what happens when a caller decides for this function
			// whether its knowledge is complete.
			name: "verify when one run found a local action and another could not look then both are stated",
			actions: []CuratedActions{
				attributed(LocalCompositeAction{Path: "./.github/actions/setup"}),
				unattributed(),
			},
			wantContains: []string{
				`"./.github/actions/setup"`,
				"not curated here",
				"there may be others it could not see",
			},
		},
		{
			name: "verify when every run was attributed then no completeness caveat is added",
			actions: []CuratedActions{
				attributed(LocalCompositeAction{Path: "./.github/actions/setup"}),
				attributed(),
			},
			wantContains:    []string{`"./.github/actions/setup"`},
			wantNotContains: []string{"there may be others it could not see"},
		},
		{
			name: "verify when two runs report the same local action then it is named once",
			actions: []CuratedActions{
				attributed(LocalCompositeAction{Path: "./.github/actions/setup"}),
				attributed(LocalCompositeAction{Path: "./.github/actions/setup"}),
			},
			// Singular, because one path seen twice is one uncovered action.
			wantContains:    []string{"a local composite action"},
			wantNotContains: []string{"local composite actions"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RenderActionsException(tt.actions)

			if tt.wantEmpty {
				assert.Equal(t, "", got)
				return
			}
			for _, want := range tt.wantContains {
				assert.Contains(t, got, want)
			}
			for _, notWant := range tt.wantNotContains {
				assert.NotContains(t, got, notWant)
			}
			// Rendered right after a markdown table, so it needs its own block, and it must not
			// carry markup a terminal would show verbatim.
			assert.True(t, strings.HasPrefix(got, "\n"), "the caveat must start its own block, got %q", got)
			assert.NotContains(t, got, "[!NOTE]")
			assert.NotContains(t, got, "|")
		})
	}
}

func TestRenderActionsException_SameLocalActionFromTwoDeclarersKeepsBoth(t *testing.T) {
	// The path resolves the same way either way, but a reader chasing it needs every place it is
	// referenced from - so dedup is on the whole value, not on the path.
	got := RenderActionsException([]CuratedActions{{
		Attributed: true,
		LocalCompositeActions: []LocalCompositeAction{
			{Path: "./shared", DeclaredBy: "org/parent-a@v1"},
			{Path: "./shared", DeclaredBy: "org/parent-b@v1"},
		},
	}})

	assert.Contains(t, got, `"./shared" declared by org/parent-a@v1`)
	assert.Contains(t, got, `"./shared" declared by org/parent-b@v1`)
}
