package githubactions

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jfrog/jfrog-client-go/utils/log"
	"gopkg.in/yaml.v3"
)

// WorkflowUse is one `uses:` value parsed out of a workflow (or composite action) YAML file.
type WorkflowUse struct {
	Owner   string
	Repo    string
	Subpath string // "" handle mono repo github actions, e.g. github/codeql-action/analyze@v3
	Ref     string
	Raw     string // the original "uses:" string, for diagnostics
}

type rawWorkflow struct {
	Jobs map[string]rawJob `yaml:"jobs"`
}

type rawJob struct {
	Steps []rawStep `yaml:"steps"`
}

type rawStep struct {
	Uses string `yaml:"uses"`
}

// ParseWorkflowUses parses every step-level `uses:` value out of one workflow YAML file.
// Local actions (uses: ./path) and Docker-URI actions (uses: docker://...) are skipped -
// neither has an owner/repo/ref shape and neither appears under the runner's _actions cache.
//
// A job's own top-level `uses:` (calling a reusable workflow, e.g.
// org/repo/.github/workflows/x.yml@ref) is intentionally not parsed here: such a job has no
// steps: of its own to instrument, and the called workflow's actions are a structurally
// different problem (see the design deck's "third-party reusable workflows" limitation) -
// out of scope for this cross-reference step.
func ParseWorkflowUses(workflowPath string) ([]WorkflowUse, error) {
	data, err := os.ReadFile(workflowPath)
	if err != nil {
		return nil, fmt.Errorf("reading workflow file %q: %w", workflowPath, err)
	}
	var wf rawWorkflow
	if err = yaml.Unmarshal(data, &wf); err != nil {
		return nil, fmt.Errorf("parsing workflow file %q: %w", workflowPath, err)
	}
	var uses []WorkflowUse
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if parsed, ok := parseUsesString(step.Uses); ok {
				uses = append(uses, parsed)
			}
		}
	}
	return uses, nil
}

// ParseWorkflowsDir aggregates ParseWorkflowUses over every *.yml/*.yaml file directly under
// workflowsDir (typically <repo>/.github/workflows). A malformed individual workflow file is
// logged and skipped rather than failing the whole aggregation - best effort, matching
// DiscoverActionCache's defensive-skip behavior.
func ParseWorkflowsDir(workflowsDir string) ([]WorkflowUse, error) {
	entries, err := os.ReadDir(workflowsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading workflows dir %q: %w", workflowsDir, err)
	}
	var uses []WorkflowUse
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		parsed, err := ParseWorkflowUses(filepath.Join(workflowsDir, name))
		if err != nil {
			log.Debug(fmt.Sprintf("github-actions curation: skipping workflow file %q: %v", name, err))
			continue
		}
		uses = append(uses, parsed...)
	}
	return uses, nil
}

// parseUsesString parses a single `uses:` value into owner/repo/subpath/ref.
// Returns ok=false for shapes that don't resolve to an owner/repo/ref triple:
// local actions (./path), Docker-URI actions (docker://...), or a malformed value with no @ref.
func parseUsesString(raw string) (WorkflowUse, bool) {
	if raw == "" || strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "docker://") {
		return WorkflowUse{}, false
	}
	atIdx := strings.LastIndex(raw, "@")
	if atIdx < 0 || atIdx == len(raw)-1 {
		return WorkflowUse{}, false
	}
	path, ref := raw[:atIdx], raw[atIdx+1:]
	segments := strings.Split(path, "/")
	if len(segments) < 2 || segments[0] == "" || segments[1] == "" {
		return WorkflowUse{}, false
	}
	subpath := ""
	if len(segments) > 2 {
		subpath = strings.Join(segments[2:], "/")
	}
	return WorkflowUse{Owner: segments[0], Repo: segments[1], Subpath: subpath, Ref: ref, Raw: raw}, true
}

type rawActionFile struct {
	Runs rawActionRuns `yaml:"runs"`
}

type rawActionRuns struct {
	Using string    `yaml:"using"`
	Steps []rawStep `yaml:"steps"`
}

// parseCompositeActionUses reads <actionPath>/action.yml (or action.yaml) and, if it's a
// composite action, returns every owner/repo/ref its own steps reference. Returns (nil, nil)
// if the action isn't composite, and (nil, nil) rather than an error if the file is missing or
// unreadable - this is a best-effort, one-level-deep lookup for Parent attribution, not a hard
// requirement (see CrossReference's known limitation).
func parseCompositeActionUses(actionPath string) ([]WorkflowUse, error) {
	for _, name := range []string{"action.yml", "action.yaml"} {
		data, err := os.ReadFile(filepath.Join(actionPath, name))
		if err != nil {
			continue
		}
		var af rawActionFile
		if err := yaml.Unmarshal(data, &af); err != nil {
			return nil, nil
		}
		if af.Runs.Using != "composite" {
			return nil, nil
		}
		var uses []WorkflowUse
		for _, step := range af.Runs.Steps {
			if parsed, ok := parseUsesString(step.Uses); ok {
				uses = append(uses, parsed)
			}
		}
		return uses, nil
	}
	return nil, nil
}

// CrossReference enriches discovered entries (from DiscoverActionCache) with Subpath and
// best-effort Parent metadata, and returns the enriched slice.
//
// Subpath comes from a direct owner/repo/ref match against used (the job's own workflow
// uses: lines). For any discovered entry with no direct match, Parent is attributed via a
// one-level-deep read of each *directly-used* action's own action.yml: if that action is a
// composite action whose own steps reference the unmatched entry, Parent is set to
// "<owner>/<repo>@<ref>" of that composite action.
//
// KNOWN LIMITATION: nesting deeper than one level (a composite action pulling in another
// composite action pulling in a third), or an action that pulls in others via a run: step
// instead of its own action.yml uses:, is not attributed. Such entries are left with
// Parent == "" - never guessed.
func CrossReference(discovered []ActionRef, used []WorkflowUse) []ActionRef {
	directMatch := make(map[string]WorkflowUse, len(used))
	for _, u := range used {
		directMatch[refKey(u.Owner, u.Repo, u.Ref)] = u
	}

	unmatched := make([]int, 0, len(discovered))
	for i := range discovered {
		if u, ok := directMatch[refKey(discovered[i].Owner, discovered[i].Repo, discovered[i].Ref)]; ok {
			discovered[i].Subpath = u.Subpath
		} else {
			unmatched = append(unmatched, i)
		}
	}
	if len(unmatched) == 0 {
		return discovered
	}

	// Build a lookup of transitive owner/repo/ref -> parent "owner/repo@ref", by reading the
	// action.yml of every directly-used, directly-discovered top-level action.
	transitiveParent := map[string]string{}
	for i := range discovered {
		if discovered[i].Subpath == "" {
			if _, isDirect := directMatch[refKey(discovered[i].Owner, discovered[i].Repo, discovered[i].Ref)]; !isDirect {
				continue
			}
		}
		compositeUses, err := parseCompositeActionUses(discovered[i].Path)
		if err != nil || len(compositeUses) == 0 {
			continue
		}
		parent := fmt.Sprintf("%s/%s@%s", discovered[i].Owner, discovered[i].Repo, discovered[i].Ref)
		for _, cu := range compositeUses {
			transitiveParent[refKey(cu.Owner, cu.Repo, cu.Ref)] = parent
		}
	}

	for _, i := range unmatched {
		if parent, ok := transitiveParent[refKey(discovered[i].Owner, discovered[i].Repo, discovered[i].Ref)]; ok {
			discovered[i].Parent = parent
		}
	}
	return discovered
}

func refKey(owner, repo, ref string) string {
	return owner + "/" + repo + "@" + ref
}
