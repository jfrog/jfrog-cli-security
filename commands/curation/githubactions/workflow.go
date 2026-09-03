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

// parseUsesString parses a single `uses:` value into owner/repo/ref, plus an optional subpath
// (empty for most actions - only present for monorepo-style actions like
// github/codeql-action/analyze@v3). Returns false for shapes that don't resolve to at least an
// owner/repo/ref triple
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

// ParseWorkflowUses parses every step-level `uses:` value out of one workflow YAML file.
// Local actions (uses: ./path) and Docker-URI actions (uses: docker://...) are skipped
// Reusable workflows are also ignored.
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
// logged and skipped - best effort, matching DiscoverActionCache's defensive-skip behavior.
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

type rawActionFile struct {
	Runs rawActionRuns `yaml:"runs"`
}

type rawActionRuns struct {
	Using string    `yaml:"using"`
	Steps []rawStep `yaml:"steps"`
}

// parseCompositeActionUses reads <actionPath>/action.yml (or action.yaml) and, if it's a
// composite action, returns every owner/repo/ref its own steps reference. Returns (nil, nil)
// if the action isn't composite - this is a best-effort, one-level-deep lookup for Parent attribution
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

// CrossReference enriches discovered entries (from DiscoverActionCache) with Subpaths and
// best-effort Parent metadata, and returns the enriched slice.
//
// Subpaths for a directly-used entry comes from every owner/repo/ref match against used (the
// job's own workflow uses: lines). For any entry with no direct match, Parent/Subpaths are
// attributed by reading the action.yml of every composite action already resolved at the
// current depth (starting with the directly-used ones) and walking outward one level at a time:
// if a composite action's own steps reference an unresolved entry, that entry's Parent becomes
// "<owner>/<repo>@<ref>" of the composite action, and its own action.yml (if also composite)
// becomes a source for the next level.
//
// The walk has no fixed depth limit: it terminates when the frontier runs dry, which it always
// does within len(discovered) rounds at most, since each round strictly attributes at least one
// previously-unattributed entry (visited/attributed dedup means no entry is ever re-processed).
// A cycle (action pulling in an ancestor of itself) can't loop forever either way, for the same
// reason - each action.yml is read at most once. That per-round-progress guarantee is also used
// as a second, independent bound below (maxRounds), so a bug that broke the dedup logic would
// still hit a hard stop instead of spinning.
//
// KNOWN LIMITATION: an action that pulls in others via a run: step instead of its own action.yml
// uses: is not attributed - such entries are left with Parent == "" - never guessed.
func CrossReference(discovered []ActionRef, used []WorkflowUse) []ActionRef {
	byKey := make(map[string]int, len(discovered))
	for i := range discovered {
		byKey[refKey(discovered[i].Owner, discovered[i].Repo, discovered[i].Ref)] = i
	}

	isDirect := make(map[string]bool, len(used))
	for _, u := range used {
		isDirect[refKey(u.Owner, u.Repo, u.Ref)] = true
	}
	subpathsByKey := collectSubpaths(used)

	// attributed marks every key that already has its Parent/Subpaths resolved (directly, or
	// transitively by an earlier/shallower round) - a source for the next level's walk, and a
	// guard against a deeper round overwriting an already-settled (shallower) attribution.
	attributed := map[string]bool{}
	frontier := make([]string, 0, len(used))
	for key := range isDirect {
		attributed[key] = true
		if idx, ok := byKey[key]; ok {
			discovered[idx].Subpaths = subpathsByKey[key]
		}
		frontier = append(frontier, key)
	}

	// maxRounds bounds the loop below: at most len(discovered) entries can ever be newly
	// attributed in total, so this many rounds is always enough. It's a safety net against a
	// regression in the visited/attributed dedup above, not a limit on legitimate nesting depth -
	// a round that attributes nothing new leaves the frontier empty and stops the loop anyway.
	maxRounds := len(discovered) + 1
	visited := map[string]bool{}
	for depth := 0; depth < maxRounds && len(frontier) > 0; depth++ {
		var nextFrontier []string
		for _, parentKey := range frontier {
			if visited[parentKey] {
				continue
			}
			visited[parentKey] = true
			parentIdx, ok := byKey[parentKey]
			if !ok {
				continue
			}
			compositeUses, err := parseCompositeActionUses(discovered[parentIdx].Path)
			if err != nil || len(compositeUses) == 0 {
				continue
			}
			parentIdentity := fmt.Sprintf("%s/%s@%s", discovered[parentIdx].Owner, discovered[parentIdx].Repo, discovered[parentIdx].Ref)
			childSubpaths := collectSubpaths(compositeUses)
			for _, cu := range compositeUses {
				childKey := refKey(cu.Owner, cu.Repo, cu.Ref)
				if attributed[childKey] {
					continue
				}
				childIdx, ok := byKey[childKey]
				if !ok {
					continue
				}
				discovered[childIdx].Parent = parentIdentity
				discovered[childIdx].Subpaths = childSubpaths[childKey]
				attributed[childKey] = true
				nextFrontier = append(nextFrontier, childKey)
			}
		}
		frontier = nextFrontier
	}
	return discovered
}

// collectSubpaths deduplicates the Subpath of every use by its owner/repo/ref key, preserving
// first-seen order. Uses with an empty Subpath contribute nothing (most actions have none).
func collectSubpaths(uses []WorkflowUse) map[string][]string {
	seen := map[string]map[string]bool{}
	result := map[string][]string{}
	for _, u := range uses {
		if u.Subpath == "" {
			continue
		}
		key := refKey(u.Owner, u.Repo, u.Ref)
		if seen[key] == nil {
			seen[key] = map[string]bool{}
		}
		if seen[key][u.Subpath] {
			continue
		}
		seen[key][u.Subpath] = true
		result[key] = append(result[key], u.Subpath)
	}
	return result
}

func refKey(owner, repo, ref string) string {
	return owner + "/" + repo + "@" + ref
}
