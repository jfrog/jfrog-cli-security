package githubactions

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

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

// ErrJobUnknown reports that the job being curated could not be identified in this workflow
// file - either no job id was given, or the file does not declare the one that was.
//
// It is not a failure of the run. Each job executes on its own runner with its own _actions
// cache, so the cache already is this job's action list; the workflow file only ever adds
// attribution on top of it. Callers treat this as "cannot attribute" and curate the cache as-is.
var ErrJobUnknown = errors.New("cannot identify the job being curated in the workflow file")

// ParseWorkflowUses parses the step-level `uses:` values of ONE job in a workflow YAML file.
// Local actions (uses: ./path) and Docker-URI actions (uses: docker://...) are skipped.
//
// jobID must name a job the file declares; otherwise ParseWorkflowUses returns ErrJobUnknown and
// parses nothing. It never falls back to the file's other jobs, and there is no "read them all"
// mode: every other job in the file ran on its own runner with its own action cache, so what
// they declare says nothing about what this job resolved. Attributing from them mislabels at
// best, and - because the result also drives FilterRelevant - drops actions this job really
// used at worst.
//
// So attribution needs both a workflow file and a job id. On a runner that is no constraint:
// GITHUB_JOB is always set. Without one, the caller curates the action cache as-is.
func ParseWorkflowUses(workflowPath, jobID string) ([]WorkflowUse, error) {
	data, err := os.ReadFile(workflowPath)
	if err != nil {
		return nil, fmt.Errorf("reading workflow file %q: %w", workflowPath, err)
	}
	var wf rawWorkflow
	if err = yaml.Unmarshal(data, &wf); err != nil {
		return nil, fmt.Errorf("parsing workflow file %q: %w", workflowPath, err)
	}
	if jobID == "" {
		return nil, fmt.Errorf("%w: no job id given for %q", ErrJobUnknown, workflowPath)
	}
	job, declared := wf.Jobs[jobID]
	if !declared {
		return nil, fmt.Errorf("%w: %q is not among %v in %q", ErrJobUnknown, jobID, slices.Sorted(maps.Keys(wf.Jobs)), workflowPath)
	}
	// One job's steps: a slice, so the order is the file's, with no map iteration to sort away.
	var uses []WorkflowUse
	for _, step := range job.Steps {
		if parsed, ok := parseUsesString(step.Uses); ok {
			uses = append(uses, parsed)
		}
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
// composite action, returns every owner/repo/ref its own steps reference - one hop outward from
// actionPath. Returns (nil, nil) if the action isn't composite. CrossReference calls this
// repeatedly, once per action per round, to walk arbitrarily many hops; this function itself
// only ever looks at the one action.yml it's given.
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
//
// Actions used by a called reusable workflow (jobs.<id>.uses:) are never attributed here either
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
	// visited is keyed by "parentKey\x00subpath" (subpath "" for the no-subpath/root case),
	// since a monorepo action invoked via more than one subpath (e.g. codeql-action's init and
	// analyze) has a separate action.yml per subpath, each needing its own scan.
	visited := map[string]bool{}
	for depth := 0; depth < maxRounds && len(frontier) > 0; depth++ {
		var nextFrontier []string
		for _, parentKey := range frontier {
			parentIdx, ok := byKey[parentKey]
			if !ok {
				continue
			}
			parentIdentity := fmt.Sprintf("%s/%s@%s", discovered[parentIdx].Owner, discovered[parentIdx].Repo, discovered[parentIdx].Ref)

			// For owner/repo/subpath@ref, the action's own metadata lives at
			// <cache>/<owner>/<repo>/<ref>/<subpath>/action.yml, not at the cache root - the root
			// is only correct when the action was never referenced via a subpath.
			subpaths := discovered[parentIdx].Subpaths
			if len(subpaths) == 0 {
				subpaths = []string{""}
			}
			for _, subpath := range subpaths {
				visitKey := parentKey + "\x00" + subpath
				if visited[visitKey] {
					continue
				}
				visited[visitKey] = true

				metadataDir := discovered[parentIdx].Path
				if subpath != "" {
					metadataDir = filepath.Join(metadataDir, subpath)
				}
				compositeUses, err := parseCompositeActionUses(metadataDir)
				if err != nil || len(compositeUses) == 0 {
					continue
				}
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

// FilterRelevant narrows discovered (after CrossReference) down to entries that are actually
// part of the current workflow's dependency graph: those directly referenced in used, or
// transitively attributed a Parent by CrossReference. Call this before deciding curation status
// for anything - CrossReference intentionally leaves unrelated entries in its return value
// untouched rather than dropping them, so this is a separate, explicit step.
//
// Anything else present in the runner's action cache but unrelated to this workflow - e.g. a
// leftover entry from a previous job on a reused self-hosted runner (see the design deck's
// Delivery 02 pre-job hook, which runs on a persistent runner across many jobs, not a
// per-job-isolated one), or an unrelated directory pointed at via --actions-cache-dir - is
// dropped here so it's never decided or reported, and can never fail curation for a workflow
// it isn't even part of.
func FilterRelevant(discovered []ActionRef, used []WorkflowUse) []ActionRef {
	isDirect := make(map[string]bool, len(used))
	for _, u := range used {
		isDirect[refKey(u.Owner, u.Repo, u.Ref)] = true
	}
	relevant := make([]ActionRef, 0, len(discovered))
	for _, ref := range discovered {
		if isDirect[refKey(ref.Owner, ref.Repo, ref.Ref)] || ref.Parent != "" {
			relevant = append(relevant, ref)
		}
	}
	return relevant
}
