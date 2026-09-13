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

	"github.com/jfrog/jfrog-client-go/utils/log"
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
// file - either no job id was given, or the file does not declare the one that was. It is not a
// failure of the run: callers treat it as "cannot attribute" and curate the cache as-is.
var ErrJobUnknown = errors.New("cannot identify the job being curated in the workflow file")

// ErrWorkflowUnparsable reports that the workflow file was read but could not be parsed as YAML.
// The runner already accepted this file, so it is a divergence between its YAML reader and ours
// rather than a broken workflow - the same position parseCompositeActionUses is in one level
// down, and handled the same way. It is not a failure of the run: callers treat it as "cannot
// attribute" and curate the cache as-is.
var ErrWorkflowUnparsable = errors.New("cannot parse the workflow file")

// ParseWorkflowUses parses the step-level `uses:` values of ONE job in a workflow YAML file.
// Local actions (uses: ./path) and Docker-URI actions (uses: docker://...) are skipped.
//
// jobID must name a job the file declares; otherwise it returns ErrJobUnknown and parses
// nothing. There is deliberately no fallback to the file's other jobs: each ran on its own
// runner with its own cache, so attributing from them would label an entry with a parent that
// never pulled it in. Attribution therefore needs both a file and a job id - no constraint on a
// runner, where GITHUB_JOB is always set.
func ParseWorkflowUses(workflowPath, jobID string) ([]WorkflowUse, error) {
	data, err := os.ReadFile(workflowPath)
	if err != nil {
		return nil, fmt.Errorf("reading workflow file %q: %w", workflowPath, err)
	}
	var wf rawWorkflow
	if err = yaml.Unmarshal(data, &wf); err != nil {
		return nil, fmt.Errorf("%w %q: %w", ErrWorkflowUnparsable, workflowPath, err)
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
// actionPath. CrossReference calls this repeatedly, once per action per round, to walk
// arbitrarily many hops; this function itself only ever looks at the one action.yml it's given.
//
// There is no error return because there is no failure: absent metadata, metadata this parser
// cannot read, and a non-composite action all mean the same thing here - nothing to attribute
// from - and none of them may fail the run. The result is always "the references found", which
// is legitimately none.
func parseCompositeActionUses(actionPath string) []WorkflowUse {
	for _, name := range []string{"action.yml", "action.yaml"} {
		data, err := os.ReadFile(filepath.Join(actionPath, name))
		if err != nil {
			continue
		}
		var af rawActionFile
		if err := yaml.Unmarshal(data, &af); err != nil {
			// The runner already accepted this file, so a parse failure here is a divergence
			// between its YAML reader and ours, not a broken action. Nothing is attributed from
			// it - the entries it pulled in stay unattributed and are still curated - but the
			// reason has to be greppable, or the missing Parent column looks like a design choice.
			log.Debug(fmt.Sprintf("github-actions curation: cannot parse %q - no transitive references attributed from it: %v", filepath.Join(actionPath, name), err))
			return nil
		}
		if af.Runs.Using != "composite" {
			return nil
		}
		var uses []WorkflowUse
		for _, step := range af.Runs.Steps {
			if parsed, ok := parseUsesString(step.Uses); ok {
				uses = append(uses, parsed)
			}
		}
		return uses
	}
	return nil
}

// CrossReference enriches discovered entries with Subpaths and best-effort Parent metadata,
// and returns the enriched slice.
//
// Attribution is purely additive: it only ever adds metadata, never removes an entry. One it
// cannot place keeps an empty Parent and is still curated - an action the runner resolved will
// execute whether or not this code can explain why it is there.
//
// A directly-used entry takes its Subpaths from the job's own uses: lines. Every other entry is
// attributed by walking outward one level at a time, reading the action.yml of each composite
// action resolved at the current depth: a step referencing an unresolved entry makes that
// entry's Parent the composite action's "<owner>/<repo>@<ref>" (first parent wins - see
// hasParent below), and that entry a source for the next level.
//
// An action key can be invoked through more than one metadata location - its cache root, and/or
// one or more subpaths - and not always by the same parent: two different composites may each
// reference the same child at a different subpath. Every distinct location any parent references
// is scanned, regardless of which parent gets credited as Parent; only the Parent field is
// first-wins.
//
// The walk has no fixed depth limit - it stops when the frontier runs dry. What guarantees that
// is markLocation: a (key, location) pair is scanned at most once, so every round must consume a
// pair not seen before, and the pairs are finite. A cycle terminates for that same reason rather
// than by being detected. Note the pair count is not len(discovered) - one key contributes a pair
// per location it is referenced through - so maxRounds below is a backstop, not the real bound.
//
// KNOWN LIMITATION: an action pulling others in via a run: step rather than its own uses:, and
// actions used by a called reusable workflow (jobs.<id>.uses:), are never attributed - Parent
// stays empty, never guessed. Unattributed is not unreported; those entries are still curated.
func CrossReference(discovered []ActionRef, used []WorkflowUse) []ActionRef {
	byKey := make(map[string]int, len(discovered))
	for i := range discovered {
		byKey[refKey(discovered[i].Owner, discovered[i].Repo, discovered[i].Ref)] = i
	}

	// scanned tracks, per key, every location (a subpath, or "" for the cache root) whose
	// action.yml has already been scanned or queued to be - across every parent that references
	// the key, not just the first. Recording a location here is the signal that it is new: the
	// guard against merging it into Subpaths twice, and against scanning it twice.
	scanned := map[string]map[string]bool{}
	markLocation := func(key, location string) (isNew bool) {
		if scanned[key] == nil {
			scanned[key] = map[string]bool{}
		}
		if scanned[key][location] {
			return false
		}
		scanned[key][location] = true
		return true
	}

	// hasParent marks every key whose Parent is already settled - directly used by the job (no
	// Parent to attribute), or attributed by an earlier, shallower round. First parent wins: once
	// a key is here, a later round finding the same child through a different composite never
	// overwrites Parent - but the location that reference was found at is still merged into
	// Subpaths and scanned, since attribution and "what still needs reading" are separate guards.
	hasParent := map[string]bool{}

	// pending pairs a key with the locations newly discovered for it this round, so the round
	// loop below only re-reads metadata that is actually new.
	type pending struct {
		key       string
		locations []string
	}
	queueLocation := func(list *[]pending, idx map[string]int, key, location string) {
		if i, ok := idx[key]; ok {
			(*list)[i].locations = append((*list)[i].locations, location)
			return
		}
		idx[key] = len(*list)
		*list = append(*list, pending{key: key, locations: []string{location}})
	}

	var frontier []pending
	frontierIdx := map[string]int{}
	for _, u := range used {
		key := refKey(u.Owner, u.Repo, u.Ref)
		hasParent[key] = true // directly used by the job itself - no Parent to attribute
		isNew := markLocation(key, u.Subpath)
		if idx, ok := byKey[key]; ok && isNew && u.Subpath != "" {
			discovered[idx].Subpaths = append(discovered[idx].Subpaths, u.Subpath)
		}
		if isNew {
			queueLocation(&frontier, frontierIdx, key, u.Subpath)
		}
	}

	// A second, independent bound: a regression in the dedup above would hit a hard stop rather
	// than spin. It is not a limit on legitimate nesting depth.
	maxRounds := len(discovered) + 1
	for depth := 0; depth < maxRounds && len(frontier) > 0; depth++ {
		var nextFrontier []pending
		nextIdx := map[string]int{}

		for _, p := range frontier {
			parentIdx, ok := byKey[p.key]
			if !ok {
				continue
			}
			parentIdentity := fmt.Sprintf("%s/%s@%s", discovered[parentIdx].Owner, discovered[parentIdx].Repo, discovered[parentIdx].Ref)

			// For owner/repo/subpath@ref, the action's own metadata lives at
			// <cache>/<owner>/<repo>/<ref>/<subpath>/action.yml, not at the cache root - the root
			// is only correct for a location that is itself the root (empty subpath).
			for _, location := range p.locations {
				metadataDir := discovered[parentIdx].Path
				if location != "" {
					metadataDir = filepath.Join(metadataDir, location)
				}
				for _, cu := range parseCompositeActionUses(metadataDir) {
					childKey := refKey(cu.Owner, cu.Repo, cu.Ref)
					childIdx, ok := byKey[childKey]
					if !ok {
						continue
					}
					if !hasParent[childKey] {
						discovered[childIdx].Parent = parentIdentity
						hasParent[childKey] = true
					}
					isNew := markLocation(childKey, cu.Subpath)
					if isNew && cu.Subpath != "" {
						discovered[childIdx].Subpaths = append(discovered[childIdx].Subpaths, cu.Subpath)
					}
					if isNew {
						queueLocation(&nextFrontier, nextIdx, childKey, cu.Subpath)
					}
				}
			}
		}
		frontier = nextFrontier
	}
	return discovered
}

func refKey(owner, repo, ref string) string {
	return owner + "/" + repo + "@" + ref
}
