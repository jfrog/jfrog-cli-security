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
	if raw == "" || IsLocalUse(raw) || strings.HasPrefix(raw, "docker://") {
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

func IsLocalUse(raw string) bool {
	return strings.HasPrefix(raw, "./")
}

// LocalUse is one `uses: ./...` step the job will run, and who declared it.
type LocalUse struct {
	// Raw is the `uses:` value verbatim, e.g. "./.github/actions/setup".
	Raw string
	// DeclaredBy is the composite action that declares this step, as "<owner>/<repo>@<ref>"
	DeclaredBy string
}

// JobUses is what one job's steps reference.
type JobUses struct {
	// Remote holds the owner/repo/ref references this job declares, in file order.
	Remote []WorkflowUse
	// Local holds the `uses: ./...` steps, in file order, deduplicated per declarer.
	Local []LocalUse
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
// Docker-URI actions (uses: docker://...) are skipped - the runner pulls those images during job
// setup rather than into the action cache. Local actions (uses: ./path) are not parsed as
// references either, but are returned in JobUses.Local so the report can declare them uncovered.
//
// jobID must name a job the file declares; otherwise it returns ErrJobUnknown and parses
// nothing. There is deliberately no fallback to the file's other jobs: each ran on its own
// runner with its own cache, so attributing from them would label an entry with a parent that
// never pulled it in. Attribution therefore needs both a file and a job id - no constraint on a
// runner, where GITHUB_JOB is always set.
//
// KNOWN FAILURE - a called reusable workflow can attribute against the wrong job because
// GITHUB_WORKFLOW_REF holds the caller file name and GITHUB_JOB holds the callee job id.
// only attribution error and is unfixed at the moment.
func ParseWorkflowUses(workflowPath, jobID string) (JobUses, error) {
	data, err := os.ReadFile(workflowPath)
	if err != nil {
		return JobUses{}, fmt.Errorf("reading workflow file %q: %w", workflowPath, err)
	}
	var wf rawWorkflow
	if err = yaml.Unmarshal(data, &wf); err != nil {
		return JobUses{}, fmt.Errorf("%w %q: %w", ErrWorkflowUnparsable, workflowPath, err)
	}
	if jobID == "" {
		return JobUses{}, fmt.Errorf("%w: no job id given for %q", ErrJobUnknown, workflowPath)
	}
	job, declared := wf.Jobs[jobID]
	if !declared {
		return JobUses{}, fmt.Errorf("%w: %q is not among %v in %q", ErrJobUnknown, jobID, slices.Sorted(maps.Keys(wf.Jobs)), workflowPath)
	}
	// One job's steps: a slice, so the order is the file's, with no map iteration to sort away.
	// DeclaredBy is left empty: the job's own workflow declares these.
	return parseSteps(job.Steps, ""), nil
}

// parseSteps splits one steps: list into the remote references to curate and the local steps
// that cannot be, attributing the local ones to declaredBy ("" for a job's own steps).
//
// Local steps are deduplicated because the report names each once: two steps invoking the same
// local action are one uncovered action, not two.
func parseSteps(steps []rawStep, declaredBy string) (uses JobUses) {
	seenLocal := map[string]bool{}
	for _, step := range steps {
		if IsLocalUse(step.Uses) {
			if !seenLocal[step.Uses] {
				seenLocal[step.Uses] = true
				uses.Local = append(uses.Local, LocalUse{Raw: step.Uses, DeclaredBy: declaredBy})
			}
			continue
		}
		if parsed, ok := parseUsesString(step.Uses); ok {
			uses.Remote = append(uses.Remote, parsed)
		}
	}
	return uses
}

type rawActionFile struct {
	Runs rawActionRuns `yaml:"runs"`
}

type rawActionRuns struct {
	Using string    `yaml:"using"`
	Steps []rawStep `yaml:"steps"`
}

// parseCompositeActionUses reads <actionPath>/action.yml (or action.yaml) and, if it's a
// composite action, returns what its own steps reference - one hop outward from actionPath.
//
// JobUses.Remote is what the walk attributes from. JobUses.Local is the part which are detected
// and reported as not curated.
func parseCompositeActionUses(actionPath, declaredBy string) JobUses {
	for _, name := range []string{"action.yml", "action.yaml"} {
		data, err := os.ReadFile(filepath.Join(actionPath, name))
		if err != nil {
			continue
		}
		var af rawActionFile
		if err := yaml.Unmarshal(data, &af); err != nil {
			log.Debug(fmt.Sprintf("github-actions curation: cannot parse %q - no transitive references attributed from it: %v", filepath.Join(actionPath, name), err))
			return JobUses{}
		}
		if af.Runs.Using != "composite" {
			return JobUses{}
		}
		return parseSteps(af.Runs.Steps, declaredBy)
	}
	return JobUses{}
}

// CrossReference enriches discovered entries with Subpaths and best-effort Parent metadata, and
// returns the enriched slice along with every local step it met on the way out.
// The local steps are a coverage statement, not attribution.
//
// A directly-used entry takes its Subpaths from the job's own uses: lines. Every other entry is
// attributed by parsing the action.yaml of composite actions.
//
// An action key can be invoked through more than one metadata location - its cache root, and/or
// one or more subpaths - and not always by the same parent: two different composites may each
// reference the same child at a different subpath. Every distinct location any parent references
// is scanned, regardless of which parent gets credited as Parent; only the Parent field is
// first-wins.
//
// Rounds are consumed by pairs, not by cache entries: one key contributes a pair per location it
// is referenced through, so a monorepo action reached through a chain of its own subpaths can
// need more rounds than the cache holds entries. Any bound derived from the entry count is
// therefore too small, and truncates silently - the unscanned subpath is still listed in
// Subpaths, so the result reads as complete.
//
// KNOWN LIMITATION: an action pulling others in via a run: step rather than its own uses:, and
// actions used by a called reusable workflow (jobs.<id>.uses:), are never attributed - Parent
// stays empty, never guessed.
func CrossReference(discovered []ActionRef, used JobUses) ([]ActionRef, []LocalUse) {
	var localUses []LocalUse
	// Deduplicated on the pair, not on the path: the same "./x" declared by two different
	// composite actions is one uncovered action reached two ways, and a reader chasing it needs
	// both declarers, while a repeat of the identical statement is noise.
	seenLocal := map[LocalUse]bool{}
	recordLocal := func(uses []LocalUse) {
		for _, use := range uses {
			if seenLocal[use] {
				continue
			}
			seenLocal[use] = true
			localUses = append(localUses, use)
		}
	}

	// The job's own local steps first, so the report lists them before the ones found deeper.
	recordLocal(used.Local)

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
	for _, u := range used.Remote {
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

	for len(frontier) > 0 {
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
				compositeUses := parseCompositeActionUses(metadataDir, parentIdentity)
				recordLocal(compositeUses.Local)
				for _, cu := range compositeUses.Remote {
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
	return discovered, localUses
}

func refKey(owner, repo, ref string) string {
	return owner + "/" + repo + "@" + ref
}
