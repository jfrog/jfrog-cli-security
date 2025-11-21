package gem

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/jfrog/gofrog/io"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
)

const (
	internalPackagePrefix = "rubygems:"
	rubyV2                = "2.6.0"
	jsonGemPrefix         = "rubygems://"
	gemVirtualRootID      = "root"
	stateSearchGEM        = iota
	stateSearchSpecsKeyword
	stateInSpecsSection
)

var sectionTerminators = map[string]bool{
	"DEPENDENCIES":  true,
	"PLATFORMS":     true,
	"RUBY VERSION":  true,
	"BUNDLED WITH":  true,
	"GIT":           true,
	"PATH":          true,
	"PLUGIN SOURCE": true,
}

type GemDep struct {
	Ref    string `json:"ref"`
	Direct bool   `json:"direct"`
}

type GemRef struct {
	Ref          string            `json:"ref"`
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Dependencies map[string]GemDep `json:"dependencies"`
	node         *xrayUtils.GraphNode
}

// NodeName returns the reference string of the gem, used as its ID in the graph.
func (gr *GemRef) NodeName() string { return gr.Ref }

func (gr *GemRef) Node(children ...*xrayUtils.GraphNode) *xrayUtils.GraphNode {
	if gr.node == nil {
		gr.node = &xrayUtils.GraphNode{Id: gr.NodeName()}
	}
	gr.node.Nodes = children
	return gr.node
}

// GemGraphInput represents the top-level structure for unmarshalling the gem dependency graph.
type GemGraphInput struct {
	Graph GemGraph `json:"graph"`
}

type GemGraph struct {
	Nodes map[string]GemRef `json:"nodes"`
}

type internalGemDep struct{ Name, Constraint string }

type internalGemRef struct {
	Ref, Name, Version string
	Dependencies       map[string]internalGemDep
}

func BuildDependencyTree(params technologies.BuildInfoBomGeneratorParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	currentDir, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return
	}
	gemExecPath, err := getRubyExecPath()
	if err != nil {
		return
	}
	return calculateDependencies(gemExecPath, currentDir, params)
}

// getRubyExecPath checks for Ruby and Bundle, validates Ruby version, and returns bundle path.
func getRubyExecPath() (bundleExecPath string, err error) {
	rubyPath, err := exec.LookPath("ruby")
	if err != nil {
		return "", fmt.Errorf("could not find 'ruby' executable in PATH: %w", err)
	}

	bundleExecPath, err = exec.LookPath("bundle")
	if err != nil {
		return "", fmt.Errorf("could not find 'bundle' executable in PATH: %w", err)
	}

	output, err := getGemCmd(rubyPath, "", "--version").RunWithOutput()
	if err != nil {
		return "", fmt.Errorf("failed to execute 'ruby --version': %w", err)
	}

	versionStr := string(output)
	fields := strings.Fields(versionStr)
	if len(fields) < 2 {
		return "", fmt.Errorf("unexpected ruby version output: %s", versionStr)
	}
	actualVersion := fields[1]
	log.Debug("Ruby version:", actualVersion)

	// Extract just major.minor from actual version and required version
	actualMajor, actualMinor, err := parseMajorMinor(actualVersion)
	if err != nil {
		return "", err
	}

	requiredMajor, requiredMinor, err := parseMajorMinor(rubyV2)
	if err != nil {
		return "", err
	}

	if actualMajor < requiredMajor || (actualMajor == requiredMajor && actualMinor < requiredMinor) {
		return "", fmt.Errorf(
			"ruby dependency tree building requires ruby %s or higher; current version: %s",
			rubyV2, actualVersion,
		)
	}

	return bundleExecPath, nil
}
func getGemCmd(execPath, workingDir, cmd string, args ...string) *io.Command {
	command := io.NewCommand(execPath, cmd, args)
	command.Dir = workingDir
	return command
}

// calculateDependencies orchestrates the generation and parsing of Gemfile.lock to build the dependency graph.
// It first runs 'bundle lock' to ensure Gemfile.lock is up-to-date, then parses the lock file,
//
//	dependencyTrees: A slice of top-level dependency nodes.
//	uniqueDeps: A slice of unique dependency IDs found in the graph.
func calculateDependencies(bundleExecPath, workingDir string, _ technologies.BuildInfoBomGeneratorParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	log.Debug("Ensuring Gemfile.lock is up to date using 'bundle lock'...")
	if _, err = getGemCmd(bundleExecPath, workingDir, "lock").RunWithOutput(); err != nil {
		err = fmt.Errorf("failed to execute 'bundle lock': %w. Ensure Gemfile is present and bundle can run", err)
		return
	}

	lockFilePath := filepath.Join(workingDir, "Gemfile.lock")
	if _, statErr := os.Stat(lockFilePath); os.IsNotExist(statErr) {
		err = fmt.Errorf("gemfile.lock not found at '%s' after running 'bundle lock'", lockFilePath)
		return
	}
	gemInput, err := parseGemfileLockDeps(lockFilePath)
	if err != nil {
		err = fmt.Errorf("error processing Gemfile.lock: %w", err)
		return
	}

	if gemInput == nil || len(gemInput.Graph.Nodes) == 0 {
		log.Debug("No gem dependencies found after parsing Gemfile.lock.")
		return []*xrayUtils.GraphNode{}, []string{}, nil
	}

	projectRootNode := buildFullGemDependencyGraph(*gemInput, workingDir)

	if projectRootNode != nil {
		dependencyTrees = projectRootNode.Nodes
	}

	if dependencyTrees == nil {
		dependencyTrees = []*xrayUtils.GraphNode{}
	}

	uniqueDeps = calculateUniqueDependencies(dependencyTrees)
	log.Debug("Calculated dependency trees (children of root): %d trees found.", len(dependencyTrees))

	return
}

// parseLockfileToInternalData parses a Gemfile.lock file line by line to extract gem specifications and their dependencies.
func parseLockfileToInternalData(lockFilePath string) (
	orderedGems []*internalGemRef,
	resolvedVersions map[string]string,
	err error,
) {
	file, ioErr := os.Open(lockFilePath)
	if ioErr != nil {
		return nil, nil, fmt.Errorf("opening lockfile %s: %w", lockFilePath, ioErr)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("closing lockfile %s: %w", lockFilePath, cerr))
		}
	}()

	scanner := bufio.NewScanner(file)

	if !advanceToSpecs(scanner) {
		log.Debug("Could not find 'specs:' section in Gemfile.lock. Assuming no dependencies.")
		return []*internalGemRef{}, make(map[string]string), nil

	}

	orderedGems, resolvedVersions = parseSpecsSection(scanner)

	if scanErr := scanner.Err(); scanErr != nil {
		return nil, nil, fmt.Errorf("error scanning lockfile: %w", scanErr)
	}
	log.Debug("Finished parsing the Gemfile.lock.")
	return orderedGems, resolvedVersions, nil
}

// advanceToSpecs moves the scanner to the line immediately following the "specs:" heading.
// It returns true if the section is found, and false otherwise.
func advanceToSpecs(scanner *bufio.Scanner) bool {
	foundGemBlock := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !foundGemBlock {
			if line == "GEM" {
				foundGemBlock = true
			}
			continue
		}
		if line == "specs:" {
			return true
		}
	}
	return false
}

// parseSpecsSection processes the lines within the "specs:" block of the lockfile.
// It uses indentation levels to distinguish between gems and their dependencies.
func parseSpecsSection(scanner *bufio.Scanner) (
	orderedGems []*internalGemRef,
	resolvedVersions map[string]string,
) {
	orderedGems = []*internalGemRef{}
	resolvedVersions = make(map[string]string)
	var currentGem *internalGemRef

	for scanner.Scan() {
		line := scanner.Text()
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" {
			currentGem = nil
			continue
		}

		if sectionTerminators[trimmedLine] {
			break
		}

		indentation := countLeadingSpaces(line)

		// The Gemfile.lock format uses indentation to define structure.
		// A parent gem is indented by 4 spaces, and its dependencies are indented by 6.
		switch indentation {
		case 4:
			parts := strings.SplitN(trimmedLine, " ", 2)
			if len(parts) == 2 {
				name, version := parts[0], strings.Trim(parts[1], "()")

				ref := internalPackagePrefix + name + ":" + version
				currentGem = &internalGemRef{
					Ref:          ref,
					Name:         name,
					Version:      version,
					Dependencies: make(map[string]internalGemDep),
				}
				orderedGems = append(orderedGems, currentGem)
				resolvedVersions[name] = version
			} else {

				currentGem = nil
			}
		case 6:
			if currentGem == nil {
				continue
			}
			depParts := strings.SplitN(trimmedLine, " ", 2)
			if len(depParts) > 0 && depParts[0] != "" {
				depName := depParts[0]
				depConstraint := ""
				if len(depParts) > 1 {
					depConstraint = strings.Trim(depParts[1], "()")
				}
				currentGem.Dependencies[depName] = internalGemDep{Name: depName, Constraint: depConstraint}
			}
		default:
			currentGem = nil
		}
	}

	return orderedGems, resolvedVersions
}

// countLeadingSpaces returns the number of leading space characters in a string.
func countLeadingSpaces(s string) int {
	for i, r := range s {
		if r != ' ' {
			return i
		}
	}
	return len(s)
}

// parseGemfileLockDeps takes the path to a Gemfile.lock, parses it using parseLockfileToInternalData,
// and then transforms the parsed data into a JSON conforming to the GemGraphInput structure.
// This JSON is used before building the final Xray graph.
func parseGemfileLockDeps(lockFilePath string) (*GemGraphInput, error) {
	orderedInternalGems, resolvedVersions, err := parseLockfileToInternalData(lockFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Gemfile.lock data: %w", err)
	}

	gemRefMap := make(map[string]GemRef, len(orderedInternalGems))
	for _, igem := range orderedInternalGems {
		dependenciesForGemRef := make(map[string]GemDep, len(igem.Dependencies))
		for depNameKey, internalDep := range igem.Dependencies {
			resolvedDepVersion, found := resolvedVersions[internalDep.Name]
			if !found {
				log.Debug("Could not find resolved version for dependency '%s', skipping it.", internalDep.Name)
				continue
			}
			depRefString := jsonGemPrefix + internalDep.Name + ":" + resolvedDepVersion
			dependenciesForGemRef[depNameKey] = GemDep{Ref: depRefString, Direct: true}
		}

		publicRef := jsonGemPrefix + igem.Name + ":" + igem.Version
		gemRefMap[publicRef] = GemRef{
			Ref:          publicRef,
			Name:         igem.Name,
			Version:      igem.Version,
			Dependencies: dependenciesForGemRef,
		}
	}

	outputStructure := GemGraphInput{Graph: GemGraph{Nodes: gemRefMap}}

	return &outputStructure, nil
}

// parseGemDependencyGraphRecursive recursively builds a single branch of the dependency graph.
func parseGemDependencyGraphRecursive(id string, graph map[string]GemRef, visitedNodes map[string]*xrayUtils.GraphNode) *xrayUtils.GraphNode {
	if node, ok := visitedNodes[id]; ok {
		return node
	}
	gemRef, ok := graph[id]
	if !ok {
		log.Debug("Warning: Gem with ID '%s' not found in graph map. Creating as leaf node.", id)
		leafNode := &xrayUtils.GraphNode{Id: id, Nodes: []*xrayUtils.GraphNode{}}
		visitedNodes[id] = leafNode
		return leafNode
	}
	childrenNodes := make([]*xrayUtils.GraphNode, 0)
	for _, dep := range gemRef.Dependencies {
		if !dep.Direct {
			continue
		}
		parsedNode := parseGemDependencyGraphRecursive(dep.Ref, graph, visitedNodes)
		if parsedNode != nil {
			childrenNodes = append(childrenNodes, parsedNode)
		}
	}
	resultNode := gemRef.Node(childrenNodes...)
	visitedNodes[id] = resultNode
	return resultNode
}

// buildFullGemDependencyGraph constructs the complete dependency graph from the GemGraphInput.
func buildFullGemDependencyGraph(graphInput GemGraphInput, workingDir string) *xrayUtils.GraphNode {
	projectName := filepath.Base(workingDir)
	visitedNodes := make(map[string]*xrayUtils.GraphNode)

	if len(graphInput.Graph.Nodes) == 0 {
		log.Debug("No nodes provided in graphInput to build dependency graph.")
		return &xrayUtils.GraphNode{Id: projectName, Nodes: []*xrayUtils.GraphNode{}}
	}

	var rootChildrenNodes []*xrayUtils.GraphNode
	allDepRefs := make(map[string]bool)
	for _, gemRef := range graphInput.Graph.Nodes {
		for _, depLink := range gemRef.Dependencies {
			allDepRefs[depLink.Ref] = true
		}
	}
	for gemID := range graphInput.Graph.Nodes {
		if !allDepRefs[gemID] {
			parsedNode := parseGemDependencyGraphRecursive(gemID, graphInput.Graph.Nodes, visitedNodes)
			if parsedNode != nil {
				rootChildrenNodes = append(rootChildrenNodes, parsedNode)
			}
		}
	}
	return &xrayUtils.GraphNode{Id: projectName, Nodes: rootChildrenNodes}
}

func parseMajorMinor(version string) (major, minor int, err error) {
	re := regexp.MustCompile(`^(\d+)\.(\d+)`)
	matches := re.FindStringSubmatch(version)
	if len(matches) < 3 {
		return 0, 0, fmt.Errorf("invalid version format: %q", version)
	}
	major, err = strconv.Atoi(matches[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid major version in %q: %w", version, err)
	}
	minor, err = strconv.Atoi(matches[2])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid minor version in %q: %w", version, err)
	}
	return major, minor, nil
}

func calculateUniqueDependencies(trees []*xrayUtils.GraphNode) []string {
	// Using a map as a set to store unique dependency IDs
	uniqueIDsSet := make(map[string]struct{})
	var stack []*xrayUtils.GraphNode
	if len(trees) > 0 {
		for i := len(trees) - 1; i >= 0; i-- {
			if trees[i] != nil {
				stack = append(stack, trees[i])
			}
		}
	}
	visitedInThisTraversal := make(map[*xrayUtils.GraphNode]bool)
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if node == nil || visitedInThisTraversal[node] {
			continue
		}
		visitedInThisTraversal[node] = true
		if node.Id != "" {
			if node.Id == gemVirtualRootID {
				log.Debug("Skipping virtual root ID ('%s') found within dependency trees.", gemVirtualRootID)
			} else {
				uniqueIDsSet[node.Id] = struct{}{}
			}
		} else {
			log.Debug("Encountered a graph node with an empty ID during unique dependency calculation.")
		}
		if node.Nodes != nil {
			for i := len(node.Nodes) - 1; i >= 0; i-- {
				child := node.Nodes[i]
				if child != nil {
					stack = append(stack, child)
				}
			}
		}
	}
	result := make([]string, 0, len(uniqueIDsSet))
	for id := range uniqueIDsSet {
		result = append(result, id)
	}

	return result
}
