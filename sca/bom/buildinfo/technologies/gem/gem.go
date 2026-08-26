package gem

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/jfrog/gofrog/io"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"gopkg.in/yaml.v3"

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
	artifactoryApiGemsPath = "/api/gems/"
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

// GemrcRegistryConfig holds the Artifactory URL, repo name, and credentials
// parsed from a gemrc source entry.
type GemrcRegistryConfig struct {
	ArtifactoryUrl string
	RepoName       string
	AuthUser       string
	AuthToken      string
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

// GetNativeGemRegistryConfig reads gemrc's ':sources:' list and returns the first
// Artifactory gems source found. Gem has no 'jf ruby-config' command, so this is
// always how it resolves the curation repository.
func GetNativeGemRegistryConfig() (*GemrcRegistryConfig, error) {
	sources, sourcePath, err := readEffectiveGemSources(DefaultGemrcPaths()...)
	if err != nil {
		return nil, err
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("no ':sources:' configured in ~/.gemrc -- run 'gem sources --add <artifactory-gems-url>' " +
			"(see Artifactory's 'Set Me Up' instructions for your Gems repository)")
	}
	for _, source := range sources {
		if cfg, ok := parseArtifactoryGemSourceUrl(source); ok {
			log.Debug(fmt.Sprintf("gem: found Artifactory-shaped source %q in %s", source, sourcePath))
			return cfg, nil
		}
	}
	return nil, fmt.Errorf(
		"none of the sources configured in %s point at an Artifactory Gems repository (expected %q in the URL) -- "+
			"run 'gem sources --add <artifactory-gems-url>' (see Artifactory's 'Set Me Up' instructions for your Gems repository)",
		sourcePath, artifactoryApiGemsPath)
}

// DefaultGemrcPaths returns gemrc file candidates in RubyGems' load order:
// ~/.gemrc, followed by any files listed in GEMRC. A later file's ':sources:' overrides an earlier one.
func DefaultGemrcPaths() []string {
	var paths []string
	if home, homeErr := os.UserHomeDir(); homeErr == nil {
		userGemrc := filepath.Join(home, ".gemrc")
		if _, statErr := os.Stat(userGemrc); statErr == nil {
			paths = append(paths, userGemrc)
		} else {
			configHome := os.Getenv("XDG_CONFIG_HOME")
			if configHome == "" {
				configHome = filepath.Join(home, ".config")
			}
			paths = append(paths, filepath.Join(configHome, "gem", "gemrc"))
		}
	}
	if envGemrc := os.Getenv("GEMRC"); envGemrc != "" {
		separator := ":"
		if runtime.GOOS == "windows" {
			separator = ";"
		}
		for _, path := range strings.Split(envGemrc, separator) {
			if path = strings.TrimSpace(path); path != "" {
				paths = append(paths, path)
			}
		}
	}
	return paths
}

// readEffectiveGemSources returns the ':sources:' list from the last gemrc path
// that defines one. Missing files are skipped, not treated as errors.
func readEffectiveGemSources(paths ...string) (sources []string, sourcePath string, err error) {
	for _, path := range paths {
		data, readErr := os.ReadFile(path) // #nosec G304 -- path comes from DefaultGemrcPaths() (fixed home-relative paths) or the user's own GEMRC env var, not attacker-controlled
		if readErr != nil {
			if os.IsNotExist(readErr) {
				continue
			}
			return nil, "", fmt.Errorf("failed to read %s: %w", path, readErr)
		}
		var raw map[string]any
		if unmarshalErr := yaml.Unmarshal(data, &raw); unmarshalErr != nil {
			return nil, "", fmt.Errorf("failed to parse %s: %w", path, unmarshalErr)
		}
		if list, ok := extractGemSourcesList(raw); ok {
			sources, sourcePath = list, path
		}
	}
	if sourcePath == "" {
		sourcePath = "~/.gemrc"
	}
	return sources, sourcePath, nil
}

// extractGemSourcesList reads the ':sources:' array from a decoded gemrc map.
// RubyGems accepts the key with or without its leading colon, so both are checked.
func extractGemSourcesList(raw map[string]any) ([]string, bool) {
	value, ok := raw[":sources"]
	if !ok {
		value, ok = raw["sources"]
	}
	if !ok {
		return nil, false
	}
	rawList, ok := value.([]any)
	if !ok {
		return nil, false
	}
	sources := make([]string, 0, len(rawList))
	for _, entry := range rawList {
		if s, ok := entry.(string); ok && strings.TrimSpace(s) != "" {
			sources = append(sources, strings.TrimSpace(s))
		}
	}
	return sources, true
}

// parseArtifactoryGemSourceUrl parses a gem source URL shaped like
// https://[user[:token]@]<host>/artifactory/api/gems/<repo>/, extracting the
// Artifactory base URL, repo name, and any embedded credentials.
func parseArtifactoryGemSourceUrl(sourceUrl string) (*GemrcRegistryConfig, bool) {
	parsed, err := url.Parse(strings.TrimSpace(sourceUrl))
	if err != nil || parsed.Host == "" || (!strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https")) {
		return nil, false
	}
	apiGemsIdx := strings.Index(parsed.Path, artifactoryApiGemsPath)
	if apiGemsIdx < 0 {
		return nil, false
	}
	repoName := strings.TrimSuffix(strings.TrimPrefix(parsed.Path[apiGemsIdx:], artifactoryApiGemsPath), "/")
	if slashIdx := strings.Index(repoName, "/"); slashIdx != -1 {
		repoName = repoName[:slashIdx]
	}
	if repoName == "" {
		return nil, false
	}
	cfg := &GemrcRegistryConfig{
		ArtifactoryUrl: fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, parsed.Path[:apiGemsIdx+1]),
		RepoName:       repoName,
	}
	if parsed.User != nil {
		cfg.AuthUser = parsed.User.Username()
		cfg.AuthToken, _ = parsed.User.Password()
	}
	return cfg, true
}
