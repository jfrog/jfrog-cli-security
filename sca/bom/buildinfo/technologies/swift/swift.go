package swift

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jfrog/gofrog/datastructures"
	version2 "github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

const (
	// VersionForMainModule - We don't have information in swift on the current package, or main module, we only have information on its
	// dependencies.
	VersionForMainModule      = "0.0.0"
	VERSION_SYNTAX_TYPE_INDEX = 1
	EXACT_VERSION_INDEX       = 2
	FROM_VERSION_INDEX        = 3
	START_RANGE_INDEX         = 4
	END_RANGE_INDEX           = 5
)

type Dependencies struct {
	Name         string          `json:"url,omitempty"`
	Version      string          `json:"version,omitempty"`
	Dependencies []*Dependencies `json:"dependencies,omitempty"`
}

func GetTechDependencyLocation(directDependencyName, directDependencyVersion string, descriptorPaths ...string) ([]*sarif.Location, error) {
	var swiftPositions []*sarif.Location
	for _, descriptorPath := range descriptorPaths {
		descriptorPath = filepath.Clean(descriptorPath)
		if !strings.HasSuffix(descriptorPath, "Package.swift") {
			log.Warn("Cannot support other files besides Package.swift: %s", descriptorPath)
			continue
		}
		data, err := os.ReadFile(descriptorPath)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		var startLine, startCol int
		foundDependency := false
		var tempIndex int
		for i, line := range lines {
			foundDependency, tempIndex, startLine, startCol = parseSwiftLine(line, directDependencyName, directDependencyVersion, descriptorPath, i, tempIndex, startLine, startCol, lines, foundDependency, &swiftPositions)
		}
	}
	return swiftPositions, nil
}

func parseSwiftLine(line, directDependencyName, directDependencyVersion, descriptorPath string, i, tempIndex, startLine, startCol int, lines []string, foundDependency bool, swiftPositions *[]*sarif.Location) (bool, int, int, int) {
	if strings.Contains(line, directDependencyName) {
		startLine = i
		startCol = strings.Index(line, directDependencyName)
		foundDependency = true
		tempIndex = i
	}
	// This means we are in a new dependency (we cannot find dependency name and version together)
	if i > tempIndex && foundDependency && strings.Contains(line, ".package") {
		foundDependency = false
	} else if foundDependency && strings.Contains(line, directDependencyVersion) {
		endLine := i
		endCol := strings.Index(line, directDependencyVersion) + len(directDependencyVersion) + 1
		var snippet string
		// if the tech dependency is a one-liner
		if endLine == startLine {
			snippet = lines[startLine][startCol:endCol]
			// else it is more than one line, so we need to parse all lines
		} else {
			for snippetLine := 0; snippetLine < endLine-startLine+1; snippetLine++ {
				switch snippetLine {
				case 0:
					snippet += "\n" + lines[snippetLine][startLine:]
				case endLine - startLine:
					snippet += "\n" + lines[snippetLine][:endCol]
				default:
					snippet += "\n" + lines[snippetLine]
				}
			}
		}
		*swiftPositions = append(*swiftPositions, sarifutils.CreateLocation(descriptorPath, startLine, endLine, startCol, endCol, snippet))
		foundDependency = false
	}
	return foundDependency, tempIndex, startLine, startCol
}

func handleNonRangeMatches(match, name, fixVersion string, index int, submatches []string) string {
	log.Debug("Fixing dependency", name, "from version", submatches[index], "to", fixVersion)
	return strings.Replace(match, submatches[index], fixVersion, 1)
}

func handleRangeMatches(match, name, fixVersion string, submatches []string) string {
	startVersion := submatches[START_RANGE_INDEX]
	endVersion := submatches[END_RANGE_INDEX]
	if version2.NewVersion(fixVersion).Compare(startVersion) < 1 && version2.NewVersion(fixVersion).Compare(endVersion) == 1 {
		// Replace the start of the range with `fixVersion`
		log.Debug("Fixing dependency", name, "from start version", startVersion, "to", fixVersion)
		return strings.Replace(match, startVersion, fixVersion, 1)
	}
	return match
}

func updateDependency(content, name, version, fixVersion string) string {
	urlPattern := `(?:https://|http://|sso://)?` + regexp.QuoteMeta(strings.TrimSuffix(name, ".git")) + `(?:\.git)?`
	pattern := `\.package\(url:\s*"` + urlPattern + `",\s*(exact:\s*"(` + version + `)"|from:\s*"(` + version + `)"|"([\d\.]+)"\.\.\s*<?\s*"([\d\.]+)")\)`
	re := regexp.MustCompile(pattern)
	result := re.ReplaceAllStringFunc(content, func(match string) string {
		submatches := re.FindStringSubmatch(match)
		if len(submatches) == 0 {
			return match
		}

		// Handle exact match
		if len(submatches) > VERSION_SYNTAX_TYPE_INDEX && strings.Contains(submatches[VERSION_SYNTAX_TYPE_INDEX], "exact") {
			return handleNonRangeMatches(match, name, fixVersion, EXACT_VERSION_INDEX, submatches)
		}

		// Handle from match
		if len(submatches) > VERSION_SYNTAX_TYPE_INDEX && strings.Contains(submatches[VERSION_SYNTAX_TYPE_INDEX], "from") {
			return handleNonRangeMatches(match, name, fixVersion, FROM_VERSION_INDEX, submatches)
		}

		// Handle range case
		if len(submatches) > 5 && submatches[START_RANGE_INDEX] != "" && submatches[END_RANGE_INDEX] != "" {
			return handleRangeMatches(match, name, fixVersion, submatches)
		}
		return match
	})
	return result
}

func FixTechDependency(dependencyName, dependencyVersion, fixVersion string, descriptorPaths ...string) error {
	for _, descriptorPath := range descriptorPaths {
		descriptorPath = filepath.Clean(descriptorPath)
		if !strings.HasSuffix(descriptorPath, "Package.swift") {
			log.Warn("Cannot support other files besides Package.swift: ", descriptorPath)
			continue
		}
		data, err := os.ReadFile(descriptorPath)
		if err != nil {
			log.Warn("Error reading file: ", descriptorPath, err)
			continue
		}
		updatedContent := updateDependency(string(data), dependencyName, dependencyVersion, fixVersion)
		if strings.Compare(string(data), updatedContent) != 0 {
			if err = os.WriteFile(descriptorPath, []byte(updatedContent), 0644); err != nil { // #nosec G703 -- descriptorPath is sanitized via filepath.Clean and validated via suffix check
				return fmt.Errorf("failed to write file: %v", err)
			}
			currentDir, err := coreutils.GetWorkingDirectory()
			if err != nil {
				return fmt.Errorf("could not run swift build due to %s", err)
			}
			_, exePath, err := getSwiftVersionAndExecPath()
			if err != nil {
				return fmt.Errorf("could not run swift build due to %s", err)
			}
			if _, err = runSwiftCmd(exePath, currentDir, []string{"build"}); err != nil {
				return fmt.Errorf("could not run swift build due to %s", err)
			}
		} else {
			log.Debug("No fixes were done in file", descriptorPath)
		}
	}
	return nil
}

func extractNameFromSwiftRepo(name string) string {
	name = strings.TrimSuffix(name, ".git")
	name = strings.TrimPrefix(name, "https://")
	// jfrog-ignore - false positive, not used for communication
	name = strings.TrimPrefix(name, "http://")
	name = strings.TrimPrefix(name, "sso://")
	return name
}

func GetSwiftDependenciesGraph(data *Dependencies, dependencyMap map[string][]string, versionMap map[string]string) {
	data.Name = extractNameFromSwiftRepo(data.Name)
	_, ok := dependencyMap[data.Name]
	if !ok {
		dependencyMap[data.Name] = []string{}
		versionMap[data.Name] = data.Version
	}
	for _, dependency := range data.Dependencies {
		dependency.Name = extractNameFromSwiftRepo(dependency.Name)
		dependencyMap[data.Name] = append(dependencyMap[data.Name], dependency.Name)
		GetSwiftDependenciesGraph(dependency, dependencyMap, versionMap)
	}
}

func GetDependenciesData(exePath, currentDir string) (*Dependencies, error) {
	result, err := runSwiftCmd(exePath, currentDir, []string{"package", "show-dependencies", "--format", "json"})
	if err != nil {
		return nil, err
	}
	var data *Dependencies
	err = json.Unmarshal(result, &data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func GetMainPackageName(currentDir string) (name string, err error) {
	file, err := os.Open(path.Join(currentDir, "Package.swift"))
	if err != nil {
		fmt.Println("Error opening file:", err)
		return "", err
	}
	defer func() {
		err = errors.Join(err, file.Close())
	}()

	re := regexp.MustCompile(`name:\s*"([^"]+)"`)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if len(matches) > 1 {
			return matches[1], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", nil
}

func BuildDependencyTree(params technologies.BuildInfoBomGeneratorParams) (dependencyTree []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	currentDir, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return nil, nil, err
	}
	packageName, err := GetMainPackageName(currentDir)
	if err != nil {
		log.Warn("Failed to get package name from Package.swift file")
		packageName = filepath.Base(currentDir)
	}

	packageInfo := fmt.Sprintf("%s:%s", packageName, VersionForMainModule)
	version, exePath, err := getSwiftVersionAndExecPath()
	if err != nil {
		err = fmt.Errorf("failed while retrieving swift path: %s", err.Error())
		return
	}
	log.Debug("Swift version: %s", version.GetVersion())
	// Calculate pod dependencies
	data, err := GetDependenciesData(exePath, currentDir)
	if err != nil {
		return nil, nil, err
	}
	uniqueDepsSet := datastructures.MakeSet[string]()
	dependencyMap := make(map[string][]string)
	versionMap := make(map[string]string)
	data.Name = packageName
	data.Version = VersionForMainModule
	GetSwiftDependenciesGraph(data, dependencyMap, versionMap)
	for key := range dependencyMap {
		if key != packageName {
			dependencyMap[packageName] = append(dependencyMap[packageName], key)
		}
	}
	versionMap[packageName] = VersionForMainModule
	rootNode := &xrayUtils.GraphNode{
		Id:    techutils.Swift.GetXrayPackageTypeId() + packageInfo,
		Nodes: []*xrayUtils.GraphNode{},
	}
	// Parse the dependencies into Xray dependency tree format
	parseSwiftDependenciesList(rootNode, dependencyMap, versionMap, uniqueDepsSet)
	dependencyTree = []*xrayUtils.GraphNode{rootNode}
	uniqueDeps = uniqueDepsSet.ToSlice()
	return
}

// Parse the dependencies into a Xray dependency tree format
func parseSwiftDependenciesList(currNode *xrayUtils.GraphNode, dependenciesGraph map[string][]string, versionMap map[string]string, uniqueDepsSet *datastructures.Set[string]) {
	if currNode.NodeHasLoop() {
		return
	}
	uniqueDepsSet.Add(currNode.Id)
	pkgName := strings.Split(strings.TrimPrefix(currNode.Id, techutils.Swift.GetXrayPackageTypeId()), ":")[0]
	currDepChildren := dependenciesGraph[pkgName]
	for _, childName := range currDepChildren {
		fullChildName := fmt.Sprintf("%s:%s", childName, versionMap[childName])
		childNode := &xrayUtils.GraphNode{
			Id:     techutils.Swift.GetXrayPackageTypeId() + fullChildName,
			Nodes:  []*xrayUtils.GraphNode{},
			Parent: currNode,
		}
		currNode.Nodes = append(currNode.Nodes, childNode)
		parseSwiftDependenciesList(childNode, dependenciesGraph, versionMap, uniqueDepsSet)
	}
}
