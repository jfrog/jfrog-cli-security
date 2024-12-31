package swift

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	// VersionForMainModule - We don't have information in swift on the current package, or main module, we only have information on its
	// dependencies.
	VersionForMainModule = "0.0.0"
)

type Dependencies struct {
	Name         string          `json:"url,omitempty"`
	Version      string          `json:"version,omitempty"`
	Dependencies []*Dependencies `json:"dependencies,omitempty"`
}

func GetTechDependencyLocation(directDependencyName, directDependencyVersion string, descriptorPaths ...string) ([]*sarif.Location, error) {
	var swiftPositions []*sarif.Location
	for _, descriptorPath := range descriptorPaths {
		path.Clean(descriptorPath)
		if !strings.HasSuffix(descriptorPath, "Package.swift") {
			log.Logger.Warn("Cannot support other files besides Package.swift: %s", descriptorPath)
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

func FixTechDependency(dependencyName, dependencyVersion, fixVersion string, descriptorPaths ...string) error {
	for _, descriptorPath := range descriptorPaths {
		path.Clean(descriptorPath)
		if !strings.HasSuffix(descriptorPath, "Package.swift") {
			log.Logger.Warn("Cannot support other files besides Package.swift: %s", descriptorPath)
			continue
		}
		data, err := os.ReadFile(descriptorPath)
		var newLines []string
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		foundDependency := false
		var tempIndex int
		for index, line := range lines {
			if strings.Contains(line, dependencyName) {
				foundDependency = true
				tempIndex = index
			}
			// This means we are in a new dependency (we cannot find dependency name and version together)
			//nolint:gocritic
			if index > tempIndex && foundDependency && strings.Contains(line, ".package") {
				foundDependency = false
			} else if foundDependency && strings.Contains(line, dependencyVersion) {
				newLine := strings.Replace(line, dependencyVersion, fixVersion, 1)
				newLines = append(newLines, newLine)
				foundDependency = false
			} else {
				newLines = append(newLines, line)
			}
		}
		output := strings.Join(newLines, "\n")
		err = os.WriteFile(descriptorPath, []byte(output), 0644)
		if err != nil {
			return fmt.Errorf("failed to write file: %v", err)
		}
	}
	return nil
}

func extractNameFromSwiftRepo(name string) string {
	name = strings.TrimSuffix(name, ".git")
	name = strings.TrimPrefix(name, "https://")
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

func GetMainPackageName(currentDir string) (string, error) {
	file, err := os.Open(path.Join(currentDir, "Package.swift"))
	if err != nil {
		fmt.Println("Error opening file:", err)
		return "", err
	}
	defer file.Close()

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

func BuildDependencyTree(params utils.AuditParams) (dependencyTree []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
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
		Id:    techutils.Swift.GetPackageTypeId() + packageInfo,
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
	pkgName := strings.Split(strings.TrimPrefix(currNode.Id, techutils.Swift.GetPackageTypeId()), ":")[0]
	currDepChildren := dependenciesGraph[pkgName]
	for _, childName := range currDepChildren {
		fullChildName := fmt.Sprintf("%s:%s", childName, versionMap[childName])
		childNode := &xrayUtils.GraphNode{
			Id:     techutils.Swift.GetPackageTypeId() + fullChildName,
			Nodes:  []*xrayUtils.GraphNode{},
			Parent: currNode,
		}
		currNode.Nodes = append(currNode.Nodes, childNode)
		parseSwiftDependenciesList(childNode, dependenciesGraph, versionMap, uniqueDepsSet)
	}
}
