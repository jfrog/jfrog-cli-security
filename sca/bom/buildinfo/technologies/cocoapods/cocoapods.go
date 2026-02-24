package cocoapods

import (
	"fmt"
	"golang.org/x/exp/slices"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

// VersionForMainModule - We don't have information in cocoapods on the current package, or main module, we only have information on its
// dependencies.
const (
	VersionForMainModule = "0.0.0"
)

var (
	mainDepRegex = regexp.MustCompile(`- ([\w/+.\-]+) \(([\d.]+)\)`)
	subDepRegex  = regexp.MustCompile(`\s{2}- ([\w/+.\-]+)`)
	versionRegex = regexp.MustCompile(`\((\d+(\.\d+){0,2})\)`)
)

func GetTechDependencyLocation(directDependencyName, directDependencyVersion string, descriptorPaths ...string) ([]*sarif.Location, error) {
	var podPositions []*sarif.Location
	for _, descriptorPath := range descriptorPaths {
		path.Clean(descriptorPath)
		if !strings.HasSuffix(descriptorPath, "Podfile") {
			log.Logger.Warn("Cannot support other files besides Podfile: %s", descriptorPath)
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
			foundDependency, tempIndex, startLine, startCol = parsePodLine(line, directDependencyName, directDependencyVersion, descriptorPath, i, tempIndex, startLine, startCol, lines, foundDependency, &podPositions)
		}
	}
	return podPositions, nil
}

func parsePodLine(line, directDependencyName, directDependencyVersion, descriptorPath string, i, tempIndex, startLine, startCol int, lines []string, foundDependency bool, podPositions *[]*sarif.Location) (bool, int, int, int) {
	if strings.Contains(line, directDependencyName) {
		startLine = i
		startCol = strings.Index(line, directDependencyName)
		foundDependency = true
		tempIndex = i
	}
	// This means we are in a new dependency (we cannot find dependency name and version together)
	if i > tempIndex && foundDependency && strings.Contains(line, "pod") {
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
		*podPositions = append(*podPositions, sarifutils.CreateLocation(descriptorPath, startLine, endLine, startCol, endCol, snippet))
		foundDependency = false
	}
	return foundDependency, tempIndex, startLine, startCol
}

func FixTechDependency(dependencyName, dependencyVersion, fixVersion string, descriptorPaths ...string) error {
	for _, descriptorPath := range descriptorPaths {
		path.Clean(descriptorPath)
		if !strings.HasSuffix(descriptorPath, "Podfile") {
			log.Logger.Warn("Cannot support other files besides Podfile: %s", descriptorPath)
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
			if index > tempIndex && foundDependency && strings.Contains(line, "pod") {
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

func GetPodDependenciesGraph(data string) (map[string][]string, map[string]string, []string) {
	var currentMainDep string
	lines := strings.Split(data, "\n")
	dependencyMap := make(map[string][]string, len(lines))
	versionMap := make(map[string]string, len(lines))
	var transitiveDependencies []string
	for _, line := range lines {
		mainDepMatch := mainDepRegex.FindStringSubmatch(line)
		if len(mainDepMatch) == 3 {
			versionMatch := versionRegex.FindStringSubmatch(line)
			currentMainDep = mainDepMatch[1]
			if _, ok := dependencyMap[currentMainDep]; !ok && len(versionMatch) > 1 {
				// New dependency with version found
				dependencyMap[currentMainDep] = []string{}
				versionMap[currentMainDep] = versionMatch[1]
			}
			continue
		}
		subDepMatch := subDepRegex.FindStringSubmatch(line)
		if len(subDepMatch) == 2 && currentMainDep != "" {
			subDependency := subDepMatch[1]
			dependencyMap[currentMainDep] = append(dependencyMap[currentMainDep], subDependency)
			transitiveDependencies = append(transitiveDependencies, subDependency)
		}
	}
	return dependencyMap, versionMap, transitiveDependencies
}

func extractPodsSection(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	content := string(data)
	startIndex := strings.Index(content, "PODS:")
	if startIndex == -1 {
		return "", fmt.Errorf("PODS: section not found")
	}
	subContent := content[startIndex:]
	endIndex := strings.Index(subContent, "DEPENDENCIES:")
	if endIndex == -1 {
		endIndex = strings.Index(subContent, "SPEC REPOS:")
	}
	if endIndex != -1 {
		subContent = subContent[:endIndex]
	}
	return subContent, nil
}

func GetDependenciesData(currentDir string) (string, error) {
	_, err := os.Stat(filepath.Join(currentDir, "Podfile.lock"))
	if err != nil {
		return "", err
	}
	result, err := extractPodsSection(filepath.Join(currentDir, "Podfile.lock"))
	if err != nil {
		return "", err
	}
	return result, nil
}

func BuildDependencyTree(params technologies.BuildInfoBomGeneratorParams) (dependencyTree []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	currentDir, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return nil, nil, err
	}

	packageName := filepath.Base(currentDir)
	packageInfo := fmt.Sprintf("%s:%s", packageName, VersionForMainModule)
	_, _, err = getPodVersionAndExecPath()
	if err != nil {
		err = fmt.Errorf("failed while retrieving pod path: %s", err.Error())
		return
	}
	// Calculate pod dependencies
	data, err := GetDependenciesData(currentDir)
	if err != nil {
		return nil, nil, err
	}
	uniqueDepsSet := datastructures.MakeSet[string]()
	dependenciesGraph, versionMap, transitiveDependencies := GetPodDependenciesGraph(data)
	for key := range dependenciesGraph {
		if key != packageName && !slices.Contains(transitiveDependencies, key) {
			dependenciesGraph[packageName] = append(dependenciesGraph[packageName], key)
		}
	}
	versionMap[packageName] = VersionForMainModule
	rootNode := &xrayUtils.GraphNode{
		Id:    techutils.Cocoapods.GetXrayPackageTypeId() + packageInfo,
		Nodes: []*xrayUtils.GraphNode{},
	}
	// Parse the dependencies into Xray dependency tree format
	parsePodDependenciesList(rootNode, dependenciesGraph, versionMap, uniqueDepsSet)
	dependencyTree = []*xrayUtils.GraphNode{rootNode}
	uniqueDeps = uniqueDepsSet.ToSlice()
	return
}

// Parse the dependencies into a Xray dependency tree format
func parsePodDependenciesList(currNode *xrayUtils.GraphNode, dependenciesGraph map[string][]string, versionMap map[string]string, uniqueDepsSet *datastructures.Set[string]) {
	if currNode.NodeHasLoop() {
		return
	}
	uniqueDepsSet.Add(currNode.Id)
	pkgName := strings.Split(strings.TrimPrefix(currNode.Id, techutils.Cocoapods.GetXrayPackageTypeId()), ":")[0]
	currDepChildren := dependenciesGraph[pkgName]
	for _, childName := range currDepChildren {
		fullChildName := fmt.Sprintf("%s:%s", childName, versionMap[childName])
		childNode := &xrayUtils.GraphNode{
			Id:     techutils.Cocoapods.GetXrayPackageTypeId() + fullChildName,
			Nodes:  []*xrayUtils.GraphNode{},
			Parent: currNode,
		}
		currNode.Nodes = append(currNode.Nodes, childNode)
		parsePodDependenciesList(childNode, dependenciesGraph, versionMap, uniqueDepsSet)
	}
}
