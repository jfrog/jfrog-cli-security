package swift

import (
	"errors"
	"fmt"
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils"
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
		if !strings.HasSuffix(descriptorPath, "Package.swift") {
			log.Logger.Warn("Cannot support other files besides Package.swift: %s", descriptorPath)
			continue
		}
		data, err := os.ReadFile(descriptorPath)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		var startLine, startCol, endLine, endCol int
		var tempIndex int
		foundDependency := false
		for i, line := range lines {
			if strings.Contains(line, directDependencyName) {
				startLine = i
				startCol = strings.Index(line, directDependencyName)
				foundDependency = true
				tempIndex = i
			}
			if i > tempIndex && foundDependency && strings.Contains(line, ".package") {
				foundDependency = false
			} else if foundDependency && strings.Contains(line, directDependencyVersion) {
				endLine = i
				endCol = len(line)
				var snippet string
				if endLine == startLine {
					snippet = lines[startLine][startCol:endCol]
				} else {
					for snippetLine := 1; snippetLine < endLine-startLine+1; snippetLine++ {
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
				podPositions = append(podPositions, sarifutils.CreateLocation(descriptorPath, startLine, endLine, startCol, endCol, snippet))
				foundDependency = false
			}
		}
	}
	return podPositions, nil
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
		for i, line := range lines {
			if strings.Contains(line, dependencyName) {
				foundDependency = true
			}
			if i > tempIndex && foundDependency && strings.Contains(line, ".package") {
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

func GetPackageName(longPkgName string) string {
	if strings.Contains(longPkgName, "/") {
		splitNameParts := strings.Split(longPkgName, "/")
		longPkgName = splitNameParts[0]
	}
	return longPkgName
}

func GetPodDependenciesGraph(data string) (map[string][]string, map[string]string) {
	var currentMainDep string
	lines := strings.Split(data, "\n")
	dependencyMap := make(map[string][]string, len(lines))
	versionMap := make(map[string]string, len(lines))
	for _, line := range lines {
		line = strings.ReplaceAll(line, "\"", "")
		mainDepMatch := mainDepRegex.FindStringSubmatch(line)
		if len(mainDepMatch) == 3 {
			versionMatch := versionRegex.FindStringSubmatch(line)
			currentMainDep = GetPackageName(mainDepMatch[1])
			_, ok := dependencyMap[currentMainDep]
			if !ok {
				dependencyMap[currentMainDep] = []string{}
				versionMap[currentMainDep] = versionMatch[1]
			}
			continue
		}
		subDepMatch := subDepRegex.FindStringSubmatch(line)
		if len(subDepMatch) == 2 && currentMainDep != "" {
			subDependency := subDepMatch[1]
			if subDependency == GetPackageName(subDependency) {
				dependencyMap[currentMainDep] = append(dependencyMap[currentMainDep], subDependency)
			}
		}
	}
	return dependencyMap, versionMap
}

func extractDepSection(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	content := string(data)
	startIndex := strings.Index(content, "dependencies:")
	if startIndex == -1 {
		return "", fmt.Errorf("dependencies: section not found")
	}
	subContent := content[startIndex:]
	endIndex := strings.Index(subContent, "targets:")
	if endIndex != -1 {
		subContent = subContent[:endIndex]
	}
	return subContent, nil
}

func GetDependenciesData(exePath, currentDir string) (string, error) {
	_, _, err := swift.RunSwiftCmd(exePath, currentDir, []string{"package", "show-dependencies", "--format", "json"})
	if err != nil {
		return "", err
	}
	result, err := extractDepSection(filepath.Join(currentDir, "Package.resolved"))
	if err != nil {
		return "", err
	}
	return result, nil
}

func BuildDependencyTree(params utils.AuditParams) (dependencyTree []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	currentDir, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return nil, nil, err
	}

	clearResolutionServerFunc, err := configPodResolutionServerIfNeeded(params)
	if err != nil {
		err = fmt.Errorf("failed while configuring a resolution server: %s", err.Error())
		return nil, nil, err
	}
	defer func() {
		if clearResolutionServerFunc != nil {
			err = errors.Join(err, clearResolutionServerFunc())
		}
	}()

	packageName := filepath.Base(currentDir)
	packageInfo := fmt.Sprintf("%s:%s", packageName, VersionForMainModule)
	_, podExecutablePath, err := swift.GetSwiftversionAndExecPath()
	if err != nil {
		err = fmt.Errorf("failed while retrieving pod path: %s", err.Error())
		return
	}
	// Calculate pod dependencies
	data, err := GetDependenciesData(podExecutablePath, currentDir)
	if err != nil {
		return nil, nil, err
	}
	uniqueDepsSet := datastructures.MakeSet[string]()
	dependenciesGraph, versionMap := GetPodDependenciesGraph(data)
	for key, _ := range dependenciesGraph {
		if key != packageName {
			dependenciesGraph[packageName] = append(dependenciesGraph[packageName], key)
		}
	}
	versionMap[packageName] = VersionForMainModule
	rootNode := &xrayUtils.GraphNode{
		Id:    utils.SwiftPackageTypeIdentifier + packageInfo,
		Nodes: []*xrayUtils.GraphNode{},
	}
	// Parse the dependencies into Xray dependency tree format
	parsePodDependenciesList(rootNode, dependenciesGraph, versionMap, uniqueDepsSet)
	dependencyTree = []*xrayUtils.GraphNode{rootNode}
	uniqueDeps = uniqueDepsSet.ToSlice()
	return
}

// Generates a .netrc file to configure an Artifactory server as the resolver server.
func configPodResolutionServerIfNeeded(params utils.AuditParams) (clearResolutionServerFunc func() error, err error) {
	// If we don't have an artifactory repo's name we don't need to configure any Artifactory server as resolution server
	if params.DepsRepo() == "" {
		return
	}

	serverDetails, err := params.ServerDetails()
	if err != nil {
		return
	}

	clearResolutionServerFunc, err = swift.SetArtifactoryAsResolutionServer(serverDetails, params.DepsRepo())
	return
}

// Parse the dependencies into an Xray dependency tree format
func parsePodDependenciesList(currNode *xrayUtils.GraphNode, dependenciesGraph map[string][]string, versionMap map[string]string, uniqueDepsSet *datastructures.Set[string]) {
	if currNode.NodeHasLoop() {
		return
	}
	uniqueDepsSet.Add(currNode.Id)
	pkgName := strings.Split(strings.TrimPrefix(currNode.Id, utils.SwiftPackageTypeIdentifier), ":")[0]
	currDepChildren := dependenciesGraph[pkgName]
	for _, childName := range currDepChildren {
		fullChildName := fmt.Sprintf("%s:%s", childName, versionMap[childName])
		childNode := &xrayUtils.GraphNode{
			Id:     utils.SwiftPackageTypeIdentifier + fullChildName,
			Nodes:  []*xrayUtils.GraphNode{},
			Parent: currNode,
		}
		currNode.Nodes = append(currNode.Nodes, childNode)
		parsePodDependenciesList(childNode, dependenciesGraph, versionMap, uniqueDepsSet)
	}
}
