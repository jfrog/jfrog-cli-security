package java

import (
	"encoding/json"
	"os"
	"sort"
	"strings"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

const (
	GavPackageTypeIdentifier = "gav://"
)

func BuildDependencyTree(depTreeParams DepTreeParams, tech techutils.Technology) ([]*xrayUtils.GraphNode, map[string]*xray.DepTreeNode, error) {
	if tech == techutils.Maven {
		return buildMavenDependencyTree(&depTreeParams)
	}
	return buildGradleDependencyTree(&depTreeParams)
}

type DepTreeParams struct {
	UseWrapper              bool
	Server                  *config.ServerDetails
	DepsRepo                string
	IsMavenDepTreeInstalled bool
	IsCurationCmd           bool
	MvnIncludePluginDeps    bool
	CurationCacheFolder     string
	UseIncludedBuilds       bool
}

type DepTreeManager struct {
	server            *config.ServerDetails
	depsRepo          string
	useWrapper        bool
	useIncludedBuilds bool
}

func NewDepTreeManager(params *DepTreeParams) DepTreeManager {
	return DepTreeManager{useWrapper: params.UseWrapper, depsRepo: params.DepsRepo, server: params.Server, useIncludedBuilds: params.UseIncludedBuilds}
}

// The structure of a dependency tree of a module in a Gradle/Maven project, as created by the gradle-dep-tree and maven-dep-tree plugins.
// PluginNodes is populated by maven-dep-tree when -DincludePluginDeps=true is passed; it contains
// transitive dependencies of Maven build plugins that participate in the install lifecycle.
type moduleDepTree struct {
	Root        string                      `json:"root"`
	Nodes       map[string]xray.DepTreeNode `json:"nodes"`
	PluginNodes map[string]xray.DepTreeNode `json:"pluginNodes,omitempty"`
}

// Reads the output files of the gradle-dep-tree and maven-dep-tree plugins and returns them as a slice of GraphNodes.
// It takes the output of the plugin's run (which is a byte representation of a list of paths of the output files, separated by newlines) as input.
// Thin wrapper over getGraphAndPluginDepsFromDepTree for callers that don't need plugin deps.
func getGraphFromDepTree(outputFilePaths string) (depsGraph []*xrayUtils.GraphNode, uniqueDepsMap map[string]*xray.DepTreeNode, err error) {
	depsGraph, uniqueDepsMap, _, _, err = getGraphAndPluginDepsFromDepTree(outputFilePaths)
	return
}

// getGraphAndPluginDepsFromDepTree returns the dependency graph and flat unique-deps map, plus the
// plugin transitive deps emitted under "pluginNodes" when -DincludePluginDeps=true. pluginDepsMap is
// nil when none were collected; pluginNodesPresent is true when the field was emitted (even empty),
// distinguishing "ran, nothing to inject" from "plugin ignored the flag".
func getGraphAndPluginDepsFromDepTree(outputFilePaths string) (depsGraph []*xrayUtils.GraphNode, uniqueDepsMap map[string]*xray.DepTreeNode, pluginDepsMap map[string]*xray.DepTreeNode, pluginNodesPresent bool, err error) {
	modules, err := parseDepTreeFiles(outputFilePaths)
	if err != nil {
		return
	}
	uniqueDepsMap = map[string]*xray.DepTreeNode{}
	for _, module := range modules {
		moduleTree, moduleUniqueDeps := GetModuleTreeAndDependencies(module)
		depsGraph = append(depsGraph, moduleTree)
		for depToAdd, depTypes := range moduleUniqueDeps {
			uniqueDepsMap[depToAdd] = depTypes
		}
		// A non-nil map (including an empty {}) means the plugin emitted the field.
		if module.PluginNodes != nil {
			pluginNodesPresent = true
		}
		for gav, node := range module.PluginNodes {
			if pluginDepsMap == nil {
				pluginDepsMap = map[string]*xray.DepTreeNode{}
			}
			existing, exists := pluginDepsMap[gav]
			if !exists {
				pluginDepsMap[gav] = &xray.DepTreeNode{
					Types:          node.Types,
					Classifier:     node.Classifier,
					Configurations: node.Configurations,
				}
				continue
			}
			// Same GAV in another module: keep the first module's classifier/configurations but
			// union the types so a single-module variant (e.g. test-jar) is still curated.
			existing.Types = mergePluginNodeTypes(existing.Types, node.Types)
		}
	}
	return
}

// mergePluginNodeTypes returns the deduplicated, sorted union of two artifact-type lists, so a
// plugin dep appearing in multiple modules keeps every type variant. Returns nil when both are empty.
func mergePluginNodeTypes(existing, incoming *[]string) *[]string {
	seen := datastructures.MakeSet[string]()
	var merged []string
	for _, src := range []*[]string{existing, incoming} {
		if src == nil {
			continue
		}
		for _, t := range *src {
			if seen.Exists(t) {
				continue
			}
			seen.Add(t)
			merged = append(merged, t)
		}
	}
	if merged == nil {
		return nil
	}
	sort.Strings(merged)
	return &merged
}

// Returns a dependency tree and a flat list of the module's dependencies for the given module
func GetModuleTreeAndDependencies(module *moduleDepTree) (*xrayUtils.GraphNode, map[string]*xray.DepTreeNode) {
	moduleTreeMap := make(map[string]xray.DepTreeNode)
	moduleDeps := module.Nodes
	for depName, dependency := range moduleDeps {
		dependencyId := GavPackageTypeIdentifier + depName
		var childrenList []string
		for _, childName := range dependency.Children {
			childId := GavPackageTypeIdentifier + childName
			childrenList = append(childrenList, childId)
		}

		moduleTreeMap[dependencyId] = xray.DepTreeNode{
			Classifier:     dependency.Classifier,
			Types:          dependency.Types,
			Children:       childrenList,
			Unresolved:     dependency.Unresolved,
			Configurations: dependency.Configurations,
		}
	}
	return xray.BuildXrayDependencyTree(moduleTreeMap, GavPackageTypeIdentifier+module.Root)
}

func parseDepTreeFiles(jsonFilePaths string) ([]*moduleDepTree, error) {
	outputFilePaths := strings.Split(strings.TrimSpace(jsonFilePaths), "\n")
	var modules []*moduleDepTree
	for _, path := range outputFilePaths {
		results, err := parseDepTreeFile(path)
		if err != nil {
			return nil, err
		}
		modules = append(modules, results)
	}
	return modules, nil
}

func parseDepTreeFile(path string) (results *moduleDepTree, err error) {
	// jfrog-ignore: The file is a JSON file that contains the dependency tree of a module in a Gradle/Maven project.
	depTreeJson, err := os.ReadFile(strings.TrimSpace(path))
	if errorutils.CheckError(err) != nil {
		return
	}
	results = &moduleDepTree{}
	err = errorutils.CheckError(json.Unmarshal(depTreeJson, &results))
	return
}

func getArtifactoryAuthFromServer(server *config.ServerDetails) (string, string, error) {
	username, password, err := server.GetAuthenticationCredentials()
	if err != nil {
		return "", "", err
	}
	if username == "" {
		return "", "", errorutils.CheckErrorf("a username is required for authenticating with Artifactory")
	}
	return username, password, nil
}

func (dtm *DepTreeManager) GetDepsRepo() string {
	return dtm.depsRepo
}
