package xray

import (
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

const maxUniqueAppearances = 10

type DepTreeNode struct {
	Classifier *string   `json:"classifier"`
	Types      *[]string `json:"types"`
	Children   []string  `json:"children"`
}

func toNodeTypesMap(depMap map[string]DepTreeNode) map[string]*DepTreeNode {
	mapOfTypes := map[string]*DepTreeNode{}
	for nodId, value := range depMap {
		mapOfTypes[nodId] = nil
		if value.Types != nil || value.Classifier != nil {
			mapOfTypes[nodId] = &DepTreeNode{
				Classifier: value.Classifier,
				Types:      value.Types,
			}
		}
	}
	return mapOfTypes
}

func BuildXrayDependencyTree(treeHelper map[string]DepTreeNode, nodeId string) (*xrayUtils.GraphNode, map[string]*DepTreeNode) {
	rootNode := &xrayUtils.GraphNode{
		Id:    nodeId,
		Nodes: []*xrayUtils.GraphNode{},
	}
	dependencyAppearances := map[string]int8{}
	populateXrayDependencyTree(rootNode, treeHelper, dependencyAppearances)
	return rootNode, toNodeTypesMap(treeHelper)
}

func populateXrayDependencyTree(currNode *xrayUtils.GraphNode, treeHelper map[string]DepTreeNode, dependencyAppearances map[string]int8) {
	dependencyAppearances[currNode.Id]++
	if _, ok := treeHelper[currNode.Id]; !ok {
		treeHelper[currNode.Id] = DepTreeNode{}
	}
	// Recursively create & append all node's dependencies.
	for _, childDepId := range treeHelper[currNode.Id].Children {
		childNode := &xrayUtils.GraphNode{
			Id:         childDepId,
			Nodes:      []*xrayUtils.GraphNode{},
			Parent:     currNode,
			Types:      treeHelper[childDepId].Types,
			Classifier: treeHelper[childDepId].Classifier,
		}
		if dependencyAppearances[childDepId] >= maxUniqueAppearances || childNode.NodeHasLoop() {
			continue
		}
		currNode.Nodes = append(currNode.Nodes, childNode)
		populateXrayDependencyTree(childNode, treeHelper, dependencyAppearances)
	}
}
