package conan

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"

	"github.com/jfrog/gofrog/io"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"

	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/jfrog-cli-security/utils"
)

const (
	PackageTypeIdentifier = "conan://"
)

func BuildDependencyTree(params utils.AuditParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	// Prepare
	currentDir, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return
	}
	conanExecPath, err := getConanExecPath()
	if err != nil {
		return
	}
	// Build
	return calculateDependencies(conanExecPath, currentDir, params)
}

func getConanExecPath() (conanExecPath string, err error) {
	if conanExecPath, err = exec.LookPath("conan"); errorutils.CheckError(err) != nil {
		return
	}
	if conanExecPath == "" {
		err = errors.New("could not find the 'conan' executable in the system PATH")
		return
	}
	log.Debug("Using Conan executable:", conanExecPath)
	// Validate conan version command
	version, err := getConanCmd(conanExecPath, "", "--version").RunWithOutput()
	if errorutils.CheckError(err) != nil {
		return
	}
	log.Debug("Conan version:", string(version))
	return
}

func getConanCmd(conanExecPath, workingDir, cmd string, args ...string) *io.Command {
	command := io.NewCommand(conanExecPath, cmd, args)
	command.Dir = workingDir
	return command
}

type conanDep struct {
	Ref    string `json:"ref"`
	Direct bool   `json:"direct"`
}

type conanRef struct {
	Ref          string              `json:"ref"`
	Name         string              `json:"name"`
	Version      string              `json:"version"`
	Dependencies map[string]conanDep `json:"dependencies"`
	node         *xrayUtils.GraphNode
}

func (cr *conanRef) Node() *xrayUtils.GraphNode {
	if cr.node == nil {
		cr.node = &xrayUtils.GraphNode{Id: cr.NodeName()}
	}
	return cr.node
}

func (cr *conanRef) NodeName() string {
	return PackageTypeIdentifier + cr.Name + ":" + cr.Version
}

type conanGraphOutput struct {
	Graph struct {
		Nodes map[string]conanRef `json:"nodes"`
	} `json:"graph"`
}

func calculateDependencies(executablePath, workingDir string, params utils.AuditParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	graphInfo := append([]string{"info", ".", "--format=json"}, params.Args()...)
	conanGraphInfoContent, err := getConanCmd(executablePath, workingDir, "graph", graphInfo...).RunWithOutput()
	if err != nil {
		return
	}

	log.Debug("Conan 'graph info' command output:\n", string(conanGraphInfoContent))
	var output conanGraphOutput
	if err = json.Unmarshal(conanGraphInfoContent, &output); err != nil {
		return
	}

	rootNode, err := parseConanDependencyGraph("0", output.Graph.Nodes)
	if err != nil {
		return
	}
	dependencyTrees = append(dependencyTrees, rootNode)

	for id, dep := range output.Graph.Nodes {
		if id == "0" {
			continue
		}
		uniqueDeps = append(uniqueDeps, dep.NodeName())
	}

	return
}

func parseConanDependencyGraph(id string, graph map[string]conanRef) (*xrayUtils.GraphNode, error) {
	var childrenNodes []*xrayUtils.GraphNode
	node, ok := graph[id]
	if !ok {
		return nil, errors.New(fmt.Sprintf("got non-existant node id %s", id))
	}
	for key, dep := range node.Dependencies {
		if !dep.Direct {
			continue
		}
		r, err := parseConanDependencyGraph(key, graph)
		if err != nil {
			return nil, err
		}
		childrenNodes = append(childrenNodes, r)
	}
	if id == "0" {
		return &xrayUtils.GraphNode{Id: "root", Nodes: childrenNodes}, nil
	} else {
		node.Node().Nodes = childrenNodes
		return node.Node(), nil
	}
}
