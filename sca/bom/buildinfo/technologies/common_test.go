package technologies

import (
	"fmt"
	"testing"

	clientservices "github.com/jfrog/jfrog-client-go/xsc/services"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"

	"golang.org/x/exp/maps"

	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"
)

func TestGetExcludePattern(t *testing.T) {
	tests := []struct {
		name            string
		exclusions      []string
		isRecursiveScan bool
		configProfile   *clientservices.ConfigProfile
		expected        string
	}{
		{
			name:            "Test exclude pattern recursive",
			exclusions:      []string{"exclude1", "exclude2"},
			isRecursiveScan: true,
			expected:        "(^exclude1$)|(^exclude2$)",
		},
		{
			name:            "Test no exclude pattern recursive",
			isRecursiveScan: true,
			expected:        "(^.*\\.git.*$)|(^.*node_modules.*$)|(^.*target.*$)|(^.*venv.*$)|(^.*test.*$)|(^dist$)",
		},
		{
			name:       "Test exclude pattern not recursive",
			exclusions: []string{"exclude1", "exclude2"},
			expected:   "(^exclude1$)|(^exclude2$)",
		},
		{
			name:     "Test no exclude pattern",
			expected: "(^.*\\.git.*$)|(^.*node_modules.*$)|(^.*target.*$)|(^.*venv.*$)|(^.*test.*$)|(^dist$)",
		},
		{
			name:       "Test exclude patterns from config profile",
			exclusions: []string{"exclude1", "exclude2"},
			configProfile: &clientservices.ConfigProfile{
				ProfileName: "profile with sca exclusions",
				Modules: []clientservices.Module{
					{
						ModuleName:   "module with sca exclusions",
						PathFromRoot: ".",
						ScanConfig: clientservices.ScanConfig{
							ScaScannerConfig: clientservices.ScaScannerConfig{
								EnableScaScan:   true,
								ExcludePatterns: []string{"exclude3"},
							},
						},
					},
				},
				IsDefault:      false,
				IsBasicProfile: false,
			},
			expected: "(^exclude1$)|(^exclude2$)|(^exclude3$)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := GetExcludePattern(test.configProfile, test.isRecursiveScan, test.exclusions...)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestBuildXrayDependencyTree(t *testing.T) {
	treeHelper := make(map[string]xray.DepTreeNode)
	rootDep := xray.DepTreeNode{Children: []string{"topDep1", "topDep2", "topDep3"}}
	topDep1 := xray.DepTreeNode{Children: []string{"midDep1", "midDep2"}}
	topDep2 := xray.DepTreeNode{Children: []string{"midDep2", "midDep3"}}
	midDep1 := xray.DepTreeNode{Children: []string{"bottomDep1"}}
	midDep2 := xray.DepTreeNode{Children: []string{"bottomDep2", "bottomDep3"}}
	bottomDep3 := xray.DepTreeNode{Children: []string{"leafDep"}}
	treeHelper["rootDep"] = rootDep
	treeHelper["topDep1"] = topDep1
	treeHelper["topDep2"] = topDep2
	treeHelper["midDep1"] = midDep1
	treeHelper["midDep2"] = midDep2
	treeHelper["bottomDep3"] = bottomDep3

	expectedUniqueDeps := []string{"rootDep", "topDep1", "topDep2", "topDep3", "midDep1", "midDep2", "midDep3", "bottomDep1", "bottomDep2", "bottomDep3", "leafDep"}

	// Constructing the expected tree Nodes
	leafDepNode := &xrayUtils.GraphNode{Id: "leafDep", Nodes: []*xrayUtils.GraphNode{}}
	bottomDep3Node := &xrayUtils.GraphNode{Id: "bottomDep3", Nodes: []*xrayUtils.GraphNode{}}
	bottomDep2Node := &xrayUtils.GraphNode{Id: "bottomDep2", Nodes: []*xrayUtils.GraphNode{}}
	bottomDep1Node := &xrayUtils.GraphNode{Id: "bottomDep1", Nodes: []*xrayUtils.GraphNode{}}
	midDep3Node := &xrayUtils.GraphNode{Id: "midDep3", Nodes: []*xrayUtils.GraphNode{}}
	midDep2Node := &xrayUtils.GraphNode{Id: "midDep2", Nodes: []*xrayUtils.GraphNode{}}
	midDep1Node := &xrayUtils.GraphNode{Id: "midDep1", Nodes: []*xrayUtils.GraphNode{}}
	topDep3Node := &xrayUtils.GraphNode{Id: "topDep3", Nodes: []*xrayUtils.GraphNode{}}
	topDep2Node := &xrayUtils.GraphNode{Id: "topDep2", Nodes: []*xrayUtils.GraphNode{}}
	topDep1Node := &xrayUtils.GraphNode{Id: "topDep1", Nodes: []*xrayUtils.GraphNode{}}
	rootNode := &xrayUtils.GraphNode{Id: "rootDep", Nodes: []*xrayUtils.GraphNode{}}

	// Setting children to parents
	bottomDep3Node.Nodes = append(bottomDep3Node.Nodes, leafDepNode)
	midDep2Node.Nodes = append(midDep2Node.Nodes, bottomDep3Node)
	midDep2Node.Nodes = append(midDep2Node.Nodes, bottomDep2Node)
	midDep1Node.Nodes = append(midDep1Node.Nodes, bottomDep1Node)
	topDep2Node.Nodes = append(topDep2Node.Nodes, midDep3Node)
	topDep2Node.Nodes = append(topDep2Node.Nodes, midDep2Node)
	topDep1Node.Nodes = append(topDep1Node.Nodes, midDep2Node)
	topDep1Node.Nodes = append(topDep1Node.Nodes, midDep1Node)
	rootNode.Nodes = append(rootNode.Nodes, topDep1Node)
	rootNode.Nodes = append(rootNode.Nodes, topDep2Node)
	rootNode.Nodes = append(rootNode.Nodes, topDep3Node)

	// Setting children to parents
	leafDepNode.Parent = bottomDep3Node
	bottomDep3Node.Parent = midDep2Node
	bottomDep3Node.Parent = midDep2Node
	bottomDep1Node.Parent = midDep1Node
	midDep3Node.Parent = topDep2Node
	midDep2Node.Parent = topDep2Node
	midDep2Node.Parent = topDep1Node
	midDep1Node.Parent = topDep1Node
	topDep1Node.Parent = rootNode
	topDep2Node.Parent = rootNode
	topDep3Node.Parent = rootNode

	tree, uniqueDeps := xray.BuildXrayDependencyTree(treeHelper, "rootDep")

	assert.ElementsMatch(t, expectedUniqueDeps, maps.Keys(uniqueDeps))
	assert.True(t, tests.CompareTree(tree, rootNode))
}

func TestSuspectCurationBlockedError(t *testing.T) {
	mvnOutput1 := "status code: 403, reason phrase: Forbidden (403)"
	mvnOutput2 := "status code: 500, reason phrase: Server Error (500)"
	pipOutput := "because of HTTP error 403 Client Error: Forbidden for url"
	goOutput := "Failed running Go command: 403 Forbidden"

	tests := []struct {
		name          string
		isCurationCmd bool
		tech          techutils.Technology
		output        string
		expect        string
	}{
		{
			name:          "mvn 403 error",
			isCurationCmd: true,
			tech:          techutils.Maven,
			output:        mvnOutput1,
			expect:        fmt.Sprintf(CurationErrorMsgToUserTemplate, techutils.Maven),
		},
		{
			name:          "mvn 500 error",
			isCurationCmd: true,
			tech:          techutils.Maven,
			output:        mvnOutput2,
			expect:        fmt.Sprintf(CurationErrorMsgToUserTemplate, techutils.Maven),
		},
		{
			name:          "pip 403 error",
			isCurationCmd: true,
			tech:          techutils.Pip,
			output:        pipOutput,
			expect:        fmt.Sprintf(CurationErrorMsgToUserTemplate, techutils.Pip),
		},
		{
			name:          "pip not pass through error",
			isCurationCmd: true,
			tech:          techutils.Pip,
			output:        "http error 401",
		},
		{
			name:          "maven not pass through error",
			isCurationCmd: true,
			tech:          techutils.Maven,
			output:        "http error 401",
		},
		{
			name:          "golang 403 error",
			isCurationCmd: true,
			tech:          techutils.Go,
			output:        goOutput,
			expect:        fmt.Sprintf(CurationErrorMsgToUserTemplate, techutils.Go),
		},
		{
			name:          "not a supported tech",
			isCurationCmd: true,
			tech:          coreutils.CI,
			output:        pipOutput,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, GetMsgToUserForCurationBlock(tt.isCurationCmd, tt.tech, tt.output), tt.expect)
		})
	}
}
