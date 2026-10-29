package results

import (
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/require"
)

func TestDepsTreeToSbomDistinctOccurrences(t *testing.T) {
	node := func(name string, children ...*xrayUtils.GraphNode) *xrayUtils.GraphNode {
		return &xrayUtils.GraphNode{Id: "gav://example:" + name + ":1.0", Nodes: children}
	}
	// The same edge occurs twice, but only its later occurrence has a grandchild.
	a := node("a", node("x", node("y")))
	b := node("b", node("x", node("y", node("z"))))
	c := node("c", node("x", node("w")))
	for _, roots := range [][]*xrayUtils.GraphNode{{a, b, c}, {c, b, a}, {b, a, c}} {
		components, dependencies := DepsTreeToSbom(roots...)
		require.NotNil(t, components)
		require.Len(t, *components, 7)
		edges := map[string][]string{}
		for _, dep := range *dependencies {
			edges[dep.Ref] = *dep.Dependencies
		}
		ref := func(name string) string { return techutils.XrayComponentIdToCdxComponentRef(node(name).Id) }
		require.ElementsMatch(t, []string{ref("y"), ref("w")}, edges[ref("x")])
		require.ElementsMatch(t, []string{ref("z")}, edges[ref("y")])
		require.Len(t, *dependencies, 5)
	}
}

func TestDepsTreeToSbomPointerCycle(t *testing.T) {
	a := &xrayUtils.GraphNode{Id: "gav://example:a:1.0"}
	b := &xrayUtils.GraphNode{Id: "gav://example:b:1.0", Nodes: []*xrayUtils.GraphNode{a}}
	a.Nodes = []*xrayUtils.GraphNode{b}
	components, dependencies := DepsTreeToSbom(a, b)
	require.Len(t, *components, 2)
	require.Len(t, *dependencies, 2)
}
