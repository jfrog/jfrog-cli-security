package java

import (
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/stretchr/testify/require"
)

// Exercise the Maven plugin JSON -> module graphs -> SBOM pipeline without a server.
func TestMavenModuleExclusionSbom(t *testing.T) {
	excluded := `{"root":"example:a:1.0","nodes":{
 "example:a:1.0":{"children":["example:x:1.0"]},
 "example:x:1.0":{"children":[]}}}`
	included := `{"root":"example:b:1.0","nodes":{
 "example:b:1.0":{"children":["example:x:1.0"]},
 "example:x:1.0":{"children":["example:y:1.0"]},
 "example:y:1.0":{"children":[]}}}`
	for _, modules := range [][]string{{excluded, included}, {included, excluded}} {
		trees, unique, _, _, err := getGraphAndPluginDepsFromDepTree(writeDepTreeModuleFiles(t, modules...))
		require.NoError(t, err)
		components, dependencies := results.DepsTreeToSbom(trees...)
		require.NotNil(t, components)
		refs := []string{}
		for _, component := range *components {
			refs = append(refs, component.BOMRef)
		}
		expected := []string{}
		for id := range unique {
			expected = append(expected, techutils.XrayComponentIdToCdxComponentRef(id))
		}
		require.Len(t, expected, 4)
		require.ElementsMatch(t, expected, refs)
		require.NotNil(t, dependencies)
		edges := map[string][]string{}
		for _, dep := range *dependencies {
			edges[dep.Ref] = *dep.Dependencies
		}
		require.ElementsMatch(t, []string{techutils.XrayComponentIdToCdxComponentRef("gav://example:y:1.0")}, edges[techutils.XrayComponentIdToCdxComponentRef("gav://example:x:1.0")])
	}
}
