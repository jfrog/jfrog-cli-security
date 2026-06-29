package java

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/stretchr/testify/assert"
)

func TestGetGradleGraphFromDepTree(t *testing.T) {
	// Create and change directory to test workspace
	tempDirPath, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "gradle", "gradle"))
	defer cleanUp()
	assert.NoError(t, os.Chmod(filepath.Join(tempDirPath, "gradlew"), 0700))
	expectedTree := map[string]map[string]string{
		"org.jfrog.example.gradle:shared:1.0":                             {},
		"org.jfrog.example.gradle:" + filepath.Base(tempDirPath) + ":1.0": {},
		"org.jfrog.example.gradle:services:1.0":                           {},
		"org.jfrog.example.gradle:webservice:1.0": {
			"junit:junit:4.11":                            "",
			"commons-io:commons-io:1.2":                   "",
			"org.apache.wicket:wicket:1.3.7":              "",
			"org.jfrog.example.gradle:shared:1.0":         "",
			"org.jfrog.example.gradle:api:1.0":            "",
			"commons-lang:commons-lang:2.4":               "",
			"commons-collections:commons-collections:3.2": "",
		},
		"org.jfrog.example.gradle:api:1.0": {
			"org.apache.wicket:wicket:1.3.7":      "",
			"org.jfrog.example.gradle:shared:1.0": "",
			"commons-lang:commons-lang:2.4":       "",
		},
	}
	expectedUniqueDeps := []string{
		"junit:junit:4.11",
		"org.jfrog.example.gradle:webservice:1.0",
		"org.jfrog.example.gradle:api:1.0",
		"org.jfrog.example.gradle:" + filepath.Base(tempDirPath) + ":1.0",
		"commons-io:commons-io:1.2",
		"org.apache.wicket:wicket:1.3.7",
		"org.jfrog.example.gradle:shared:1.0",
		"org.jfrog.example.gradle:api:1.0",
		"commons-collections:commons-collections:3.2",
		"commons-lang:commons-lang:2.4",
		"org.hamcrest:hamcrest-core:1.3",
		"org.slf4j:slf4j-api:1.4.2",
	}

	manager := &gradleDepTreeManager{
		DepTreeManager: DepTreeManager{},
		isCurationCmd:  false,
	}
	outputFileContent, err := manager.runGradleDepTree()
	assert.NoError(t, err)
	depTree, uniqueDeps, err := getGraphFromDepTree(outputFileContent)
	assert.NoError(t, err)
	reflect.DeepEqual(uniqueDeps, expectedUniqueDeps)

	for _, dependency := range depTree {
		dependencyId := strings.TrimPrefix(dependency.Id, GavPackageTypeIdentifier)
		depChild, exists := expectedTree[dependencyId]
		assert.True(t, exists)
		assert.Equal(t, len(depChild), len(dependency.Nodes))
	}
}

func TestGetGradleGraphFromDepTreeWithCuration(t *testing.T) {
	tempDirPath, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "gradle", "gradle"))
	defer cleanUp()
	assert.NoError(t, os.Chmod(filepath.Join(tempDirPath, "gradlew"), 0700))

	manager := &gradleDepTreeManager{
		DepTreeManager: DepTreeManager{},
		isCurationCmd:  true,
	}
	outputFileContent, err := manager.runGradleDepTree()
	assert.NoError(t, err)
	depTree, uniqueDeps, err := getGraphFromDepTree(outputFileContent)
	assert.NoError(t, err)
	assert.NotEmpty(t, depTree)
	assert.NotEmpty(t, uniqueDeps)
}

// writeDepTreeModuleFiles writes each maven-dep-tree module JSON to its own temp file and
// returns the newline-separated list of paths that getGraph*FromDepTree expects as input.
func writeDepTreeModuleFiles(t *testing.T, modulesJSON ...string) string {
	dir := t.TempDir()
	paths := make([]string, 0, len(modulesJSON))
	for i, content := range modulesJSON {
		p := filepath.Join(dir, fmt.Sprintf("module-%d.json", i))
		assert.NoError(t, os.WriteFile(p, []byte(content), 0600))
		paths = append(paths, p)
	}
	return strings.Join(paths, "\n")
}

func TestGetGraphAndPluginDepsFromDepTreeSingleModule(t *testing.T) {
	moduleJSON := `{
		"root": "org.example:app:1.0",
		"nodes": {
			"org.example:app:1.0": {"classifier": null, "types": ["jar"], "children": ["commons-io:commons-io:2.11.0"]},
			"commons-io:commons-io:2.11.0": {"classifier": null, "types": ["jar"], "children": []}
		},
		"pluginNodes": {
			"org.ow2.asm:asm:9.8": {"classifier": null, "types": ["jar"], "children": []},
			"commons-io:commons-io:2.21.0": {"classifier": "sources", "types": ["jar"], "children": [], "configurations": ["compile"]}
		}
	}`
	depsGraph, uniqueDeps, pluginDeps, pluginNodesPresent, err := getGraphAndPluginDepsFromDepTree(writeDepTreeModuleFiles(t, moduleJSON))
	assert.NoError(t, err)
	assert.Len(t, depsGraph, 1)
	assert.NotEmpty(t, uniqueDeps)

	assert.True(t, pluginNodesPresent, "pluginNodes field is present")
	assert.NotNil(t, pluginDeps)
	assert.Len(t, pluginDeps, 2)

	asm := pluginDeps["org.ow2.asm:asm:9.8"]
	assert.NotNil(t, asm)
	assert.Equal(t, []string{"jar"}, *asm.Types)
	assert.Nil(t, asm.Classifier)

	// Classifier and Configurations must be carried over from the plugin node (A4).
	commonsIo := pluginDeps["commons-io:commons-io:2.21.0"]
	assert.NotNil(t, commonsIo)
	assert.Equal(t, "sources", *commonsIo.Classifier)
	assert.Equal(t, []string{"compile"}, *commonsIo.Configurations)
}

func TestGetGraphAndPluginDepsFromDepTreeNoPluginNodes(t *testing.T) {
	moduleJSON := `{
		"root": "org.example:app:1.0",
		"nodes": {"org.example:app:1.0": {"classifier": null, "types": ["jar"], "children": []}}
	}`
	depsGraph, uniqueDeps, pluginDeps, pluginNodesPresent, err := getGraphAndPluginDepsFromDepTree(writeDepTreeModuleFiles(t, moduleJSON))
	assert.NoError(t, err)
	assert.Len(t, depsGraph, 1)
	assert.NotEmpty(t, uniqueDeps)
	// No "pluginNodes" field -> nil map and pluginNodesPresent=false, so callers can tell
	// "plugin ignored the flag" from "ran but found nothing".
	assert.False(t, pluginNodesPresent, "pluginNodes field is absent")
	assert.Nil(t, pluginDeps)
}

func TestGetGraphAndPluginDepsFromDepTreeMultiModuleDedup(t *testing.T) {
	moduleA := `{
		"root": "org.example:app-a:1.0",
		"nodes": {"org.example:app-a:1.0": {"classifier": null, "types": ["jar"], "children": []}},
		"pluginNodes": {
			"org.ow2.asm:asm:9.8": {"classifier": null, "types": ["jar"], "children": []},
			"commons-io:commons-io:2.21.0": {"classifier": null, "types": ["jar"], "children": []}
		}
	}`
	moduleB := `{
		"root": "org.example:app-b:1.0",
		"nodes": {"org.example:app-b:1.0": {"classifier": null, "types": ["jar"], "children": []}},
		"pluginNodes": {
			"org.ow2.asm:asm:9.8": {"classifier": null, "types": ["test-jar"], "children": []},
			"org.codehaus.plexus:plexus-utils:4.0.2": {"classifier": null, "types": ["jar"], "children": []}
		}
	}`
	depsGraph, _, pluginDeps, pluginNodesPresent, err := getGraphAndPluginDepsFromDepTree(writeDepTreeModuleFiles(t, moduleA, moduleB))
	assert.NoError(t, err)
	assert.Len(t, depsGraph, 2)

	assert.True(t, pluginNodesPresent, "pluginNodes field is present")
	assert.NotNil(t, pluginDeps)
	assert.Len(t, pluginDeps, 3)
	// Types are unioned across modules (sorted), so module B's "test-jar" isn't dropped.
	asm := pluginDeps["org.ow2.asm:asm:9.8"]
	assert.NotNil(t, asm)
	assert.Equal(t, []string{"jar", "test-jar"}, *asm.Types)
	assert.Contains(t, pluginDeps, "commons-io:commons-io:2.21.0")
	assert.Contains(t, pluginDeps, "org.codehaus.plexus:plexus-utils:4.0.2")
}

func TestMergePluginNodeTypes(t *testing.T) {
	sp := func(s ...string) *[]string { return &s }
	cases := []struct {
		name string
		a, b *[]string
		want *[]string
	}{
		{"both nil", nil, nil, nil},
		{"left nil", nil, sp("jar"), sp("jar")},
		{"right nil", sp("jar"), nil, sp("jar")},
		{"dedup and sort", sp("test-jar", "jar"), sp("jar"), sp("jar", "test-jar")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mergePluginNodeTypes(tc.a, tc.b)
			if tc.want == nil {
				assert.Nil(t, got)
				return
			}
			assert.Equal(t, *tc.want, *got)
		})
	}
}
