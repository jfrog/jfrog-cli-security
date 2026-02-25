package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePackageSpec(t *testing.T) {
	handler := &NpmInstallHandler{}

	tests := []struct {
		name        string
		spec        string
		wantName    string
		wantVersion string
		wantErr     bool
	}{
		{
			name:        "simple package",
			spec:        "express@4.18.2",
			wantName:    "express",
			wantVersion: "4.18.2",
		},
		{
			name:        "scoped package",
			spec:        "@angular/core@17.0.0",
			wantName:    "@angular/core",
			wantVersion: "17.0.0",
		},
		{
			name:        "scoped package with nested scope",
			spec:        "@morgan-stanley/fdc3-web@1.0.0",
			wantName:    "@morgan-stanley/fdc3-web",
			wantVersion: "1.0.0",
		},
		{
			name:        "wildcard version",
			spec:        "lodash@*",
			wantName:    "lodash",
			wantVersion: "*",
		},
		{
			name:        "caret range",
			spec:        "express@^4.18.0",
			wantName:    "express",
			wantVersion: "^4.18.0",
		},
		{
			name:        "tilde range",
			spec:        "express@~4.18.0",
			wantName:    "express",
			wantVersion: "~4.18.0",
		},
		{
			name:        "latest tag",
			spec:        "next@latest",
			wantName:    "next",
			wantVersion: "latest",
		},
		{
			name:        "greater-equal range",
			spec:        "react@>=18.0.0",
			wantName:    "react",
			wantVersion: ">=18.0.0",
		},
		{
			name:    "missing version - no @",
			spec:    "express",
			wantErr: true,
		},
		{
			name:    "scoped package without version",
			spec:    "@angular/core",
			wantErr: true,
		},
		{
			name:    "empty string",
			spec:    "",
			wantErr: true,
		},
		{
			name:    "only @",
			spec:    "@",
			wantErr: true,
		},
		{
			name:    "trailing @ with no version",
			spec:    "express@",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg, err := handler.ParsePackageSpec(tt.spec)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantName, pkg.Name)
			assert.Equal(t, tt.wantVersion, pkg.Version)
		})
	}
}

func TestCreateTempProject(t *testing.T) {
	handler := &NpmInstallHandler{}

	tests := []struct {
		name       string
		pkgName    string
		pkgVersion string
		existDeps  map[string]string
	}{
		{
			name:       "add to existing dependencies",
			pkgName:    "express",
			pkgVersion: "4.18.2",
			existDeps:  map[string]string{"react": "^18.0.0"},
		},
		{
			name:       "add scoped package to empty deps",
			pkgName:    "@angular/core",
			pkgVersion: "17.0.0",
			existDeps:  map[string]string{},
		},
		{
			name:       "add wildcard version alongside existing",
			pkgName:    "lodash",
			pkgVersion: "*",
			existDeps:  map[string]string{"express": "4.18.2", "react": "^18.0.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			projectDir := t.TempDir()
			tempDir := t.TempDir()

			srcPkg := map[string]interface{}{
				"name":         "my-project",
				"version":      "1.0.0",
				"dependencies": tt.existDeps,
			}
			srcData, _ := json.MarshalIndent(srcPkg, "", "  ")
			require.NoError(t, os.WriteFile(filepath.Join(projectDir, "package.json"), srcData, 0644))

			require.NoError(t, os.WriteFile(filepath.Join(projectDir, ".npmrc"), []byte("registry=https://registry.npmjs.org/"), 0644))

			// node_modules and .git should be excluded
			require.NoError(t, os.MkdirAll(filepath.Join(projectDir, "node_modules", "react"), 0755))
			require.NoError(t, os.WriteFile(filepath.Join(projectDir, "node_modules", "react", "index.js"), []byte("module.exports = {}"), 0644))
			require.NoError(t, os.MkdirAll(filepath.Join(projectDir, ".git", "objects"), 0755))
			require.NoError(t, os.WriteFile(filepath.Join(projectDir, ".git", "HEAD"), []byte("ref: refs/heads/main"), 0644))

			err := handler.CreateTempProject(projectDir, tempDir, tt.pkgName, tt.pkgVersion)
			require.NoError(t, err)

			// Verify package.json was copied and has the new dependency
			data, err := os.ReadFile(filepath.Join(tempDir, "package.json"))
			require.NoError(t, err)

			var packageJson map[string]interface{}
			require.NoError(t, json.Unmarshal(data, &packageJson))

			assert.Equal(t, "my-project", packageJson["name"])

			deps, ok := packageJson["dependencies"].(map[string]interface{})
			require.True(t, ok, "dependencies should be a map")
			assert.Equal(t, tt.pkgVersion, deps[tt.pkgName])

			for k, v := range tt.existDeps {
				assert.Equal(t, v, deps[k])
			}
			_, err = os.Stat(filepath.Join(tempDir, ".npmrc"))
			assert.NoError(t, err, ".npmrc should be copied")

			_, err = os.Stat(filepath.Join(tempDir, "node_modules"))
			assert.True(t, os.IsNotExist(err), "node_modules should not be copied")
			_, err = os.Stat(filepath.Join(tempDir, ".git"))
			assert.True(t, os.IsNotExist(err), ".git should not be copied")
		})
	}
}

