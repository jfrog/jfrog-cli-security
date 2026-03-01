package _go

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoParsePackageSpec(t *testing.T) {
	handler := &GoInstallHandler{}

	tests := []struct {
		name        string
		spec        string
		wantName    string
		wantVersion string
		wantErr     bool
	}{
		{
			name:        "standard module",
			spec:        "github.com/pkg/errors@v0.9.1",
			wantName:    "github.com/pkg/errors",
			wantVersion: "v0.9.1",
		},
		{
			name:        "short module path",
			spec:        "rsc.io/quote@v1.5.2",
			wantName:    "rsc.io/quote",
			wantVersion: "v1.5.2",
		},
		{
			name:        "module with many path segments",
			spec:        "github.com/jfrog/jfrog-cli-core/v2@v2.50.0",
			wantName:    "github.com/jfrog/jfrog-cli-core/v2",
			wantVersion: "v2.50.0",
		},
		{
			name:        "pre-release version",
			spec:        "golang.org/x/text@v0.14.0-rc.1",
			wantName:    "golang.org/x/text",
			wantVersion: "v0.14.0-rc.1",
		},
		{
			name:        "pseudo-version",
			spec:        "golang.org/x/text@v0.0.0-20170915032832-14c0d48ead0c",
			wantName:    "golang.org/x/text",
			wantVersion: "v0.0.0-20170915032832-14c0d48ead0c",
		},
		{
			name:    "missing version - no @",
			spec:    "github.com/pkg/errors",
			wantErr: true,
		},
		{
			name:    "empty spec",
			spec:    "",
			wantErr: true,
		},
		{
			name:    "only @",
			spec:    "@",
			wantErr: true,
		},
		{
			name:    "@ at start with version",
			spec:    "@v1.0.0",
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
			require.NoError(t, err)
			assert.Equal(t, tt.wantName, pkg.Name)
			assert.Equal(t, tt.wantVersion, pkg.Version)
		})
	}
}

func TestGoCreateTempProject(t *testing.T) {
	handler := &GoInstallHandler{}

	tests := []struct {
		name       string
		pkgName    string
		pkgVersion string
		existDeps  []string
	}{
		{
			name:       "add package to project with existing dependency",
			pkgName:    "github.com/pkg/errors",
			pkgVersion: "v0.9.1",
			existDeps:  []string{"rsc.io/quote v1.5.2"},
		},
		{
			name:       "add multi-segment module to project with multiple deps",
			pkgName:    "github.com/jfrog/jfrog-cli-core/v2",
			pkgVersion: "v2.50.0",
			existDeps:  []string{"rsc.io/quote v1.5.2", "rsc.io/sampler v1.3.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			projectDir := t.TempDir()
			tempDir := t.TempDir()

			goMod := "module my-project\n\ngo 1.21\n\nrequire (\n"
			for _, dep := range tt.existDeps {
				goMod += "\t" + dep + "\n"
			}
			goMod += ")\n"
			require.NoError(t, os.WriteFile(filepath.Join(projectDir, "go.mod"), []byte(goMod), 0644))

			require.NoError(t, os.MkdirAll(filepath.Join(projectDir, ".git", "objects"), 0755))
			require.NoError(t, os.WriteFile(filepath.Join(projectDir, ".git", "HEAD"), []byte("ref: refs/heads/main"), 0644))
			require.NoError(t, os.MkdirAll(filepath.Join(projectDir, "vendor"), 0755))
			require.NoError(t, os.WriteFile(filepath.Join(projectDir, "vendor", "modules.txt"), []byte("# vendor"), 0644))

			err := handler.CreateTempProject(projectDir, tempDir, tt.pkgName, tt.pkgVersion)
			require.NoError(t, err)

			data, err := os.ReadFile(filepath.Join(tempDir, "go.mod"))
			require.NoError(t, err)

			content := string(data)
			assert.True(t, strings.Contains(content, "module my-project"),
				"go.mod should keep the original module name")
			assert.True(t, strings.Contains(content, tt.pkgName),
				"go.mod should contain the new dependency: %s", tt.pkgName)
			for _, dep := range tt.existDeps {
				depName := strings.Fields(dep)[0]
				assert.True(t, strings.Contains(content, depName),
					"go.mod should still contain existing dependency: %s", depName)
			}

			_, err = os.Stat(filepath.Join(tempDir, ".git"))
			assert.True(t, os.IsNotExist(err), ".git should not be copied")
			_, err = os.Stat(filepath.Join(tempDir, "vendor"))
			assert.True(t, os.IsNotExist(err), "vendor should not be copied")
		})
	}
}

func TestGoCreateTempProject_InvalidDir(t *testing.T) {
	handler := &GoInstallHandler{}
	err := handler.CreateTempProject("/nonexistent/path/that/does/not/exist", t.TempDir(), "github.com/pkg/errors", "v0.9.1")
	assert.Error(t, err)
}
