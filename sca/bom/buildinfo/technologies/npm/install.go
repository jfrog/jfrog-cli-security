package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"

	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

type NpmInstallHandler struct{}

func (h *NpmInstallHandler) Technology() techutils.Technology {
	return techutils.Npm
}

// ParsePackageSpec parses an npm package spec: <name>@<version> or @<scope>/<name>@<version>.
func (h *NpmInstallHandler) ParsePackageSpec(spec string) (technologies.InstalledPackage, error) {
	lastAt := strings.LastIndex(spec, "@")
	if lastAt <= 0 {
		return technologies.InstalledPackage{}, errorutils.CheckErrorf(
			"invalid npm package spec: '%s'. Expected format: <packageName>@<packageVersion> (e.g. express@4.18.2 or @scope/name@1.0.0)", spec)
	}
	name := spec[:lastAt]
	version := spec[lastAt+1:]
	if name == "" || version == "" {
		return technologies.InstalledPackage{}, errorutils.CheckErrorf(
			"invalid npm package spec: '%s'. Both package name and version are required", spec)
	}
	return technologies.InstalledPackage{Name: name, Version: version}, nil
}

// CreateTempProject copies the project directory (excluding node_modules) to the temp directory,
// then adds the requested package to the copied package.json.
func (h *NpmInstallHandler) CreateTempProject(projectDir, tempDir, pkgName, pkgVersion string) error {
	if err := biutils.CopyDir(projectDir, tempDir, true, []string{"node_modules", ".git"}); err != nil {
		return err
	}
	return addDependencyToPackageJson(filepath.Join(tempDir, "package.json"), pkgName, pkgVersion)
}

func addDependencyToPackageJson(packageJsonPath, pkgName, pkgVersion string) error {
	data, err := os.ReadFile(packageJsonPath)
	if err != nil {
		return errorutils.CheckErrorf("failed to read package.json at '%s': %s", packageJsonPath, err.Error())
	}

	var packageJson map[string]interface{}
	if err = json.Unmarshal(data, &packageJson); err != nil {
		return errorutils.CheckErrorf("failed to parse package.json: %s", err.Error())
	}

	deps, ok := packageJson["dependencies"].(map[string]interface{})
	if !ok {
		deps = make(map[string]interface{})
	}
	deps[pkgName] = pkgVersion
	packageJson["dependencies"] = deps

	updatedData, err := json.MarshalIndent(packageJson, "", "  ")
	if err != nil {
		return errorutils.CheckError(err)
	}
	updatedData = append(updatedData, '\n')
	return errorutils.CheckError(os.WriteFile(packageJsonPath, updatedData, 0644))
}
