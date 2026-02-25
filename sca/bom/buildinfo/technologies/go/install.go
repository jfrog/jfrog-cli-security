package _go

import (
	"fmt"
	"os/exec"
	"strings"

	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"

	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

type GoInstallHandler struct{}

func (h *GoInstallHandler) Technology() techutils.Technology {
	return techutils.Go
}

// ParsePackageSpec parses a Go package spec: <module>@<version>.
func (h *GoInstallHandler) ParsePackageSpec(spec string) (technologies.InstalledPackage, error) {
	atIdx := strings.LastIndex(spec, "@")
	if atIdx <= 0 {
		return technologies.InstalledPackage{}, errorutils.CheckErrorf(
			"invalid Go package spec: '%s'. Expected format: <module>@<version> (e.g. github.com/pkg/errors@v0.9.1)", spec)
	}
	name := spec[:atIdx]
	version := spec[atIdx+1:]
	if name == "" || version == "" {
		return technologies.InstalledPackage{}, errorutils.CheckErrorf(
			"invalid Go package spec: '%s'. Both module path and version are required", spec)
	}
	return technologies.InstalledPackage{Name: name, Version: version}, nil
}

func (h *GoInstallHandler) CreateTempProject(projectDir, tempDir, pkgName, pkgVersion string) error {
	if err := biutils.CopyDir(projectDir, tempDir, true, []string{".git", "vendor"}); err != nil {
		return err
	}
	requireArg := fmt.Sprintf("-require=%s@%s", pkgName, pkgVersion)
	cmd := exec.Command("go", "mod", "edit", requireArg)
	cmd.Dir = tempDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errorutils.CheckErrorf("failed to add require to temp go.mod: %s\n%s", err.Error(), string(output))
	}
	return nil
}

