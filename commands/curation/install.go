package curation

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	gotech "github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/go"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/npm"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results/output"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

type PackageInstallHandler interface {
	ParsePackageSpec(spec string) (technologies.InstalledPackage, error)
	CreateTempProject(projectDir, tempDir, pkgName, pkgVersion string) error
	Technology() techutils.Technology
}

var installHandlers = map[techutils.Technology]PackageInstallHandler{
	techutils.Npm: &npm.NpmInstallHandler{},
	techutils.Go:  &gotech.GoInstallHandler{},
}

func (ca *CurationAuditCommand) runInstallMode() (err error) {
	originalDir, err := os.Getwd()
	if err != nil {
		return errorutils.CheckError(err)
	}

	projectDir := originalDir
	if len(ca.workingDirs) > 0 {
		projectDir, err = filepath.Abs(ca.workingDirs[0])
		if err != nil {
			return errorutils.CheckError(err)
		}
		if err = os.Chdir(projectDir); err != nil {
			return errorutils.CheckError(err)
		}
		defer func() {
			if e := errorutils.CheckError(os.Chdir(originalDir)); err == nil {
				err = e
			}
		}()
	}

	handler, err := detectInstallHandler()
	if err != nil {
		return err
	}
	tech := handler.Technology()
	pkg, parseErr := handler.ParsePackageSpec(ca.installPackage)
	if parseErr != nil {
		return parseErr
	}
	ca.installPackage = pkg.Name
	log.Info(fmt.Sprintf("Running curation audit for %s package %s@%s", tech.ToFormal(), pkg.Name, pkg.Version))

	if err = ca.SetRepo(tech); err != nil {
		return err
	}
	ca.AuditParamsInterface = ca.SetDepsRepo(ca.PackageManagerConfig.TargetRepo())

	tempDir, err := os.MkdirTemp("", "curation-install-*")
	if err != nil {
		return errorutils.CheckError(err)
	}
	defer func() {
		if removeErr := os.RemoveAll(tempDir); removeErr != nil {
			log.Warn(fmt.Sprintf("Failed to remove temporary directory %s: %s", tempDir, removeErr.Error()))
		}
	}()

	if err = handler.CreateTempProject(projectDir, tempDir, pkg.Name, pkg.Version); err != nil {
		return err
	}

	if err = os.Chdir(tempDir); err != nil {
		return errorutils.CheckError(err)
	}
	defer func() {
		if e := errorutils.CheckError(os.Chdir(projectDir)); err == nil {
			err = e
		}
	}()

	results := map[string]*CurationReport{}
	auditErr := ca.doCurateAudit(results)

	if ca.Progress() != nil {
		err = errors.Join(err, ca.Progress().Quit())
	}

	hasBlockedPackages := false
	for _, report := range results {
		if len(report.packagesStatus) > 0 {
			hasBlockedPackages = true
			break
		}
	}

	for projectPath, report := range results {
		err = errors.Join(err, printResult(ca.OutputFormat(), projectPath, report.packagesStatus))
	}

	if hasBlockedPackages {
		for _, report := range results {
			for _, ps := range report.packagesStatus {
				if ps.WaiverAllowed && !utils.IsCI() {
					err = errors.Join(err, ca.requestWaiver(report.packagesStatus))
					break
				}
			}
		}
	}

	err = errors.Join(err, output.RecordSecurityCommandSummary(output.NewCurationSummary(convertResultsToSummary(results))))

	if auditErr != nil {
		return errors.Join(err, auditErr)
	}

	if hasBlockedPackages {
		return err
	}

	return err
}

func detectInstallHandler() (PackageInstallHandler, error) {
	detectedTechs := techutils.DetectedTechnologiesList()
	for _, tech := range detectedTechs {
		if handler, ok := installHandlers[techutils.Technology(tech)]; ok {
			return handler, nil
		}
	}
	supportedTechs := getSupportedInstallTechnologies()
	return nil, errorutils.CheckErrorf(
		"could not detect a supported technology in the current directory for --install. Currently supported: %s",
		strings.Join(supportedTechs, ", "))
}

func getSupportedInstallTechnologies() []string {
	techs := make([]string, 0, len(installHandlers))
	for tech := range installHandlers {
		techs = append(techs, tech.ToFormal())
	}
	return techs
}
