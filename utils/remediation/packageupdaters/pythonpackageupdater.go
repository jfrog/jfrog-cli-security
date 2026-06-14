package packageupdaters

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

const (
	defaultRequirementFile = "requirements.txt"
	// Package names are case-insensitive with this prefix
	PythonPackageRegexPrefix = "(?i)"
	// Match all possible operators and versions syntax
	PythonPackageRegexSuffix = "\\s*(([\\=\\<\\>\\~]=)|([\\>\\<]))\\s*(\\.|\\d)*(\\d|(\\.\\*))(\\,\\s*(([\\=\\<\\>\\~]=)|([\\>\\<])).*\\s*(\\.|\\d)*(\\d|(\\.\\*)))?"
)

type PythonPackageUpdater struct {
	pipRequirementsFile string
	CommonPackageUpdater
}

func (py *PythonPackageUpdater) UpdateDependency(fixDetails *FixDetails) error {
	if fixDetails.IsDirectDependency {
		return py.updateDirectDependency(fixDetails)
	}

	return &ErrUnsupportedFix{
		PackageName:  fixDetails.ImpactedDependencyName,
		FixedVersion: fixDetails.SuggestedFixedVersion,
		ErrorType:    IndirectDependencyFixNotSupported,
	}
}

func (py *PythonPackageUpdater) updateDirectDependency(fixDetails *FixDetails) (err error) {
	switch fixDetails.Technology {
	case techutils.Poetry:
		return py.handlePoetry(fixDetails)
	case techutils.Pip:
		return py.handlePip(fixDetails)
	case techutils.Pipenv:
		return py.CommonPackageUpdater.UpdateDependency(fixDetails, fixDetails.Technology.GetPackageInstallationCommand())
	default:
		return errors.New("unknown python package manger: " + fixDetails.Technology.GetPackageType())
	}
}

func (py *PythonPackageUpdater) handlePoetry(fixDetails *FixDetails) (err error) {
	if err = py.CommonPackageUpdater.UpdateDependency(fixDetails, fixDetails.Technology.GetPackageInstallationCommand()); err != nil {
		return
	}
	return runPackageMangerCommand(techutils.Poetry.GetExecCommandName(), techutils.Poetry.String(), []string{"update"})
}

func (py *PythonPackageUpdater) handlePip(fixDetails *FixDetails) (err error) {
	var fixedFile string
	fixedPackage := fixDetails.ImpactedDependencyName + "==" + fixDetails.SuggestedFixedVersion
	currentFile, err := py.tryGetRequirementFile()
	if err != nil {
		return errors.New("failed to read pip requirements file: " + err.Error())
	}
	re := regexp.MustCompile(PythonPackageRegexPrefix + "(" + fixDetails.ImpactedDependencyName + "|" + strings.ToLower(fixDetails.ImpactedDependencyName) + ")" + PythonPackageRegexSuffix)
	if packageToReplace := re.FindString(currentFile); packageToReplace != "" {
		fixedFile = strings.Replace(currentFile, packageToReplace, strings.ToLower(fixedPackage), 1)
	}
	if fixedFile == "" {
		return fmt.Errorf("impacted package %s not found, fix failed", fixDetails.ImpactedDependencyName)
	}
	//#nosec G703 -- False positive - the path is determined by internal file scanning, not user input, and was already validated by the preceding Stat call.
	if err = os.WriteFile(py.pipRequirementsFile, []byte(fixedFile), 0600); err != nil {
		err = fmt.Errorf("an error occured while writing the fixed version of %s to the requirements file:\n%s", fixDetails.SuggestedFixedVersion, err.Error())
	}
	return
}

func (py *PythonPackageUpdater) tryGetRequirementFile() (string, error) {
	if py.pipRequirementsFile != "" {
		fileContent, err := py.tryReadRequirementFile(py.pipRequirementsFile)
		if err != nil {
			return "", err
		}
		return fileContent, nil
	} else {
		py.pipRequirementsFile = "setup.py"
		fileContent, err := py.tryReadRequirementFile(py.pipRequirementsFile)
		if err != nil {
			py.pipRequirementsFile = "requirements.txt"
			fileContent, err = py.tryReadRequirementFile(py.pipRequirementsFile)
			if err != nil {
				return "", err
			}
			return fileContent, nil
		}
		return fileContent, nil
	}
}

func (py *PythonPackageUpdater) tryReadRequirementFile(file string) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	fullPath := filepath.Join(wd, file)
	if !strings.HasPrefix(filepath.Clean(fullPath), wd) {
		return "", errors.New("wrong requirements file input: " + fullPath)
	}
	data, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		return "", errors.New("an error occurred while attempting to read the requirements file:\n" + err.Error())
	}
	return string(data), nil
}
