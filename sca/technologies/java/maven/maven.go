package maven

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jfrog/jfrog-cli-security/sca/dependencytree"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

var mavenConfigPath = filepath.Join(".mvn", "maven.config")

type MavenHandler struct {
}

func (mavenHandler MavenHandler) GetTechDependencyTree(descriptorPaths ...string) (dependencytree.DependencyTreeResult, error) {
	return dependencytree.GetTechDependencyTree(techutils.Maven, dependencytree.DependencyTreeParams{})
}

func RunMvnCmd(goals []string) (cmdOutput []byte, err error) {
	restoreMavenConfig, err := removeMavenConfig()
	if err != nil {
		return
	}

	defer func() {
		if restoreMavenConfig != nil {
			err = errors.Join(err, restoreMavenConfig())
		}
	}()

	if mdt.settingsXmlPath != "" {
		goals = append(goals, "-s", mdt.settingsXmlPath)
	}

	//#nosec G204
	c := exec.Command("mvn", goals...)
	// TODO: remove constaint on the working directory
	c.Dir = mdt.workingDir
	cmdOutput, err = exec.Command("mvn", goals...).CombinedOutput()
	if err != nil {
		stringOutput := string(cmdOutput)
		if len(cmdOutput) > 0 {
			log.Info(stringOutput)
		}
		if msg := sca.SuspectCurationBlockedError(mdt.isCurationCmd, techutils.Maven, stringOutput); msg != "" {
			err = fmt.Errorf("failed running command 'mvn %s\n\n%s", strings.Join(goals, " "), msg)
		} else {
			err = fmt.Errorf("failed running command 'mvn %s': %s", strings.Join(goals, " "), err.Error())
		}
	}
	return
}

func removeMavenConfig() (func() error, error) {
	mavenConfigExists, err := fileutils.IsFileExists(mavenConfigPath, false)
	if err != nil {
		return nil, err
	}
	if !mavenConfigExists {
		return nil, nil
	}
	restoreMavenConfig, err := ioutils.BackupFile(mavenConfigPath, "maven.config.bkp")
	if err != nil {
		return nil, err
	}
	err = os.Remove(mavenConfigPath)
	if err != nil {
		err = errorutils.CheckErrorf("failed to remove %s while building the maven dependencies tree. Error received:\n%s", mavenConfigPath, err.Error())
	}
	return restoreMavenConfig, err
}
