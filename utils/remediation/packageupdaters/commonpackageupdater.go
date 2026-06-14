package packageupdaters

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"golang.org/x/exp/slices"
)

const (
	// NodePackageJSONFileName is the file name of the Node.js package manifest.
	NodePackageJSONFileName = "package.json"
	// NodeModulesDirName is the Node.js modules directory name.
	NodeModulesDirName               = "node_modules"
	nodePackageJSONFileName          = NodePackageJSONFileName
	nodeModulesDirName               = NodeModulesDirName
	nodeDependenciesSection          = "dependencies"
	nodeDevDependenciesSection       = "devDependencies"
	nodeOptionalDependenciesSection  = "optionalDependencies"
	nodeOverridesSection             = "overrides"
	nodePackageManagerInstallTimeout = 15 * time.Minute
)

var nodePackageManifestSections = []string{
	nodeDependenciesSection,
	nodeDevDependenciesSection,
	nodeOptionalDependenciesSection,
	nodeOverridesSection,
}

// SupportedFixTechnologies lists the technologies for which automatic dependency
// fixing is supported.
var SupportedFixTechnologies = []techutils.Technology{
	techutils.Npm,
	techutils.Maven,
	techutils.Pip,
	techutils.Go,
	techutils.Pnpm,
}

func GetCompatiblePackageUpdater(fixDetails *FixDetails) (PackageUpdater, bool) {
	switch fixDetails.Technology {
	case techutils.Go:
		return &GoPackageUpdater{}, true
	case techutils.Pip:
		return &PythonPackageUpdater{pipRequirementsFile: defaultRequirementFile}, true
	case techutils.Npm:
		return &NpmPackageUpdater{}, true
	case techutils.Maven:
		return &MavenPackageUpdater{}, true
	case techutils.Pnpm:
		return &PnpmPackageUpdater{}, true
	default:
		return nil, false
	}
}

type CommonPackageUpdater struct{}

func EvidencePathLooksLikeNpmPackageCoordinate(evidenceFile string) bool {
	dir := filepath.Dir(evidenceFile)
	if dir == "." || dir == "" {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(dir), "/") {
		if part == "" || part == "." {
			continue
		}
		if strings.Contains(part, "@") && !strings.HasPrefix(part, "@") {
			return true
		}
	}
	return false
}

func (cph *CommonPackageUpdater) CollectVulnerabilityDescriptorPaths(fixDetails *FixDetails, namesFilters []string, ignoreFilters []string) []string {
	pathsSet := datastructures.MakeSet[string]()
	for _, component := range fixDetails.Components {
		for _, evidence := range component.Evidences {
			if evidence.File == "" || techutils.IsTechnologyDescriptor(evidence.File) == techutils.NoTech || slices.ContainsFunc(ignoreFilters, func(pattern string) bool { return strings.Contains(evidence.File, pattern) }) {
				continue
			}
			if len(namesFilters) == 0 || slices.Contains(namesFilters, filepath.Base(evidence.File)) {
				pathsSet.Add(evidence.File)
			}
		}
	}
	return pathsSet.ToSlice()
}

func (cph *CommonPackageUpdater) BuildPackageDependencyLineRegex(impactedName, impactedVersion, dependencyLineFormat string) *regexp.Regexp {
	regexpFitImpactedName := strings.ToLower(regexp.QuoteMeta(impactedName))
	regexpFitImpactedVersion := strings.ToLower(regexp.QuoteMeta(impactedVersion))
	regexpCompleteFormat := fmt.Sprintf(strings.ToLower(dependencyLineFormat), regexpFitImpactedName, regexpFitImpactedVersion)
	return regexp.MustCompile(regexpCompleteFormat)
}

func EscapeJsonPathKey(key string) string {
	r := strings.NewReplacer(".", "\\.", "*", "\\*", "?", "\\?")
	return r.Replace(key)
}

func (cph *CommonPackageUpdater) GetFixedPackageJSONManifest(content []byte, packageName, newVersion, descriptorPath string) ([]byte, error) {
	updated := false
	escapedName := EscapeJsonPathKey(packageName)

	for _, section := range nodePackageManifestSections {
		path := section + "." + escapedName
		if gjson.GetBytes(content, path).Exists() {
			var err error
			content, err = sjson.SetBytes(content, path, newVersion)
			if err != nil {
				return nil, fmt.Errorf("failed to set version for '%s' in section '%s': %w", packageName, section, err)
			}
			updated = true
		}
	}

	if !updated {
		return nil, fmt.Errorf("package '%s' not found in allowed sections [%s] in '%s'", packageName, strings.Join(nodePackageManifestSections, ", "), descriptorPath)
	}
	return content, nil
}

func (cph *CommonPackageUpdater) UpdatePackageJSONDescriptor(descriptorPath, packageName, newVersion string) ([]byte, error) {
	descriptorContent, err := os.ReadFile(descriptorPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file '%s': %w", descriptorPath, err)
	}

	backupContent := make([]byte, len(descriptorContent))
	copy(backupContent, descriptorContent)

	updatedContent, err := cph.GetFixedPackageJSONManifest(descriptorContent, packageName, newVersion, descriptorPath)
	if err != nil {
		return nil, fmt.Errorf("failed to update version in descriptor: %w", err)
	}

	if err = os.WriteFile(descriptorPath, updatedContent, 0644); err != nil {
		return nil, fmt.Errorf("failed to write updated descriptor '%s': %w", descriptorPath, err)
	}
	return backupContent, nil
}

func (cph *CommonPackageUpdater) withDescriptorWorkingDir(descriptorPath, originalWd string, fn func() error) (err error) {
	descriptorDir := filepath.Dir(descriptorPath)
	if err = os.Chdir(descriptorDir); err != nil {
		return fmt.Errorf("failed to change directory to '%s': %w", descriptorDir, err)
	}
	defer func() {
		if chErr := os.Chdir(originalWd); chErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to return to original directory: %w", chErr))
		}
	}()
	return fn()
}

func (cph *CommonPackageUpdater) BuildEnvWithOverrides(overrides map[string]string) []string {
	env := make([]string, 0, len(os.Environ())+len(overrides))
	for _, e := range os.Environ() {
		key := strings.SplitN(e, "=", 2)[0]
		if _, shouldOverride := overrides[key]; !shouldOverride {
			env = append(env, e)
		}
	}
	for key, value := range overrides {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	return env
}

func (cph *CommonPackageUpdater) UpdateDependency(fixDetails *FixDetails, installationCommand string, extraArgs ...string) (err error) {
	impactedPackage := strings.ToLower(fixDetails.ImpactedDependencyName)
	commandArgs := []string{installationCommand}
	commandArgs = append(commandArgs, extraArgs...)
	versionOperator := fixDetails.Technology.GetPackageVersionOperator()
	fixedPackageArgs := GetFixedPackage(impactedPackage, versionOperator, fixDetails.SuggestedFixedVersion)
	commandArgs = append(commandArgs, fixedPackageArgs...)
	return runPackageMangerCommand(fixDetails.Technology.GetExecCommandName(), fixDetails.Technology.String(), commandArgs)
}

func runPackageMangerCommand(commandName string, techName string, commandArgs []string) error {
	fullCommand := commandName + " " + strings.Join(commandArgs, " ")
	log.Debug(fmt.Sprintf("Running '%s'", fullCommand))
	cmd := exec.Command(commandName, commandArgs...)
	if commandName == "pnpm" {
		cmd.Env = EnvWithCorepackIntegrityWorkaround(os.Environ())
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to update %s dependency: '%s' command failed: %s\n%s", techName, fullCommand, err.Error(), output)
	}
	return nil
}

func EnvWithCorepackIntegrityWorkaround(base []string) []string {
	const key = "COREPACK_INTEGRITY_KEYS"
	prefix := key + "="
	out := make([]string, 0, len(base)+1)
	for _, e := range base {
		if !strings.HasPrefix(e, prefix) {
			out = append(out, e)
		}
	}
	return append(out, prefix+"0")
}

func GetFixedPackage(impactedPackage string, versionOperator string, suggestedFixedVersion string) (fixedPackageArgs []string) {
	fixedPackageString := strings.TrimSpace(impactedPackage) + versionOperator + strings.TrimSpace(suggestedFixedVersion)
	fixedPackageArgs = strings.Split(fixedPackageString, " ")
	return
}

func (cph *CommonPackageUpdater) GetAllDescriptorFilesFullPaths(descriptorFilesSuffixes []string, patternsToExclude ...string) (descriptorFilesFullPaths []string, err error) {
	if len(descriptorFilesSuffixes) == 0 {
		return
	}

	var regexpPatternsCompilers []*regexp.Regexp
	for _, patternToExclude := range patternsToExclude {
		regexpPatternsCompilers = append(regexpPatternsCompilers, regexp.MustCompile(patternToExclude))
	}

	err = filepath.WalkDir(".", func(path string, d fs.DirEntry, innerErr error) error {
		if innerErr != nil {
			return fmt.Errorf("an error has occurred when attempting to access or traverse the file system: %w", innerErr)
		}

		for _, regexpCompiler := range regexpPatternsCompilers {
			if match := regexpCompiler.FindString(path); match != "" {
				return filepath.SkipDir
			}
		}

		for _, assetFileSuffix := range descriptorFilesSuffixes {
			if strings.HasSuffix(path, assetFileSuffix) {
				var absFilePath string
				absFilePath, innerErr = filepath.Abs(path)
				if innerErr != nil {
					return fmt.Errorf("couldn't retrieve file's absolute path for './%s': %w", path, innerErr)
				}
				descriptorFilesFullPaths = append(descriptorFilesFullPaths, absFilePath)
			}
		}
		return nil
	})
	if err != nil {
		err = fmt.Errorf("failed to get descriptor files absolute paths: %w", err)
	}
	return
}

func BuildPackageWithVersionRegex(impactedName, impactedVersion, dependencyLineFormat string) *regexp.Regexp {
	var c CommonPackageUpdater
	return c.BuildPackageDependencyLineRegex(impactedName, impactedVersion, dependencyLineFormat)
}

func GetVulnerabilityLocations(fixDetails *FixDetails, namesFilters []string, ignoreFilters []string) []string {
	var c CommonPackageUpdater
	return c.CollectVulnerabilityDescriptorPaths(fixDetails, namesFilters, ignoreFilters)
}

// IsFileTrackedByGit returns true if the given file is tracked by the git repository
// rooted at repoRootDir.
func IsFileTrackedByGit(filePath, repoRootDir string) (bool, error) {
	repo, err := git.PlainOpen(repoRootDir)
	if err != nil {
		return false, fmt.Errorf("failed to open git repository at '%s': %w", repoRootDir, err)
	}

	head, err := repo.Head()
	if err != nil {
		return false, fmt.Errorf("failed to get HEAD reference: %w", err)
	}

	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return false, fmt.Errorf("failed to get HEAD commit: %w", err)
	}

	tree, err := commit.Tree()
	if err != nil {
		return false, fmt.Errorf("failed to get commit tree: %w", err)
	}

	_, err = tree.File(filePath)
	if errors.Is(err, object.ErrFileNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check file in commit tree: %w", err)
	}
	return true, nil
}
