package techutils

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/common/project"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/artifactory/services/fspatterns"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

type Technology string

const (
	Maven  Technology = "maven"
	Gradle Technology = "gradle"
	Npm    Technology = "npm"
	Pnpm   Technology = "pnpm"
	Yarn   Technology = "yarn"
	Go     Technology = "go"
	Pip    Technology = "pip"
	Pipenv Technology = "pipenv"
	Poetry Technology = "poetry"
	Nuget  Technology = "nuget"
	Dotnet Technology = "dotnet"
	Docker Technology = "docker"
	Oci    Technology = "oci"
	Conan  Technology = "conan"
	NoTech Technology = ""
)
const Pypi = "pypi"

var AllTechnologiesStrings = []string{Maven.String(), Gradle.String(), Npm.String(), Pnpm.String(), Yarn.String(), Go.String(), Pip.String(), Pipenv.String(), Poetry.String(), Nuget.String(), Dotnet.String(), Docker.String(), Oci.String(), Conan.String()}

type CodeLanguage string

const (
	JavaScript CodeLanguage = "javascript"
	Python     CodeLanguage = "python"
	GoLang     CodeLanguage = "go"
	Java       CodeLanguage = "java"
	CSharp     CodeLanguage = "C#"
	CPP        CodeLanguage = "C++"
)

// Associates a technology with project type (used in config commands for the package-managers).
// Docker is not present, as there is no docker-config command and, consequently, no docker.yaml file we need to operate on.
var TechToProjectType = map[Technology]project.ProjectType{
	Maven:  project.Maven,
	Gradle: project.Gradle,
	Npm:    project.Npm,
	Yarn:   project.Yarn,
	Go:     project.Go,
	Pip:    project.Pip,
	Pipenv: project.Pipenv,
	Poetry: project.Poetry,
	Nuget:  project.Nuget,
	Dotnet: project.Dotnet,
}

var packageTypes = map[string]string{
	"gav":      "Maven",
	"docker":   "Docker",
	"rpm":      "RPM",
	"deb":      "Debian",
	"nuget":    "NuGet",
	"generic":  "Generic",
	"npm":      "npm",
	"pip":      "Python",
	"pypi":     "Python",
	"composer": "Composer",
	"go":       "Go",
	"alpine":   "Alpine",
}

type TechData struct {
	// The name of the package type used in this technology.
	packageType string
	// The package type ID used in Xray.
	packageTypeId string
	// Suffixes of file/directory names that indicate if a project uses this technology.
	// The name of at least one of the files/directories in the project's directory must end with one of these suffixes.
	indicators []string
	// If suffix provides a content validator and the file/directory name matches, the content of the file will be validated to check if it is the indicator first.
	validators map[string]ContentValidator
	// Suffixes of file/directory names that indicate if a project does not use this technology.
	// The names of all the files/directories in the project's directory must NOT end with any of these suffixes.
	exclude []string
	// The files that handle the project's dependencies.
	packageDescriptors []string
	// Formal name of the technology
	formal string
	// The executable name of the technology
	execCommand string
	// The operator for package versioning
	packageVersionOperator string
	// The package installation command of a package
	packageInstallationCommand string
}

// Given a file content, returns true if the content is an indicator of the technology.
type ContentValidator func(content []byte) bool

var technologiesData = map[Technology]TechData{
	Maven: {
		indicators:         []string{"pom.xml"},
		packageDescriptors: []string{"pom.xml"},
		execCommand:        "mvn",
	},
	Gradle: {
		indicators:         []string{"build.gradle", "build.gradle.kts"},
		packageDescriptors: []string{"build.gradle", "build.gradle.kts"},
	},
	Npm: {
		indicators:                 []string{"package.json", "package-lock.json", "npm-shrinkwrap.json"},
		exclude:                    []string{"pnpm-lock.yaml", ".yarnrc.yml", "yarn.lock", ".yarn"},
		packageDescriptors:         []string{"package.json"},
		formal:                     string(Npm),
		packageVersionOperator:     "@",
		packageInstallationCommand: "install",
	},
	Pnpm: {
		indicators:                 []string{"pnpm-lock.yaml"},
		exclude:                    []string{".yarnrc.yml", "yarn.lock", ".yarn"},
		packageDescriptors:         []string{"package.json"},
		packageVersionOperator:     "@",
		packageTypeId:              "npm://",
		packageInstallationCommand: "update",
	},
	Yarn: {
		indicators:             []string{".yarnrc.yml", "yarn.lock", ".yarn", ".yarnrc"},
		exclude:                []string{"pnpm-lock.yaml"},
		packageDescriptors:     []string{"package.json"},
		packageVersionOperator: "@",
	},
	Go: {
		indicators:                 []string{"go.mod"},
		packageDescriptors:         []string{"go.mod"},
		packageVersionOperator:     "@v",
		packageInstallationCommand: "get",
	},
	Pip: {
		packageType:        Pypi,
		indicators:         []string{"pyproject.toml", "setup.py", "requirements.txt"},
		validators:         map[string]ContentValidator{"pyproject.toml": pyProjectTomlIndicatorContent(Pip)},
		packageDescriptors: []string{"setup.py", "requirements.txt", "pyproject.toml"},
		exclude:            []string{"Pipfile", "Pipfile.lock", "poetry.lock"},
	},
	Pipenv: {
		packageType:                Pypi,
		indicators:                 []string{"Pipfile", "Pipfile.lock"},
		packageDescriptors:         []string{"Pipfile"},
		packageVersionOperator:     "==",
		packageInstallationCommand: "install",
	},
	Poetry: {
		packageType:                Pypi,
		indicators:                 []string{"pyproject.toml", "poetry.lock"},
		validators:                 map[string]ContentValidator{"pyproject.toml": pyProjectTomlIndicatorContent(Poetry)},
		packageDescriptors:         []string{"pyproject.toml"},
		packageInstallationCommand: "add",
		packageVersionOperator:     "==",
	},
	Nuget: {
		indicators:         []string{".sln", ".csproj"},
		packageDescriptors: []string{".sln", ".csproj"},
		formal:             "NuGet",
		// .NET CLI is used for NuGet projects
		execCommand:                "dotnet",
		packageInstallationCommand: "add",
		// packageName -v packageVersion
		packageVersionOperator: " -v ",
	},
	Dotnet: {
		indicators:         []string{".sln", ".csproj"},
		packageDescriptors: []string{".sln", ".csproj"},
		formal:             ".NET",
	},
	Docker: {},
	Oci:    {},
	Conan: {
		indicators:         []string{"conanfile.txt", "conanfile.py "},
		packageDescriptors: []string{"conanfile.txt", "conanfile.py "},
		formal:             "Conan",
	},
}

var (
	// [tool.poetry] section
	pyProjectTomlPoetryRegex = regexp.MustCompile(`(?ms)^\[tool\.poetry\]`)
	// `hatchling` in the [build-system] section
	pyProjectTomlHatchRegex = regexp.MustCompile(`(?ms)^\[build-system\].*requires\s*=\s*\[.*"hatchling".*]`)
	// `flit_core` in the [build-system] section
	pyProjectTomlFlitRegex = regexp.MustCompile(`(?ms)^\[build-system\].*requires\s*=\s*\[.*"flit_core[^\]]*.*]`)
	// `pdm-pep517` in the [build-system] section
	pyProjectTomlPdmRegex = regexp.MustCompile(`(?ms)^\[build-system\].*requires\s*=\s*\[.*"pdm-pep517".*]`)
)

func pyProjectTomlIndicatorContent(tech Technology) ContentValidator {
	return func(content []byte) bool {
		if pyProjectTomlPoetryRegex.Match(content) {
			return tech == Poetry
		}
		if pyProjectTomlHatchRegex.Match(content) || pyProjectTomlFlitRegex.Match(content) || pyProjectTomlPdmRegex.Match(content) {
			// Not supported yet
			return false
		}
		// Default to Pip
		return tech == Pip
	}
}

func TechnologyToLanguage(technology Technology) CodeLanguage {
	languageMap := map[Technology]CodeLanguage{
		Npm:    JavaScript,
		Pip:    Python,
		Poetry: Python,
		Pipenv: Python,
		Go:     GoLang,
		Maven:  Java,
		Gradle: Java,
		Nuget:  CSharp,
		Dotnet: CSharp,
		Yarn:   JavaScript,
		Pnpm:   JavaScript,
	}
	return languageMap[technology]
}

func (tech Technology) ToFormal() string {
	if technologiesData[tech].formal == "" {
		return cases.Title(language.Und).String(tech.String())
	}
	return technologiesData[tech].formal
}

func (tech Technology) String() string {
	return string(tech)
}

func (tech Technology) GetExecCommandName() string {
	if technologiesData[tech].execCommand == "" {
		return tech.String()
	}
	return technologiesData[tech].execCommand
}

func (tech Technology) GetPackageType() string {
	if technologiesData[tech].packageType == "" {
		return tech.String()
	}
	return technologiesData[tech].packageType
}

func (tech Technology) GetPackageTypeId() string {
	if technologiesData[tech].packageTypeId == "" {
		return fmt.Sprintf("%s://", tech.GetPackageType())
	}
	return technologiesData[tech].packageTypeId
}

func (tech Technology) GetPackageDescriptor() []string {
	return technologiesData[tech].packageDescriptors
}

func (tech Technology) GetPackageVersionOperator() string {
	return technologiesData[tech].packageVersionOperator
}

func (tech Technology) GetPackageInstallationCommand() string {
	return technologiesData[tech].packageInstallationCommand
}

func (tech Technology) isDescriptor(path string) bool {
	for _, descriptor := range technologiesData[tech].packageDescriptors {
		if strings.HasSuffix(path, descriptor) {
			return true
		}
	}
	return false
}

func (tech Technology) isIndicator(path string) (bool, error) {
	for _, suffix := range technologiesData[tech].indicators {
		if strings.HasSuffix(path, suffix) {
			return checkPotentialIndicator(path, technologiesData[tech].validators[suffix])
		}
	}
	return false, nil
}

func DetectedTechnologiesList() (technologies []string) {
	wd, err := os.Getwd()
	if errorutils.CheckError(err) != nil {
		return
	}
	return detectedTechnologiesListInPath(wd, false)
}

func detectedTechnologiesListInPath(path string, recursive bool) (technologies []string) {
	detectedTechnologies, err := DetectTechnologiesDescriptors(path, recursive, []string{}, map[Technology][]string{}, "")
	if err != nil {
		return
	}
	if len(detectedTechnologies) == 0 {
		return
	}
	techStringsList := DetectedTechnologiesToSlice(detectedTechnologies)
	log.Info(fmt.Sprintf("Detected: %s.", strings.Join(techStringsList, ", ")))
	return techStringsList
}

// If recursive is true, the search will not be limited to files in the root path.
// If recursive is true the search may return Technology.NoTech value
// If requestedTechs is empty, all technologies will be checked.
// If excludePathPattern is not empty, files/directories that match the wildcard pattern will be excluded from the search.
func DetectTechnologiesDescriptors(path string, recursive bool, requestedTechs []string, requestedDescriptors map[Technology][]string, excludePathPattern string) (technologiesDetected map[Technology]map[string][]string, err error) {
	filesList, dirsList, err := listFilesAndDirs(path, recursive, true, true, excludePathPattern)
	if err != nil {
		return
	}
	workingDirectoryToIndicators, excludedTechAtWorkingDir, err := mapFilesToRelevantWorkingDirectories(filesList, requestedDescriptors)
	if err != nil {
		return
	}
	var strJson string
	if strJson, err = coreutils.GetJsonIndent(workingDirectoryToIndicators); err != nil {
		return
	} else if len(workingDirectoryToIndicators) > 0 {
		log.Debug(fmt.Sprintf("mapped %d working directories with indicators/descriptors:\n%s", len(workingDirectoryToIndicators), strJson))
	}
	technologiesDetected, err = mapWorkingDirectoriesToTechnologies(workingDirectoryToIndicators, excludedTechAtWorkingDir, ToTechnologies(requestedTechs), requestedDescriptors)
	if err != nil {
		return
	}
	if recursive {
		// If recursive search, we need to also make sure to include directories that do not have any technology indicators.
		technologiesDetected = addNoTechIfNeeded(technologiesDetected, path, dirsList)
	}
	techCount := len(technologiesDetected)
	if _, exist := technologiesDetected[NoTech]; exist {
		techCount--
	}
	if techCount > 0 {
		log.Debug(fmt.Sprintf("Detected %d technologies at %s: %s.", techCount, path, maps.Keys(technologiesDetected)))
	}
	return
}

func listFilesAndDirs(rootPath string, isRecursive, excludeWithRelativePath, preserveSymlink bool, excludePathPattern string) (files, dirs []string, err error) {
	filesOrDirsInPath, err := fspatterns.ListFiles(rootPath, isRecursive, true, excludeWithRelativePath, preserveSymlink, excludePathPattern)
	if err != nil {
		return
	}
	for _, path := range filesOrDirsInPath {
		if isDir, e := fileutils.IsDirExists(path, preserveSymlink); e != nil {
			err = errors.Join(err, fmt.Errorf("failed to check if %s is a directory: %w", path, e))
			continue
		} else if isDir {
			dirs = append(dirs, path)
		} else {
			files = append(files, path)
		}
	}
	return
}

func addNoTechIfNeeded(technologiesDetected map[Technology]map[string][]string, rootPath string, dirsList []string) (_ map[Technology]map[string][]string) {
	noTechMap := map[string][]string{}
	for _, dir := range getDirNoTechList(technologiesDetected, rootPath, dirsList) {
		// Convert the directories
		noTechMap[dir] = []string{}
	}
	if len(technologiesDetected) == 0 || len(noTechMap) > 0 {
		// no technologies detected at all (add NoTech without any directories) or some directories were added to NoTech
		technologiesDetected[NoTech] = noTechMap
	}
	return technologiesDetected
}

func getDirNoTechList(technologiesDetected map[Technology]map[string][]string, dir string, dirsList []string) (noTechList []string) {
	for _, techDirs := range technologiesDetected {
		if _, exist := techDirs[dir]; exist {
			// The directory is already mapped to a technology, no need to add the dir or its sub directories to NoTech
			return
		}
	}
	children := getDirChildren(dir, dirsList)
	childNoTechCount := 0
	for _, child := range children {
		childNoTechList := getDirNoTechList(technologiesDetected, child, dirsList)
		if len(childNoTechList) > 0 {
			childNoTechCount++
		}
		noTechList = append(noTechList, childNoTechList...)
	}
	if childNoTechCount == len(children) {
		// If all children exists in childNoTechList, add only the parent directory to NoTech
		noTechList = []string{dir}
	}

	// for _, techDirs := range technologiesDetected {
	// 	if _, exist := techDirs[dir]; exist {
	// 		// The directory is already mapped to a technology, no need to add the dir or its sub directories to NoTech
	// 		break
	// 	}
	// 	for _, child := range children {
	// 		childNoTechList := getDirNoTechList(technologiesDetected, child, dirsList)
	// 	}

	// 	if len(children) == 0 {
	// 		// No children directories, add the directory to NoTech
	// 		childNoTechList = append(childNoTechList, dir)
	// 		break
	// 	}
	// 	for _, child := range children {
	// 		childNoTechList = append(childNoTechList, getDirNoTechList(technologiesDetected, child, dirsList)...)
	// 	}
	// 	// If all children exists in childNoTechList, add only the parent directory to NoTech
	// 	if len(children) == len(childNoTechList) {
	// 		childNoTechList = []string{dir}
	// 	}
	// }
	return
}

func getDirChildren(dir string, dirsList []string) (children []string) {
	for _, dirPath := range dirsList {
		if filepath.Dir(dirPath) == dir {
			children = append(children, dirPath)
		}
	}
	return
}

// func addNoTechIfNeeded(technologiesDetected map[Technology]map[string][]string, path, excludePathPattern string) (finalMap map[Technology]map[string][]string, err error) {
// 	finalMap = technologiesDetected
// 	noTechMap := map[string][]string{}
// 	// TODO: not only direct, need to see if multiple levels of directories are missing technology indicators
// 	// if all directories in are found no need for anything else,
// 	// if one missing need to add it to NoTech
// 	// if not one detected add only parent directory no need for each directory
// 	directories, err := getDirectDirectories(path, excludePathPattern)
// 	if err != nil {
// 		return
// 	}
// 	for _, dir := range directories {
// 		// Check if the directory is already mapped to a technology
// 		isMapped := false
// 		for _, techDirs := range finalMap {
// 			if _, exist := techDirs[dir]; exist {
// 				isMapped = true
// 				break
// 			}
// 		}
// 		if !isMapped {
// 			// Add the directory to NoTech (no indicators/descriptors were found)
// 			noTechMap[dir] = []string{}
// 		}
// 	}
// 	if len(technologiesDetected) == 0 || len(noTechMap) > 0 {
// 		// no technologies detected at all (add NoTech without any directories) or some directories were added to NoTech
// 		finalMap[NoTech] = noTechMap
// 	}
// 	return
// }

// func getDirectDirectories(path, excludePathPattern string) (directories []string, err error) {
// 	// Get all files and directories in the path, not recursive
// 	filesOrDirsInPath, err := fspatterns.ListFiles(path, false, true, true, true, excludePathPattern)
// 	if err != nil {
// 		return
// 	}
// 	// Filter to directories only
// 	for _, potentialDir := range filesOrDirsInPath {
// 		isDir, e := fileutils.IsDirExists(potentialDir, true)
// 		if e != nil {
// 			err = errors.Join(err, fmt.Errorf("failed to check if %s is a directory: %w", potentialDir, e))
// 			continue
// 		}
// 		if isDir {
// 			directories = append(directories, potentialDir)
// 		}
// 	}
// 	return
// }

// Map files to relevant working directories according to the technologies' indicators/descriptors and requested descriptors.
// files: The file paths to map.
// requestedDescriptors: Special requested descriptors (for example in Pip requirement.txt can have different path) for each technology.
// Returns:
//  1. workingDirectoryToIndicators: A map of working directories to the files that are relevant to the technologies.
//     wd1: [wd1/indicator, wd1/descriptor]
//     wd/wd2: [wd/wd2/indicator]
//  2. excludedTechAtWorkingDir: A map of working directories to the technologies that are excluded from the working directory.
//     wd1: [tech1, tech2]
//     wd/wd2: [tech1]
func mapFilesToRelevantWorkingDirectories(files []string, requestedDescriptors map[Technology][]string) (workingDirectoryToIndicators map[string][]string, excludedTechAtWorkingDir map[string][]Technology, err error) {
	workingDirectoryToIndicatorsSet := make(map[string]*datastructures.Set[string])
	excludedTechAtWorkingDir = make(map[string][]Technology)
	for _, path := range files {
		directory := filepath.Dir(path)

		for tech, techData := range technologiesData {
			// Check if the working directory contains indicators/descriptors for the technology
			indicator, e := tech.isIndicator(path)
			if e != nil {
				err = errors.Join(err, fmt.Errorf("failed to check if %s is an indicator of %s: %w", path, tech, e))
				continue
			}
			relevant := indicator || tech.isDescriptor(path) || isRequestedDescriptor(path, requestedDescriptors[tech])
			if relevant {
				if _, exist := workingDirectoryToIndicatorsSet[directory]; !exist {
					workingDirectoryToIndicatorsSet[directory] = datastructures.MakeSet[string]()
				}
				workingDirectoryToIndicatorsSet[directory].Add(path)
			}
			// Check if the working directory contains a file/directory with a name that ends with an excluded suffix
			if isExclude(path, techData) {
				excludedTechAtWorkingDir[directory] = append(excludedTechAtWorkingDir[directory], tech)
			}
		}
	}
	workingDirectoryToIndicators = make(map[string][]string)
	for wd, indicators := range workingDirectoryToIndicatorsSet {
		workingDirectoryToIndicators[wd] = indicators.ToSlice()
	}
	return
}

func isRequestedDescriptor(path string, requestedDescriptors []string) bool {
	for _, requestedDescriptor := range requestedDescriptors {
		if strings.HasSuffix(path, requestedDescriptor) {
			return true
		}
	}
	return false
}

func checkPotentialIndicator(path string, validator ContentValidator) (isIndicator bool, err error) {
	if validator == nil {
		isIndicator = true
		return
	}
	data, err := fileutils.ReadFile(path)
	if err != nil {
		return
	}
	return validator(data), nil
}

func isExclude(path string, techData TechData) bool {
	for _, exclude := range techData.exclude {
		if strings.HasSuffix(path, exclude) {
			return true
		}
	}
	return false
}

// Map working directories to technologies according to the given workingDirectoryToIndicators map files.
// workingDirectoryToIndicators: A map of working directories to the files inside the directory that are relevant to the technologies.
// excludedTechAtWorkingDir: A map of working directories to the technologies that are excluded from the working directory.
// requestedTechs: The technologies to check, if empty all technologies will be checked.
// requestedDescriptors: Special requested descriptors (for example in Pip requirement.txt can have different path) for each technology to detect.
func mapWorkingDirectoriesToTechnologies(workingDirectoryToIndicators map[string][]string, excludedTechAtWorkingDir map[string][]Technology, requestedTechs []Technology, requestedDescriptors map[Technology][]string) (technologiesDetected map[Technology]map[string][]string, err error) {
	// Get the relevant technologies to check
	technologies := requestedTechs
	var techProvidedByUser bool
	if len(technologies) == 0 {
		technologies = GetAllTechnologiesList()
	} else {
		// If the project's technology was provided by the user, and isn't detected by us, we want to enable capturing the technology by its descriptor as well as by its indicators.
		// In case we execute our auto-detection we want to avoid that since it may lead to collisions between package managers with the same descriptor (like Npm and Yarn)
		techProvidedByUser = true
		log.Debug(fmt.Sprintf("Technologies were identified either from the command flags supplied by the user or inferred from the provided installation command. Detected technologies: %s.", technologies))
	}
	technologiesDetected = make(map[Technology]map[string][]string)
	// Map working directories to technologies
	for _, tech := range technologies {
		if techWorkingDirs, e := getTechInformationFromWorkingDir(tech, workingDirectoryToIndicators, excludedTechAtWorkingDir, requestedDescriptors, techProvidedByUser); e != nil {
			err = errors.Join(err, fmt.Errorf("failed to get information from working directory for %s", tech))
		} else if len(techWorkingDirs) > 0 {
			// Found indicators of the technology, add to detected.
			technologiesDetected[tech] = techWorkingDirs
		}
	}
	for _, tech := range requestedTechs {
		if _, exist := technologiesDetected[tech]; !exist {
			// Requested (forced with flag) technology and not found any indicators/descriptors in detection, add as detected.
			log.Warn(fmt.Sprintf("Requested technology %s but not found any indicators/descriptors in detection.", tech))
			technologiesDetected[tech] = map[string][]string{}
		}
	}
	return
}

func getTechInformationFromWorkingDir(tech Technology, workingDirectoryToIndicators map[string][]string, excludedTechAtWorkingDir map[string][]Technology, requestedDescriptors map[Technology][]string, techProvidedByUser bool) (techWorkingDirs map[string][]string, err error) {
	techWorkingDirs = make(map[string][]string)
	for wd, indicators := range workingDirectoryToIndicators {
		descriptorsAtWd := []string{}
		foundIndicator := false
		foundDescriptor := false
		if isTechExcludedInWorkingDir(tech, wd, excludedTechAtWorkingDir) {
			// Exclude this technology from this working directory
			continue
		}
		// Check if the working directory contains indicators/descriptors for the technology
		for _, path := range indicators {
			if tech.isDescriptor(path) || isRequestedDescriptor(path, requestedDescriptors[tech]) {
				descriptorsAtWd = append(descriptorsAtWd, path)
				foundDescriptor = true
			}
			if indicator, e := tech.isIndicator(path); e != nil {
				err = errors.Join(err, fmt.Errorf("failed to check if %s is an indicator of %s: %w", path, tech, e))
				continue
			} else if indicator || isRequestedDescriptor(path, requestedDescriptors[tech]) {
				foundIndicator = true
			}
		}
		if foundIndicator || (foundDescriptor && techProvidedByUser) {
			// If indicators of the technology were found in the current working directory, add to detected.
			// If descriptors were found for a specific tech that was provided by the user, we add the descriptor to detected.
			techWorkingDirs[wd] = descriptorsAtWd
		}
	}
	// Don't allow working directory if sub directory already exists as key for the same technology
	techWorkingDirs = cleanSubDirectories(techWorkingDirs)
	return
}

func isTechExcludedInWorkingDir(tech Technology, wd string, excludedTechAtWorkingDir map[string][]Technology) bool {
	if excludedTechs, exist := excludedTechAtWorkingDir[wd]; exist {
		for _, excludedTech := range excludedTechs {
			if excludedTech == tech {
				return true
			}
		}
	}
	return false
}

// Remove sub directories keys from the given workingDirectoryToFiles map.
// Keys: [dir/dir, dir/directory] -> [dir/dir, dir/directory]
// Keys: [dir, directory] -> [dir, directory]
// Keys: [dir/dir2, dir/dir2/dir3, dir/dir2/dir3/dir4] -> [dir/dir2]
// Values of removed sub directories will be added to the root directory.
func cleanSubDirectories(workingDirectoryToFiles map[string][]string) (result map[string][]string) {
	result = make(map[string][]string)
	for wd, files := range workingDirectoryToFiles {
		root := getExistingRootDir(wd, workingDirectoryToFiles)
		result[root] = append(result[root], files...)
	}
	return
}

// Get the root directory of the given path according to the given workingDirectoryToIndicators map.
func getExistingRootDir(path string, workingDirectoryToIndicators map[string][]string) (root string) {
	root = path
	for wd := range workingDirectoryToIndicators {
		parentWd := filepath.Dir(wd)
		parentRoot := filepath.Dir(root)
		if parentRoot != parentWd && hasCompletePathPrefix(root, wd) {
			root = wd
		}
	}
	return
}

// This functions checks if wd is a PATH prefix for root. Examples:
// root = dir1/dir2/dir3 | wd = dir1/dir --> false (wd is prefix to root, but is not actually a valid part of its path)
// root = dir1/dir2/dir3 | wd = dir1/dir2 --> true
func hasCompletePathPrefix(root, wd string) bool {
	if !strings.HasPrefix(root, wd) {
		return false
	}
	rootParts := strings.Split(root, string(filepath.Separator))
	wdParts := strings.Split(wd, string(filepath.Separator))
	idxToCheck := len(wdParts) - 1
	return rootParts[idxToCheck] == wdParts[idxToCheck]
}

// DetectedTechnologiesToSlice returns a string slice that includes all the names of the detected technologies.
func DetectedTechnologiesToSlice(detected map[Technology]map[string][]string) []string {
	keys := make([]string, 0, len(detected))
	for tech := range detected {
		if tech == NoTech {
			continue
		}
		keys = append(keys, string(tech))
	}
	return keys
}

func ToTechnologies(args []string) (technologies []Technology) {
	for _, argument := range args {
		technologies = append(technologies, Technology(argument))
	}
	return
}

func GetAllTechnologiesList() (technologies []Technology) {
	for tech := range technologiesData {
		technologies = append(technologies, tech)
	}
	return
}

// SplitComponentId splits a Xray component ID to the component name, version and package type.
// In case componentId doesn't contain a version, the returned version will be an empty string.
// In case componentId's format is invalid, it will be returned as the component name
// and empty strings will be returned instead of the version and the package type.
// Examples:
//  1. componentId: "gav://antparent:ant:1.6.5"
//     Returned values:
//     Component name: "antparent:ant"
//     Component version: "1.6.5"
//     Package type: "Maven"
//  2. componentId: "generic://sha256:244fd47e07d1004f0aed9c156aa09083c82bf8944eceb67c946ff7430510a77b/foo.jar"
//     Returned values:
//     Component name: "foo.jar"
//     Component version: ""
//     Package type: "Generic"
//  3. componentId: "invalid-comp-id"
//     Returned values:
//     Component name: "invalid-comp-id"
//     Component version: ""
//     Package type: ""
func SplitComponentId(componentId string) (string, string, string) {
	compIdParts := strings.Split(componentId, "://")
	// Invalid component ID
	if len(compIdParts) != 2 {
		return componentId, "", ""
	}

	packageType := compIdParts[0]
	packageId := compIdParts[1]

	// Generic identifier structure: generic://sha256:<Checksum>/name
	if packageType == "generic" {
		lastSlashIndex := strings.LastIndex(packageId, "/")
		return packageId[lastSlashIndex+1:], "", packageTypes[packageType]
	}

	var compName, compVersion string
	switch packageType {
	case "rpm":
		// RPM identifier structure: rpm://os-version:package:epoch-version:version
		// os-version is optional.
		splitCompId := strings.Split(packageId, ":")
		if len(splitCompId) >= 3 {
			compName = splitCompId[len(splitCompId)-3]
			compVersion = fmt.Sprintf("%s:%s", splitCompId[len(splitCompId)-2], splitCompId[len(splitCompId)-1])
		}
	default:
		// All other identifiers look like this: package-type://package-name:version.
		// Sometimes there's a namespace or a group before the package name, separated by a '/' or a ':'.
		lastColonIndex := strings.LastIndex(packageId, ":")

		if lastColonIndex != -1 {
			compName = packageId[:lastColonIndex]
			compVersion = packageId[lastColonIndex+1:]
		}
	}

	// If there's an error while parsing the component ID
	if compName == "" {
		compName = packageId
	}

	return compName, compVersion, packageTypes[packageType]
}
