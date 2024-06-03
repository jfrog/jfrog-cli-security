package utils

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
)
const Pypi = "pypi"

type CodeLanguage string

const (
	JavaScript CodeLanguage = "javascript"
	Python     CodeLanguage = "python"
	GoLang     CodeLanguage = "go"
	Java       CodeLanguage = "java"
	CSharp     CodeLanguage = "C#"
)

type TechData struct {
	// The name of the package type used in this technology.
	packageType string
	// Suffixes of file/directory names that indicate if a project uses this technology.
	// The name of at least one of the files/directories in the project's directory must end with one of these suffixes.
	indicators []string
	// If suffix provides a content validator and the file/directory name matches, the content of the file will be validated to check if it is the indicator first.
	validators map[string]ContentValidator
	// Suffixes of file/directory names that indicate if a project does not use this technology.
	// The names of all the files/directories in the project's directory must NOT end with any of these suffixes.
	exclude []string
	// Whether this technology is supported by the 'jf ci-setup' command.
	ciSetupSupport bool
	// Whether Contextual Analysis supported in this technology.
	applicabilityScannable bool
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
		indicators:             []string{"pom.xml"},
		ciSetupSupport:         true,
		packageDescriptors:     []string{"pom.xml"},
		execCommand:            "mvn",
		applicabilityScannable: true,
	},
	Gradle: {
		indicators:             []string{"build.gradle", "build.gradle.kts"},
		ciSetupSupport:         true,
		packageDescriptors:     []string{"build.gradle", "build.gradle.kts"},
		applicabilityScannable: true,
	},
	Npm: {
		indicators:                 []string{"package.json", "package-lock.json", "npm-shrinkwrap.json"},
		exclude:                    []string{"pnpm-lock.yaml", ".yarnrc.yml", "yarn.lock", ".yarn"},
		ciSetupSupport:             true,
		packageDescriptors:         []string{"package.json"},
		formal:                     string(Npm),
		packageVersionOperator:     "@",
		packageInstallationCommand: "install",
		applicabilityScannable:     true,
	},
	Pnpm: {
		indicators:                 []string{"pnpm-lock.yaml"},
		exclude:                    []string{".yarnrc.yml", "yarn.lock", ".yarn"},
		packageDescriptors:         []string{"package.json"},
		packageVersionOperator:     "@",
		packageInstallationCommand: "update",
		applicabilityScannable:     true,
	},
	Yarn: {
		indicators:             []string{".yarnrc.yml", "yarn.lock", ".yarn", ".yarnrc"},
		exclude:                []string{"pnpm-lock.yaml"},
		packageDescriptors:     []string{"package.json"},
		packageVersionOperator: "@",
		applicabilityScannable: true,
	},
	Go: {
		indicators:                 []string{"go.mod"},
		packageDescriptors:         []string{"go.mod"},
		packageVersionOperator:     "@v",
		packageInstallationCommand: "get",
	},
	Pip: {
		packageType:            Pypi,
		indicators:             []string{"pyproject.toml", "setup.py", "requirements.txt"},
		validators:             map[string]ContentValidator{"pyproject.toml": pyProjectTomlIndicatorContent(Pip)},
		packageDescriptors:     []string{"setup.py", "requirements.txt", "pyproject.toml"},
		exclude:                []string{"Pipfile", "Pipfile.lock", "poetry.lock"},
		applicabilityScannable: true,
	},
	Pipenv: {
		packageType:                Pypi,
		indicators:                 []string{"Pipfile", "Pipfile.lock"},
		packageDescriptors:         []string{"Pipfile"},
		packageVersionOperator:     "==",
		packageInstallationCommand: "install",
		applicabilityScannable:     true,
	},
	Poetry: {
		packageType:                Pypi,
		indicators:                 []string{"pyproject.toml", "poetry.lock"},
		validators:                 map[string]ContentValidator{"pyproject.toml": pyProjectTomlIndicatorContent(Poetry)},
		packageDescriptors:         []string{"pyproject.toml"},
		packageInstallationCommand: "add",
		packageVersionOperator:     "==",
		applicabilityScannable:     true,
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
	Docker: {
		applicabilityScannable: true,
	},
	Oci: {
		applicabilityScannable: true,
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
		return true
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

func (tech Technology) GetPackageDescriptor() []string {
	return technologiesData[tech].packageDescriptors
}

func (tech Technology) IsCiSetup() bool {
	return technologiesData[tech].ciSetupSupport
}

func (tech Technology) GetPackageVersionOperator() string {
	return technologiesData[tech].packageVersionOperator
}

func (tech Technology) GetPackageInstallationCommand() string {
	return technologiesData[tech].packageInstallationCommand
}

func (tech Technology) ApplicabilityScannable() bool {
	return technologiesData[tech].applicabilityScannable
}

func DetectedTechnologiesList() (technologies []string) {
	wd, err := os.Getwd()
	if errorutils.CheckError(err) != nil {
		return
	}
	return detectedTechnologiesListInPath(wd, false)
}

func detectedTechnologiesListInPath(path string, recursive bool) (technologies []string) {
	detectedTechnologies, err := DetectTechnologies(path, false, recursive)
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
// If requestedTechs is empty, all technologies will be checked.
// If excludePathPattern is not empty, files/directories that match the wildcard pattern will be excluded from the search.
func DetectTechnologiesDescriptors(path string, recursive bool, requestedTechs []string, requestedDescriptors map[Technology][]string, excludePathPattern string) (technologiesDetected map[Technology]map[string][]string, err error) {
	filesList, err := fspatterns.ListFiles(path, recursive, false, true, true, excludePathPattern)
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
	if len(technologiesDetected) > 0 {
		log.Debug(fmt.Sprintf("Detected %d technologies at %s: %s.", len(technologiesDetected), path, maps.Keys(technologiesDetected)))
	}
	return
}

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
			indicator, e := isIndicator(path, techData)
			if e != nil {
				err = errors.Join(err, fmt.Errorf("failed to check if %s is an indicator of %s: %w", path, tech, e))
				continue
			}
			relevant := indicator || isDescriptor(path, techData) || isRequestedDescriptor(path, requestedDescriptors[tech])
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

func isDescriptor(path string, techData TechData) bool {
	for _, descriptor := range techData.packageDescriptors {
		if strings.HasSuffix(path, descriptor) {
			return true
		}
	}
	return false
}

func isRequestedDescriptor(path string, requestedDescriptors []string) bool {
	for _, requestedDescriptor := range requestedDescriptors {
		if strings.HasSuffix(path, requestedDescriptor) {
			return true
		}
	}
	return false
}

func isIndicator(path string, techData TechData) (bool, error) {
	for _, suffix := range techData.indicators {
		if strings.HasSuffix(path, suffix) {
			return checkPotentialIndicator(path, techData.validators[suffix])
		}
	}
	return false, nil
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
	if len(technologies) == 0 {
		technologies = GetAllTechnologiesList()
	}
	technologiesDetected = make(map[Technology]map[string][]string)
	// Map working directories to technologies
	for _, tech := range technologies {
		if techWorkingDirs, e := getTechInformationFromWorkingDir(tech, workingDirectoryToIndicators, excludedTechAtWorkingDir, requestedDescriptors); e != nil {
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

func getTechInformationFromWorkingDir(tech Technology, workingDirectoryToIndicators map[string][]string, excludedTechAtWorkingDir map[string][]Technology, requestedDescriptors map[Technology][]string) (techWorkingDirs map[string][]string, err error) {
	techWorkingDirs = make(map[string][]string)
	for wd, indicators := range workingDirectoryToIndicators {
		descriptorsAtWd := []string{}
		foundIndicator := false
		if isTechExcludedInWorkingDir(tech, wd, excludedTechAtWorkingDir) {
			// Exclude this technology from this working directory
			continue
		}
		// Check if the working directory contains indicators/descriptors for the technology
		for _, path := range indicators {
			if isDescriptor(path, technologiesData[tech]) || isRequestedDescriptor(path, requestedDescriptors[tech]) {
				descriptorsAtWd = append(descriptorsAtWd, path)
			}
			if indicator, e := isIndicator(path, technologiesData[tech]); e != nil {
				err = errors.Join(err, fmt.Errorf("failed to check if %s is an indicator of %s: %w", path, tech, e))
				continue
			} else if indicator || isRequestedDescriptor(path, requestedDescriptors[tech]) {
				foundIndicator = true
			}
		}
		if foundIndicator {
			// Found indicators of the technology in the current working directory, add to detected.
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
		if parentRoot != parentWd && strings.HasPrefix(root, wd) {
			root = wd
		}
	}
	return
}

// DetectTechnologies tries to detect all technologies types according to the files in the given path.
// 'isCiSetup' will limit the search of possible techs to Maven, Gradle, and npm.
// 'recursive' will determine if the search will be limited to files in the root path or not.
func DetectTechnologies(path string, isCiSetup, recursive bool) (map[Technology]bool, error) {
	var filesList []string
	var err error
	if recursive {
		filesList, err = fileutils.ListFilesRecursiveWalkIntoDirSymlink(path, false)
	} else {
		filesList, err = fileutils.ListFiles(path, true)
	}
	if err != nil {
		return nil, err
	}
	log.Info(fmt.Sprintf("Scanning %d file(s):%s", len(filesList), filesList))
	return detectTechnologiesByFilePaths(filesList, isCiSetup)
}

func detectTechnologiesByFilePaths(paths []string, isCiSetup bool) (detected map[Technology]bool, err error) {
	detected = make(map[Technology]bool)
	exclude := make(map[Technology]bool)
	for _, path := range paths {
		for techName, techData := range technologiesData {
			// If the detection is in a 'jf ci-setup' command, then the checked technology must be supported.
			if !isCiSetup || (isCiSetup && techData.ciSetupSupport) {
				// If the project contains a file/directory with a name that ends with an excluded suffix, then this technology is excluded.
				for _, excludeFile := range techData.exclude {
					if strings.HasSuffix(path, excludeFile) {
						exclude[techName] = true
					}
				}
				// If this technology was already excluded, there's no need to look for indicator files/directories.
				if _, exist := exclude[techName]; !exist {
					// If the project contains a file/directory with a name that ends with the indicator suffix, then the project probably uses this technology.
					if indicator, e := isIndicator(path, techData); e != nil {
						err = errors.Join(err, fmt.Errorf("failed to check if %s is an indicator of %s: %w", path, techName, e))
					} else if indicator {
						detected[techName] = true
					}
				}
			}
		}
	}
	// Remove excluded technologies.
	for excludeTech := range exclude {
		delete(detected, excludeTech)
	}
	return detected, err
}

// DetectedTechnologiesToSlice returns a string slice that includes all the names of the detected technologies.
func DetectedTechnologiesToSlice(detected map[Technology]bool) []string {
	keys := make([]string, 0, len(detected))
	for tech := range detected {
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

func ContainsApplicabilityScannableTech(technologies []Technology) bool {
	for _, technology := range technologies {
		if technology.ApplicabilityScannable() {
			return true
		}
	}
	return false
}
