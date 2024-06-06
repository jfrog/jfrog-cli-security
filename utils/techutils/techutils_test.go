package techutils

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/maps"
)

func TestMapFilesToRelevantWorkingDirectories(t *testing.T) {
	noRequest := map[Technology][]string{}
	noExclude := map[string][]Technology{}

	tests := []struct {
		name                 string
		paths                []string
		requestedDescriptors map[Technology][]string
		expectedWorkingDir   map[string][]string
		expectedExcluded     map[string][]Technology
	}{
		{
			name:                 "noTechTest",
			paths:                []string{"pomxml", filepath.Join("sub1", "file"), filepath.Join("sub", "sub", "file")},
			requestedDescriptors: noRequest,
			expectedWorkingDir:   map[string][]string{},
			expectedExcluded:     noExclude,
		},
		{
			name:                 "mavenTest",
			paths:                []string{"pom.xml", filepath.Join("sub1", "pom.xml"), filepath.Join("sub2", "pom.xml")},
			requestedDescriptors: noRequest,
			expectedWorkingDir: map[string][]string{
				".":    {"pom.xml"},
				"sub1": {filepath.Join("sub1", "pom.xml")},
				"sub2": {filepath.Join("sub2", "pom.xml")},
			},
			expectedExcluded: noExclude,
		},
		{
			name:                 "npmTest",
			paths:                []string{filepath.Join("dir", "package.json"), filepath.Join("dir", "package-lock.json"), filepath.Join("dir2", "npm-shrinkwrap.json")},
			requestedDescriptors: noRequest,
			expectedWorkingDir: map[string][]string{
				"dir":  {filepath.Join("dir", "package.json"), filepath.Join("dir", "package-lock.json")},
				"dir2": {filepath.Join("dir2", "npm-shrinkwrap.json")},
			},
			expectedExcluded: noExclude,
		},
		{
			name:                 "pnpmTest",
			paths:                []string{filepath.Join("dir", "package.json"), filepath.Join("dir", "pnpm-lock.yaml")},
			requestedDescriptors: noRequest,
			expectedWorkingDir:   map[string][]string{"dir": {filepath.Join("dir", "package.json"), filepath.Join("dir", "pnpm-lock.yaml")}},
			expectedExcluded:     map[string][]Technology{"dir": {Npm, Yarn}},
		},
		{
			name:                 "yarnTest",
			paths:                []string{filepath.Join("dir", "package.json"), filepath.Join("dir", ".yarn")},
			requestedDescriptors: noRequest,
			expectedWorkingDir:   map[string][]string{"dir": {filepath.Join("dir", "package.json"), filepath.Join("dir", ".yarn")}},
			expectedExcluded:     map[string][]Technology{"dir": {Npm, Pnpm}},
		},
		{
			name:                 "golangTest",
			paths:                []string{filepath.Join("dir", "dir2", "go.mod")},
			requestedDescriptors: noRequest,
			expectedWorkingDir:   map[string][]string{filepath.Join("dir", "dir2"): {filepath.Join("dir", "dir2", "go.mod")}},
			expectedExcluded:     noExclude,
		},
		{
			name: "pipTest",
			paths: []string{
				filepath.Join("users_dir", "test", "package", "setup.py"),
				filepath.Join("users_dir", "test", "package", "blabla.txt"),
				filepath.Join("users_dir", "test", "package2", "requirements.txt"),
			},
			requestedDescriptors: noRequest,
			expectedWorkingDir: map[string][]string{
				filepath.Join("users_dir", "test", "package"):  {filepath.Join("users_dir", "test", "package", "setup.py")},
				filepath.Join("users_dir", "test", "package2"): {filepath.Join("users_dir", "test", "package2", "requirements.txt")}},
			expectedExcluded: noExclude,
		},
		{
			name:                 "pipRequestedDescriptorTest",
			paths:                []string{filepath.Join("dir", "blabla.txt"), filepath.Join("dir", "somefile")},
			requestedDescriptors: map[Technology][]string{Pip: {"blabla.txt"}},
			expectedWorkingDir:   map[string][]string{"dir": {filepath.Join("dir", "blabla.txt")}},
			expectedExcluded:     noExclude,
		},
		{
			name:                 "pipenvTest",
			paths:                []string{filepath.Join("users", "test", "package", "Pipfile")},
			requestedDescriptors: noRequest,
			expectedWorkingDir:   map[string][]string{filepath.Join("users", "test", "package"): {filepath.Join("users", "test", "package", "Pipfile")}},
			expectedExcluded:     map[string][]Technology{filepath.Join("users", "test", "package"): {Pip}},
		},
		{
			name:                 "gradleTest",
			paths:                []string{filepath.Join("users", "test", "package", "build.gradle"), filepath.Join("dir", "build.gradle.kts"), filepath.Join("dir", "file")},
			requestedDescriptors: noRequest,
			expectedWorkingDir: map[string][]string{
				filepath.Join("users", "test", "package"): {filepath.Join("users", "test", "package", "build.gradle")},
				"dir": {filepath.Join("dir", "build.gradle.kts")},
			},
			expectedExcluded: noExclude,
		},
		{
			name:                 "nugetTest",
			paths:                []string{filepath.Join("dir", "project.sln"), filepath.Join("dir", "sub1", "project.csproj"), filepath.Join("dir", "file")},
			requestedDescriptors: noRequest,
			expectedWorkingDir: map[string][]string{
				"dir":                        {filepath.Join("dir", "project.sln")},
				filepath.Join("dir", "sub1"): {filepath.Join("dir", "sub1", "project.csproj")},
			},
			expectedExcluded: noExclude,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detectedWd, detectedExcluded, err := mapFilesToRelevantWorkingDirectories(test.paths, test.requestedDescriptors)
			assert.NoError(t, err)
			// Assert working directories
			expectedKeys := maps.Keys(test.expectedWorkingDir)
			actualKeys := maps.Keys(detectedWd)
			assert.ElementsMatch(t, expectedKeys, actualKeys, "expected: %s, actual: %s", expectedKeys, actualKeys)
			for key, value := range test.expectedWorkingDir {
				assert.ElementsMatch(t, value, detectedWd[key], "expected: %s, actual: %s", value, detectedWd[key])
			}
			// Assert excluded
			expectedKeys = maps.Keys(test.expectedExcluded)
			actualKeys = maps.Keys(detectedExcluded)
			assert.ElementsMatch(t, expectedKeys, actualKeys, "expected: %s, actual: %s", expectedKeys, actualKeys)
			for key, value := range test.expectedExcluded {
				assert.ElementsMatch(t, value, detectedExcluded[key], "expected: %s, actual: %s", value, detectedExcluded[key])
			}
		})
	}
}

func TestMapWorkingDirectoriesToTechnologies(t *testing.T) {
	projectDir, callback := createTempDirWithPyProjectToml(t, Poetry)
	defer callback()
	noRequestSpecialDescriptors := map[Technology][]string{}
	noRequestTech := []Technology{}
	tests := []struct {
		name                         string
		workingDirectoryToIndicators map[string][]string
		excludedTechAtWorkingDir     map[string][]Technology
		requestedTechs               []Technology
		requestedDescriptors         map[Technology][]string

		expected map[Technology]map[string][]string
	}{
		{
			name:                         "noTechTest",
			workingDirectoryToIndicators: map[string][]string{},
			excludedTechAtWorkingDir:     map[string][]Technology{},
			requestedTechs:               noRequestTech,
			requestedDescriptors:         noRequestSpecialDescriptors,
			expected:                     map[Technology]map[string][]string{},
		},
		{
			name: "all techs test",
			workingDirectoryToIndicators: map[string][]string{
				"folder":                        {filepath.Join("folder", "pom.xml")},
				filepath.Join("folder", "sub1"): {filepath.Join("folder", "sub1", "pom.xml")},
				filepath.Join("folder", "sub2"): {filepath.Join("folder", "sub2", "pom.xml")},
				"dir":                           {filepath.Join("dir", "package.json"), filepath.Join("dir", "package-lock.json"), filepath.Join("dir", "build.gradle.kts"), filepath.Join("dir", "project.sln")},
				"directory":                     {filepath.Join("directory", "npm-shrinkwrap.json")},
				"dir3":                          {filepath.Join("dir3", "package.json"), filepath.Join("dir3", ".yarn")},
				projectDir:                      {filepath.Join(projectDir, "pyproject.toml")},
				filepath.Join("dir3", "dir"):    {filepath.Join("dir3", "dir", "package.json"), filepath.Join("dir3", "dir", "pnpm-lock.yaml")},
				filepath.Join("dir", "dir2"):    {filepath.Join("dir", "dir2", "go.mod")},
				filepath.Join("users_dir", "test", "package"):  {filepath.Join("users_dir", "test", "package", "setup.py")},
				filepath.Join("users_dir", "test", "package2"): {filepath.Join("users_dir", "test", "package2", "requirements.txt")},
				filepath.Join("users", "test", "package"):      {filepath.Join("users", "test", "package", "Pipfile"), filepath.Join("users", "test", "package", "build.gradle")},
				filepath.Join("dir", "sub1"):                   {filepath.Join("dir", "sub1", "project.csproj")},
			},
			excludedTechAtWorkingDir: map[string][]Technology{
				filepath.Join("users", "test", "package"): {Pip},
				"dir3":                       {Npm},
				filepath.Join("dir3", "dir"): {Npm, Yarn},
			},
			requestedTechs:       noRequestTech,
			requestedDescriptors: noRequestSpecialDescriptors,
			expected: map[Technology]map[string][]string{
				Maven: {"folder": {filepath.Join("folder", "pom.xml"), filepath.Join("folder", "sub1", "pom.xml"), filepath.Join("folder", "sub2", "pom.xml")}},
				Npm: {
					"dir":       {filepath.Join("dir", "package.json")},
					"directory": {},
				},
				Pnpm: {filepath.Join("dir3", "dir"): {filepath.Join("dir3", "dir", "package.json")}},
				Yarn: {"dir3": {filepath.Join("dir3", "package.json")}},
				Go:   {filepath.Join("dir", "dir2"): {filepath.Join("dir", "dir2", "go.mod")}},
				Pip: {
					filepath.Join("users_dir", "test", "package"):  {filepath.Join("users_dir", "test", "package", "setup.py")},
					filepath.Join("users_dir", "test", "package2"): {filepath.Join("users_dir", "test", "package2", "requirements.txt")},
				},
				Poetry: {projectDir: {filepath.Join(projectDir, "pyproject.toml")}},
				Pipenv: {filepath.Join("users", "test", "package"): {filepath.Join("users", "test", "package", "Pipfile")}},
				Gradle: {
					"dir": {filepath.Join("dir", "build.gradle.kts")},
					filepath.Join("users", "test", "package"): {filepath.Join("users", "test", "package", "build.gradle")},
				},
				Nuget:  {"dir": {filepath.Join("dir", "project.sln"), filepath.Join("dir", "sub1", "project.csproj")}},
				Dotnet: {"dir": {filepath.Join("dir", "project.sln"), filepath.Join("dir", "sub1", "project.csproj")}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detectedTech, err := mapWorkingDirectoriesToTechnologies(test.workingDirectoryToIndicators, test.excludedTechAtWorkingDir, test.requestedTechs, test.requestedDescriptors)
			assert.NoError(t, err)
			expectedKeys := maps.Keys(test.expected)
			detectedKeys := maps.Keys(detectedTech)
			assert.ElementsMatch(t, expectedKeys, detectedKeys, "expected: %s, actual: %s", expectedKeys, detectedKeys)
			for key, value := range test.expected {
				actualKeys := maps.Keys(detectedTech[key])
				expectedKeys := maps.Keys(value)
				assert.ElementsMatch(t, expectedKeys, actualKeys, "for tech %s, expected: %s, actual: %s", key, expectedKeys, actualKeys)
				for innerKey, innerValue := range value {
					assert.ElementsMatch(t, innerValue, detectedTech[key][innerKey], "expected: %s, actual: %s", innerValue, detectedTech[key][innerKey])
				}
			}
		})
	}
}

func TestGetExistingRootDir(t *testing.T) {
	tests := []struct {
		name                         string
		path                         string
		workingDirectoryToIndicators map[string][]string
		expected                     string
	}{
		{
			name:                         "empty",
			path:                         "",
			workingDirectoryToIndicators: map[string][]string{},
			expected:                     "",
		},
		{
			name: "no match",
			path: "dir",
			workingDirectoryToIndicators: map[string][]string{
				filepath.Join("folder", "sub1"):    {filepath.Join("folder", "sub1", "pom.xml")},
				"dir2":                             {filepath.Join("dir2", "go.mod")},
				"dir3":                             {},
				filepath.Join("directory", "dir2"): {filepath.Join("directory", "dir2", "go.mod")},
			},
			expected: "dir",
		},
		{
			name: "match root",
			path: filepath.Join("directory", "dir2"),
			workingDirectoryToIndicators: map[string][]string{
				filepath.Join("folder", "sub1"):    {filepath.Join("folder", "sub1", "pom.xml")},
				"dir2":                             {filepath.Join("dir2", "go.mod")},
				"dir3":                             {},
				filepath.Join("directory", "dir2"): {filepath.Join("directory", "dir2", "go.mod")},
			},
			expected: filepath.Join("directory", "dir2"),
		},
		{
			name: "match sub",
			path: filepath.Join("directory", "dir2"),
			workingDirectoryToIndicators: map[string][]string{
				filepath.Join("folder", "sub1"):    {filepath.Join("folder", "sub1", "pom.xml")},
				"dir2":                             {filepath.Join("dir2", "go.mod")},
				"directory":                        {},
				filepath.Join("directory", "dir2"): {filepath.Join("directory", "dir2", "go.mod")},
			},
			expected: "directory",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, getExistingRootDir(test.path, test.workingDirectoryToIndicators))
		})
	}
}

func TestCleanSubDirectories(t *testing.T) {
	tests := []struct {
		name                    string
		workingDirectoryToFiles map[string][]string
		expected                map[string][]string
	}{
		{
			name:                    "empty",
			workingDirectoryToFiles: map[string][]string{},
			expected:                map[string][]string{},
		},
		{
			name: "no sub directories",
			workingDirectoryToFiles: map[string][]string{
				"directory":                       {filepath.Join("directory", "file")},
				filepath.Join("dir", "dir"):       {filepath.Join("dir", "dir", "file")},
				filepath.Join("dir", "directory"): {filepath.Join("dir", "directory", "file")},
			},
			expected: map[string][]string{
				"directory":                       {filepath.Join("directory", "file")},
				filepath.Join("dir", "dir"):       {filepath.Join("dir", "dir", "file")},
				filepath.Join("dir", "directory"): {filepath.Join("dir", "directory", "file")},
			},
		},
		{
			name: "sub directories",
			workingDirectoryToFiles: map[string][]string{
				filepath.Join("dir", "dir"):                  {filepath.Join("dir", "dir", "file")},
				filepath.Join("dir", "directory"):            {filepath.Join("dir", "directory", "file")},
				"dir":                                        {filepath.Join("dir", "file")},
				"directory":                                  {filepath.Join("directory", "file")},
				filepath.Join("dir", "dir2"):                 {filepath.Join("dir", "dir2", "file")},
				filepath.Join("dir", "dir2", "dir3"):         {filepath.Join("dir", "dir2", "dir3", "file")},
				filepath.Join("dir", "dir2", "dir3", "dir4"): {filepath.Join("dir", "dir2", "dir3", "dir4", "file")},
			},
			expected: map[string][]string{
				"directory": {filepath.Join("directory", "file")},
				"dir": {
					filepath.Join("dir", "file"),
					filepath.Join("dir", "dir", "file"),
					filepath.Join("dir", "directory", "file"),
					filepath.Join("dir", "dir2", "file"),
					filepath.Join("dir", "dir2", "dir3", "file"),
					filepath.Join("dir", "dir2", "dir3", "dir4", "file"),
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cleaned := cleanSubDirectories(test.workingDirectoryToFiles)
			cleanedKeys := maps.Keys(cleaned)
			expectedKeys := maps.Keys(test.expected)
			assert.ElementsMatch(t, expectedKeys, cleanedKeys, "expected: %s, actual: %s", expectedKeys, cleanedKeys)
			for key, value := range test.expected {
				assert.ElementsMatch(t, value, cleaned[key], "expected: %s, actual: %s", value, cleaned[key])
			}
		})
	}
}

func createTempDirWithPyProjectToml(t *testing.T, tech Technology) (tmpDir string, callback func()) {
	tmpDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err, "Couldn't create temp dir")
	callback = func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir), "Couldn't remove temp dir")
	}
	content := ""
	// create the content of the file
	switch tech {
	case Poetry:
		content = "[tool.poetry]\nname = \"test\"\nversion = \"0.1.0\"\n\n[tool.poetry.dependencies]\npython = \"^3.8\"\nnumpy = \"^1.19.0\""
	case Pip:
		// setuptools
		content = "[build-system]\nbuild-backend = \"setuptools.build_meta\"\nrequires = [\"setuptools\", \"wheel\"]\n\n[project]\ndynamic = [\"dependencies\"]\nname = \"pip-test\"\nversion = \"1.0.0\""
	default:
		assert.Fail(t, "unsupported technology")
	}
	// create the file
	out, err := os.Create(filepath.Join(tmpDir, "pyproject.toml"))
	defer func() {
		assert.NoError(t, out.Close())
	}()
	assert.NoError(t, err)
	// write the content to the file
	_, err = out.Write([]byte(content))
	assert.NoError(t, err)
	return
}

func TestGetTechInformationFromWorkingDir(t *testing.T) {
	projectDir, callback := createTempDirWithPyProjectToml(t, Pip)
	defer callback()
	workingDirectoryToIndicators := map[string][]string{
		"folder":                        {filepath.Join("folder", "pom.xml")},
		filepath.Join("folder", "sub1"): {filepath.Join("folder", "sub1", "pom.xml")},
		filepath.Join("folder", "sub2"): {filepath.Join("folder", "sub2", "pom.xml")},
		"dir":                           {filepath.Join("dir", "package.json"), filepath.Join("dir", "package-lock.json"), filepath.Join("dir", "build.gradle.kts"), filepath.Join("dir", "project.sln"), filepath.Join("dir", "blabla.txt")},
		"directory":                     {filepath.Join("directory", "npm-shrinkwrap.json")},
		"dir3":                          {filepath.Join("dir3", "package.json"), filepath.Join("dir3", ".yarn")},
		projectDir:                      {filepath.Join(projectDir, "pyproject.toml")},
		filepath.Join("dir3", "dir"):    {filepath.Join("dir3", "dir", "package.json"), filepath.Join("dir3", "dir", "pnpm-lock.yaml")},
		filepath.Join("dir", "dir2"):    {filepath.Join("dir", "dir2", "go.mod")},
		filepath.Join("users_dir", "test", "package"):  {filepath.Join("users_dir", "test", "package", "setup.py")},
		filepath.Join("users_dir", "test", "package2"): {filepath.Join("users_dir", "test", "package2", "requirements.txt")},
		filepath.Join("users", "test", "package"):      {filepath.Join("users", "test", "package", "Pipfile"), filepath.Join("users", "test", "package", "build.gradle")},
		filepath.Join("dir", "sub1"):                   {filepath.Join("dir", "sub1", "project.csproj")},
	}
	excludedTechAtWorkingDir := map[string][]Technology{
		filepath.Join("users", "test", "package"): {Pip},
		"dir3":                       {Npm, Pnpm},
		filepath.Join("dir3", "dir"): {Npm, Yarn},
	}

	tests := []struct {
		name                 string
		tech                 Technology
		requestedDescriptors map[Technology][]string
		expected             map[string][]string
	}{
		{
			name:                 "mavenTest",
			tech:                 Maven,
			requestedDescriptors: map[Technology][]string{},
			expected: map[string][]string{
				"folder": {
					filepath.Join("folder", "pom.xml"),
					filepath.Join("folder", "sub1", "pom.xml"),
					filepath.Join("folder", "sub2", "pom.xml"),
				},
			},
		},
		{
			name:                 "npmTest",
			tech:                 Npm,
			requestedDescriptors: map[Technology][]string{},
			expected: map[string][]string{
				"dir":       {filepath.Join("dir", "package.json")},
				"directory": {},
			},
		},
		{
			name:                 "pnpmTest",
			tech:                 Pnpm,
			requestedDescriptors: map[Technology][]string{},
			expected:             map[string][]string{filepath.Join("dir3", "dir"): {filepath.Join("dir3", "dir", "package.json")}},
		},
		{
			name:                 "yarnTest",
			tech:                 Yarn,
			requestedDescriptors: map[Technology][]string{},
			expected:             map[string][]string{"dir3": {filepath.Join("dir3", "package.json")}},
		},
		{
			name:                 "golangTest",
			tech:                 Go,
			requestedDescriptors: map[Technology][]string{},
			expected:             map[string][]string{filepath.Join("dir", "dir2"): {filepath.Join("dir", "dir2", "go.mod")}},
		},
		{
			name:                 "pipTest",
			tech:                 Pip,
			requestedDescriptors: map[Technology][]string{},
			expected: map[string][]string{
				filepath.Join("users_dir", "test", "package"):  {filepath.Join("users_dir", "test", "package", "setup.py")},
				filepath.Join("users_dir", "test", "package2"): {filepath.Join("users_dir", "test", "package2", "requirements.txt")},
				projectDir: {filepath.Join(projectDir, "pyproject.toml")},
			},
		},
		{
			name:                 "pipRequestedDescriptorTest",
			tech:                 Pip,
			requestedDescriptors: map[Technology][]string{Pip: {"blabla.txt"}},
			expected: map[string][]string{
				"dir": {filepath.Join("dir", "blabla.txt")},
				filepath.Join("users_dir", "test", "package"):  {filepath.Join("users_dir", "test", "package", "setup.py")},
				filepath.Join("users_dir", "test", "package2"): {filepath.Join("users_dir", "test", "package2", "requirements.txt")},
				projectDir: {filepath.Join(projectDir, "pyproject.toml")},
			},
		},
		{
			name:                 "pipenvTest",
			tech:                 Pipenv,
			requestedDescriptors: map[Technology][]string{},
			expected:             map[string][]string{filepath.Join("users", "test", "package"): {filepath.Join("users", "test", "package", "Pipfile")}},
		},
		{
			name:                 "gradleTest",
			tech:                 Gradle,
			requestedDescriptors: map[Technology][]string{},
			expected: map[string][]string{
				filepath.Join("users", "test", "package"): {filepath.Join("users", "test", "package", "build.gradle")},
				"dir": {filepath.Join("dir", "build.gradle.kts")},
			},
		},
		{
			name:                 "nugetTest",
			tech:                 Nuget,
			requestedDescriptors: map[Technology][]string{},
			expected:             map[string][]string{"dir": {filepath.Join("dir", "project.sln"), filepath.Join("dir", "sub1", "project.csproj")}},
		},
		{
			name:                 "dotnetTest",
			tech:                 Dotnet,
			requestedDescriptors: map[Technology][]string{},
			expected:             map[string][]string{"dir": {filepath.Join("dir", "project.sln"), filepath.Join("dir", "sub1", "project.csproj")}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			techInformation, err := getTechInformationFromWorkingDir(test.tech, workingDirectoryToIndicators, excludedTechAtWorkingDir, test.requestedDescriptors)
			assert.NoError(t, err)
			expectedKeys := maps.Keys(test.expected)
			actualKeys := maps.Keys(techInformation)
			assert.ElementsMatch(t, expectedKeys, actualKeys, fmt.Sprintf("expected: %v, actual: %v", expectedKeys, actualKeys))
			for key, value := range test.expected {
				assert.ElementsMatch(t, value, techInformation[key], fmt.Sprintf("expected: %v, actual: %v", value, techInformation[key]))
			}
		})
	}
}

func TestTechnologyToLanguage(t *testing.T) {
	tests := []struct {
		name       string
		technology Technology
		language   CodeLanguage
	}{
		{name: "Maven to Java", technology: Maven, language: Java},
		{name: "Gradle to Java", technology: Gradle, language: Java},
		{name: "Npm to JavaScript", technology: Npm, language: JavaScript},
		{name: "Pnpm to JavaScript", technology: Pnpm, language: JavaScript},
		{name: "Yarn to JavaScript", technology: Yarn, language: JavaScript},
		{name: "Go to GoLang", technology: Go, language: GoLang},
		{name: "Pip to Python", technology: Pip, language: Python},
		{name: "Pipenv to Python", technology: Pipenv, language: Python},
		{name: "Poetry to Python", technology: Poetry, language: Python},
		{name: "Nuget to CSharp", technology: Nuget, language: CSharp},
		{name: "Dotnet to CSharp", technology: Dotnet, language: CSharp},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.language, TechnologyToLanguage(tt.technology), "TechnologyToLanguage(%v) == %v", tt.technology, tt.language)
		})
	}
}
