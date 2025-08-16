package techutils

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"
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
		expected                     map[Technology]map[string][]string
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
		{
			// When tech is requested by user we detect technology by indicator as well as by descriptors, therefore we can relate descriptor files to tech even when indicator doesn't exist
			name: "tech requested by user test",
			workingDirectoryToIndicators: map[string][]string{
				"dir3":     {filepath.Join("dir3", "package.json")},
				projectDir: {filepath.Join(projectDir, "pyproject.toml")},
			},
			requestedTechs:       []Technology{Yarn, Poetry},
			requestedDescriptors: noRequestSpecialDescriptors,
			expected: map[Technology]map[string][]string{
				Yarn:   {"dir3": {filepath.Join("dir3", "package.json")}},
				Poetry: {projectDir: {filepath.Join(projectDir, "pyproject.toml")}},
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

func TestAddNoTechIfNeeded(t *testing.T) {
	tmpDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err, "Couldn't create temp dir")
	assert.NoError(t, fileutils.CreateDirIfNotExist(filepath.Join(tmpDir, "folder")))
	assert.NoError(t, fileutils.CreateDirIfNotExist(filepath.Join(tmpDir, "tech-folder")))

	prevWd, err := os.Getwd()
	assert.NoError(t, err, "Couldn't get working directory")
	assert.NoError(t, os.Chdir(tmpDir), "Couldn't change working directory")
	defer func() {
		clientTests.ChangeDirAndAssert(t, prevWd)
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir), "Couldn't remove temp dir")
	}()

	tests := []struct {
		name                 string
		path                 string
		dirList              []string
		technologiesDetected map[Technology]map[string][]string
		expected             map[Technology]map[string][]string
	}{
		{
			name:                 "No tech detected",
			path:                 tmpDir,
			dirList:              []string{},
			technologiesDetected: map[Technology]map[string][]string{},
			expected:             map[Technology]map[string][]string{NoTech: {tmpDir: {}}},
		},
		{
			name:                 "No tech detected, sub dir",
			path:                 tmpDir,
			dirList:              []string{filepath.Join(tmpDir, "folder"), filepath.Join(tmpDir, "tech-folder")},
			technologiesDetected: map[Technology]map[string][]string{Npm: {filepath.Join(tmpDir, "tech-folder"): {}}},
			expected:             map[Technology]map[string][]string{Npm: {filepath.Join(tmpDir, "tech-folder"): {}}, NoTech: {filepath.Join(tmpDir, "folder"): {}}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := addNoTechIfNeeded(test.technologiesDetected, test.path, test.dirList)
			assert.Equal(t, test.expected, actual)
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
		{
			// This test case checks that we capture the correct root when sub is a prefix to root, but not an actual path prefix
			// Example: root = "dir1/dir2", sub = "dir" -> root indeed starts with 'dir' but 'dir' is not a path prefix to the root
			name: "match root when root's letters start with sub's letters",
			path: filepath.Join("dir3", "dir"),
			workingDirectoryToIndicators: map[string][]string{
				filepath.Join("dir3", "dir"): {filepath.Join("dir3", "dir", "package.json")},
				"dir":                        {filepath.Join("dir", "package.json")},
			},
			expected: filepath.Join("dir3", "dir"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, getExistingRootDir(test.path, test.workingDirectoryToIndicators))
		})
	}
}

func TestHasCompletePathPrefix(t *testing.T) {
	tests := []struct {
		name     string
		root     string
		wd       string
		expected bool
	}{
		{
			name:     "no prefix",
			root:     filepath.Join("dir1", "dir2"),
			wd:       filepath.Join("some", "other", "project"),
			expected: false,
		},
		{
			name:     "prefix but not a path prefix",
			root:     filepath.Join("dir1", "dir2"),
			wd:       "dir",
			expected: false,
		},
		{
			name:     "path prefix",
			root:     filepath.Join("dir1", "dir2"),
			wd:       "dir1",
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, hasCompletePathPrefix(test.root, test.wd))
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

func TestCleanSubDirectoriesForTechUnsupportedMulti(t *testing.T) {
	workingDirectoryToIndicators := map[string][]string{
		"project-root": {filepath.Join("project-root", "package.json")},
		filepath.Join("project-root", "directory"): {filepath.Join("project-root", "directory", "package.json")},
	}

	testCases := []struct {
		name                string
		cleanSubDirectories bool
		expected            map[string][]string
	}{
		{
			name:                "cleanSubDirectories is true",
			cleanSubDirectories: true,
			expected:            map[string][]string{"project-root": {filepath.Join("project-root", "package.json"), filepath.Join("project-root", "directory", "package.json")}},
		},
		{
			name: "cleanSubDirectories is false",
			expected: map[string][]string{
				"project-root": {filepath.Join("project-root", "package.json")},
				filepath.Join("project-root", "directory"): {filepath.Join("project-root", "directory", "package.json")},
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			if test.cleanSubDirectories {
				unsetEnv := clientTests.SetEnvWithCallbackAndAssert(t, JfrogCleanTechSubModulesEnv, "TRUE")
				defer unsetEnv()
			}
			assertTechInformation(t, Npm, workingDirectoryToIndicators, map[string][]Technology{}, map[Technology][]string{}, false, test.expected)
		})
	}
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
		"dir4":                          {filepath.Join("dir4", "package.json")},
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
		techProvidedByUser   bool
		expected             map[string][]string
	}{
		{
			name:                 "mavenTest",
			tech:                 Maven,
			requestedDescriptors: map[Technology][]string{},
			techProvidedByUser:   false,
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
			techProvidedByUser:   false,
			expected: map[string][]string{
				"dir":       {filepath.Join("dir", "package.json")},
				"dir4":      {filepath.Join("dir4", "package.json")},
				"directory": {},
			},
		},
		{
			name:                 "pnpmTest",
			tech:                 Pnpm,
			requestedDescriptors: map[Technology][]string{},
			techProvidedByUser:   false,
			expected:             map[string][]string{filepath.Join("dir3", "dir"): {filepath.Join("dir3", "dir", "package.json")}},
		},
		{
			name:                 "yarnTest",
			tech:                 Yarn,
			requestedDescriptors: map[Technology][]string{},
			techProvidedByUser:   false,
			expected:             map[string][]string{"dir3": {filepath.Join("dir3", "package.json")}},
		},
		{
			name:                 "golangTest",
			tech:                 Go,
			requestedDescriptors: map[Technology][]string{},
			techProvidedByUser:   false,
			expected:             map[string][]string{filepath.Join("dir", "dir2"): {filepath.Join("dir", "dir2", "go.mod")}},
		},
		{
			name:                 "pipTest",
			tech:                 Pip,
			requestedDescriptors: map[Technology][]string{},
			techProvidedByUser:   false,
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
			techProvidedByUser:   false,
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
			techProvidedByUser:   false,
			expected:             map[string][]string{filepath.Join("users", "test", "package"): {filepath.Join("users", "test", "package", "Pipfile")}},
		},
		{
			name:                 "gradleTest",
			tech:                 Gradle,
			requestedDescriptors: map[Technology][]string{},
			techProvidedByUser:   false,
			expected: map[string][]string{
				filepath.Join("users", "test", "package"): {filepath.Join("users", "test", "package", "build.gradle")},
				"dir": {filepath.Join("dir", "build.gradle.kts")},
			},
		},
		{
			name:                 "nugetTest",
			tech:                 Nuget,
			requestedDescriptors: map[Technology][]string{},
			techProvidedByUser:   false,
			expected:             map[string][]string{"dir": {filepath.Join("dir", "project.sln"), filepath.Join("dir", "sub1", "project.csproj")}},
		},
		{
			name:                 "dotnetTest",
			tech:                 Dotnet,
			requestedDescriptors: map[Technology][]string{},
			techProvidedByUser:   false,
			expected:             map[string][]string{"dir": {filepath.Join("dir", "project.sln"), filepath.Join("dir", "sub1", "project.csproj")}},
		},
		// When tech is provided by the user we detect technology by indicator and descriptors and not just by indicator. Test cases are provided only for technologies that might experience conflicts.
		{
			name:                 "yarnTestWithProvidedTechFromUser",
			tech:                 Yarn,
			requestedDescriptors: make(map[Technology][]string),
			techProvidedByUser:   true,
			expected: map[string][]string{
				"dir":  {filepath.Join("dir", "package.json")},
				"dir3": {filepath.Join("dir3", "package.json")},
				"dir4": {filepath.Join("dir4", "package.json")},
			},
		},
		{
			name:                 "pnpmTestWithProvidedTechFromUser",
			tech:                 Pnpm,
			requestedDescriptors: make(map[Technology][]string),
			techProvidedByUser:   true,
			expected: map[string][]string{
				filepath.Join("dir3", "dir"): {filepath.Join("dir3", "dir", "package.json")},
				"dir":                        {filepath.Join("dir", "package.json")},
				"dir4":                       {filepath.Join("dir4", "package.json")},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertTechInformation(t, test.tech, workingDirectoryToIndicators, excludedTechAtWorkingDir, test.requestedDescriptors, test.techProvidedByUser, test.expected)
		})
	}
}

func assertTechInformation(t *testing.T, tech Technology, workingDirectoryToIndicators map[string][]string, excludedTechAtWorkingDir map[string][]Technology, requestedDescriptors map[Technology][]string, techProvidedByUser bool, expected map[string][]string) {
	techInformation, err := getTechInformationFromWorkingDir(tech, workingDirectoryToIndicators, excludedTechAtWorkingDir, requestedDescriptors, techProvidedByUser)
	assert.NoError(t, err)
	expectedKeys := maps.Keys(expected)
	actualKeys := maps.Keys(techInformation)
	assert.ElementsMatch(t, expectedKeys, actualKeys, fmt.Sprintf("expected: %v, actual: %v", expectedKeys, actualKeys))
	for key, value := range expected {
		assert.ElementsMatch(t, value, techInformation[key], fmt.Sprintf("expected: %v, actual: %v", value, techInformation[key]))
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

func TestToCdxPackageType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"gav to maven", "gav", "maven"},
		{"docker to docker", "docker", "docker"},
		{"go to golang", "go", "golang"},
		{"unknown passthrough", "foobar", "foobar"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.expected, ToCdxPackageType(tt.input), "ToCdxPackageType(%v) == %v", tt.input, tt.expected)
		})
	}
}

func TestCdxPackageTypeToXrayPackageType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"maven to gav", "maven", "gav"},
		{"docker to docker", "docker", "docker"},
		{"golang to go", "golang", "go"},
		{"unknown passthrough", "foobar", "foobar"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.expected, CdxPackageTypeToXrayPackageType(tt.input), "CdxPackageTypeToXrayPackageType(%v) == %v", tt.input, tt.expected)
		})
	}
}

func TestSplitPackageUrlWithQualifiers(t *testing.T) {
	tests := []struct {
		name          string
		purl          string
		compName      string
		compNamespace string
		compVersion   string
		packageType   string
		qualifiers    map[string]string
	}{
		{
			name:          "npm scope with version",
			purl:          "pkg:npm/@scope/package@1.0.0",
			compName:      "package",
			compNamespace: "@scope",
			compVersion:   "1.0.0",
			packageType:   "npm",
			qualifiers:    map[string]string{},
		},
		{
			name:          "escaped npm scope with version",
			purl:          "pkg:npm/%40scope/package@1.0.0",
			compName:      "package",
			compNamespace: "@scope",
			compVersion:   "1.0.0",
			packageType:   "npm",
			qualifiers:    map[string]string{},
		},
		{
			name:          "golang with version",
			purl:          "pkg:golang/github.com/gophish/gophish@v0.1.2",
			compName:      "gophish",
			compNamespace: "github.com/gophish",
			compVersion:   "v0.1.2",
			packageType:   "golang",
			qualifiers:    map[string]string{},
		},
		{
			name:          "golang without version",
			purl:          "pkg:golang/github.com/go-gitea/gitea",
			compName:      "gitea",
			compNamespace: "github.com/go-gitea",
			packageType:   "golang",
			qualifiers:    map[string]string{},
		},
		{
			name:          "maven with qualifier",
			purl:          "pkg:maven/org.apache.commons/commons-lang3@3.12.0?package-id=d3f8d67af404667f",
			compName:      "commons-lang3",
			compNamespace: "org.apache.commons",
			compVersion:   "3.12.0",
			packageType:   "maven",
			qualifiers:    map[string]string{"package-id": "d3f8d67af404667f"},
		},
		{
			name:        "gav with version",
			purl:        "pkg:gav/xpp3:xpp3_min@1.1.4c",
			compName:    "xpp3:xpp3_min",
			compVersion: "1.1.4c",
			packageType: "gav",
			qualifiers:  map[string]string{},
		},
		{
			name:          "docker with namespace",
			purl:          "pkg:docker/docker.io/library/nginx@1.27-alpine",
			compName:      "nginx",
			compNamespace: "docker.io/library",
			compVersion:   "1.27-alpine",
			packageType:   "docker",
			qualifiers:    map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compType, namespace, name, version, qualifiers := SplitPackageUrlWithQualifiers(tt.purl)
			assert.Equalf(t, tt.packageType, compType, "SplitPackageUrlWithQualifiers(%v) compType == %v", tt.purl, tt.packageType)
			assert.Equalf(t, tt.compName, name, "SplitPackageUrlWithQualifiers(%v) compName == %v", tt.purl, tt.compName)
			assert.Equalf(t, tt.compNamespace, namespace, "SplitPackageUrlWithQualifiers(%v) compNamespace == %v", tt.purl, tt.compNamespace)
			assert.Equalf(t, tt.compVersion, version, "SplitPackageUrlWithQualifiers(%v) compVersion == %v", tt.purl, tt.compVersion)
			assert.Equalf(t, tt.qualifiers, qualifiers, "SplitPackageUrlWithQualifiers(%v) qualifiers == %v", tt.purl, tt.qualifiers)
		})
	}
}

func TestSplitPackageURL(t *testing.T) {
	tests := []struct {
		name        string
		purl        string
		compName    string
		compVersion string
		packageType string
	}{
		{"npm scope with version", "pkg:npm/@scope/package@1.0.0", "@scope/package", "1.0.0", "npm"},
		{"escaped npm scope with version", "pkg:npm/%40scope/package@1.0.0", "@scope/package", "1.0.0", "npm"},
		{"golang with version", "pkg:golang/github.com/gophish/gophish@v0.1.2", "github.com/gophish/gophish", "v0.1.2", "golang"},
		{"gav with version", "pkg:gav/xpp3:xpp3_min@1.1.4c", "xpp3:xpp3_min", "1.1.4c", "gav"},
		{"maven with qualifier", "pkg:maven/org.apache.commons/commons-lang3@3.12.0?package-id=d3f8d67af404667f", "org.apache.commons/commons-lang3", "3.12.0", "maven"},
		{"docker with namespace", "pkg:docker/docker.io/library/nginx@1.27-alpine", "docker.io/library/nginx", "1.27-alpine", "docker"},
		{"golang without version", "pkg:golang/github.com/go-gitea/gitea", "github.com/go-gitea/gitea", "", "golang"},
		{"generic", "pkg:generic/sha256:534a70dc82967ee32184e13d28ea485e909b20d3f13d553122bab3e4de03b50c/sha256__534a70dc82967ee32184e13d28ea485e909b20d3f13d553122bab3e4de03b50c.tar", "sha256:534a70dc82967ee32184e13d28ea485e909b20d3f13d553122bab3e4de03b50c/sha256__534a70dc82967ee32184e13d28ea485e909b20d3f13d553122bab3e4de03b50c.tar", "", "generic"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, version, compType := SplitPackageURL(tt.purl)
			assert.Equal(t, tt.compName, name, "compName")
			assert.Equal(t, tt.compVersion, version, "compVersion")
			assert.Equal(t, tt.packageType, compType, "packageType")
		})
	}
}

func TestToPackageUrl(t *testing.T) {
	tests := []struct {
		name        string
		compName    string
		version     string
		packageType string
		expected    string
	}{
		{"npm scope with version", "@scope/package", "1.0.0", "npm", "pkg:npm/@scope/package@1.0.0"},
		{"golang", "github.com/gophish/gophish", "v0.1.2", "golang", "pkg:golang/github.com/gophish/gophish@v0.1.2"},
		{"gav", "xpp3:xpp3_min", "1.1.4c", "gav", "pkg:gav/xpp3:xpp3_min@1.1.4c"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := ToPackageUrl(tt.compName, tt.version, tt.packageType)
			assert.Equalf(t, tt.expected, actual, "ToPackageUrl(%v, %v, %v) == %v", tt.compName, tt.version, tt.packageType, tt.expected)
		})
	}
}

func TestToPackageRef(t *testing.T) {
	tests := []struct {
		name        string
		compName    string
		version     string
		packageType string
		expected    string
	}{
		{"npm scope with version", "@scope/package", "1.0.0", "npm", "npm:@scope/package:1.0.0"},
		{"golang", "github.com/gophish/gophish", "v0.1.2", "golang", "golang:github.com/gophish/gophish:v0.1.2"},
		{"gav", "xpp3:xpp3_min", "1.1.4c", "gav", "gav:xpp3:xpp3_min:1.1.4c"},
		{"no version", "github.com/gophish/gophish", "", "golang", "golang:github.com/gophish/gophish"},
		{"root", "root", "", "", "generic:root"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := ToPackageRef(tt.compName, tt.version, tt.packageType)
			assert.Equalf(t, tt.expected, actual, "ToPackageRef(%v, %v, %v) == %v", tt.compName, tt.version, tt.packageType, tt.expected)
		})
	}
}

func TestPurlToXrayComponentId(t *testing.T) {
	tests := []struct {
		name     string
		purl     string
		expected string
	}{
		{"golang", "pkg:golang/github.com/gophish/gophish@v0.1.2", "go://github.com/gophish/gophish:v0.1.2"},
		{"no version golang", "pkg:golang/github.com/gophish/gophish", "go://github.com/gophish/gophish"},
		{"maven", "pkg:maven/xpp3:xpp3_min@1.1.4c", "gav://xpp3:xpp3_min:1.1.4c"},
		{"npm", "pkg:npm/@scope/package@1.0.0", "npm://@scope/package:1.0.0"},
		{"docker", "pkg:docker/docker.io/library/nginx@1.27-alpine", "docker://docker.io/library/nginx:1.27-alpine"},
		{"rpm", "pkg:rpm/openssl@0:1.1.0l-1.3.mga7", "rpm://openssl:0:1.1.0l-1.3.mga7"},
		{"root", "pkg:generic/root", "generic://root"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := PurlToXrayComponentId(tt.purl)
			assert.Equalf(t, tt.expected, actual, "PurlToXrayComponentId(%v) == %v", tt.purl, tt.expected)
		})
	}
}

func TestXrayComponentIdToPurl(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"npm", "npm://@scope/package:1.0.0", "pkg:npm/@scope/package@1.0.0"},
		{"gav", "gav://xpp3:xpp3_min:1.1.4c", "pkg:maven/xpp3:xpp3_min@1.1.4c"},
		{"npm", "npm://@scope/package:1.0.0", "pkg:npm/@scope/package@1.0.0"},
		{"go", "go://github.com/gophish/gophish:v0.1.2", "pkg:golang/github.com/gophish/gophish@v0.1.2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := XrayComponentIdToPurl(tt.input)
			assert.Equalf(t, tt.expected, actual, "XrayComponentIdToPurl(%v) == %v", tt.input, tt.expected)
		})
	}
}

func TestXrayComponentIdToCdxComponentRef(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"npm", "npm://@scope/package:1.0.0", "npm:@scope/package:1.0.0"},
		{"gav", "gav://xpp3:xpp3_min:1.1.4c", "maven:xpp3:xpp3_min:1.1.4c"},
		{"npm", "npm://@scope/package:1.0.0", "npm:@scope/package:1.0.0"},
		{"go", "go://github.com/gophish/gophish:v0.1.2", "golang:github.com/gophish/gophish:v0.1.2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := XrayComponentIdToCdxComponentRef(tt.input)
			assert.Equalf(t, tt.expected, actual, "XrayComponentIdToCdxComponentRef(%v) == %v", tt.input, tt.expected)
		})
	}
}

func TestWorkspaceAwareTechnologyDetection(t *testing.T) {
	// Create a temporary directory structure for testing
	tempDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err, "Couldn't create temp dir")
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tempDir), "Couldn't remove temp dir")
	}()
	// Create workspace root
	workspaceRoot := tempDir
	rootPackageJson := `{
		"name": "workspace-root",
		"workspaces": ["packages/*", "plugins/*"]
	}`
	assert.NoError(t, os.WriteFile(filepath.Join(workspaceRoot, "package.json"), []byte(rootPackageJson), 0644))
	assert.NoError(t, os.WriteFile(filepath.Join(workspaceRoot, "yarn.lock"), []byte("# yarn.lock"), 0644))

	// Create packages
	packagesDir := filepath.Join(workspaceRoot, "packages")
	assert.NoError(t, os.MkdirAll(packagesDir, 0755))

	appDir := filepath.Join(packagesDir, "app")
	assert.NoError(t, os.MkdirAll(appDir, 0755))
	appPackageJson := `{"name": "@workspace/app", "version": "1.0.0"}`
	assert.NoError(t, os.WriteFile(filepath.Join(appDir, "package.json"), []byte(appPackageJson), 0644))

	backendDir := filepath.Join(packagesDir, "backend")
	assert.NoError(t, os.MkdirAll(backendDir, 0755))
	backendPackageJson := `{"name": "@workspace/backend", "version": "1.0.0"}`
	assert.NoError(t, os.WriteFile(filepath.Join(backendDir, "package.json"), []byte(backendPackageJson), 0644))

	// Create plugins
	pluginsDir := filepath.Join(workspaceRoot, "plugins")
	assert.NoError(t, os.MkdirAll(pluginsDir, 0755))

	catalogDir := filepath.Join(pluginsDir, "catalog")
	assert.NoError(t, os.MkdirAll(catalogDir, 0755))
	catalogPackageJson := `{"name": "@workspace/catalog", "version": "1.0.0"}`
	assert.NoError(t, os.WriteFile(filepath.Join(catalogDir, "package.json"), []byte(catalogPackageJson), 0644))

	// Test technology detection
	technologiesDetected, err := DetectTechnologiesDescriptors(workspaceRoot, true, []string{}, map[Technology][]string{}, "")
	assert.NoError(t, err)

	// Verify that workspace root is detected as yarn
	assert.Contains(t, technologiesDetected, Yarn, "Workspace root should be detected as yarn")
	yarnDirs := technologiesDetected[Yarn]
	assert.Contains(t, yarnDirs, workspaceRoot, "Workspace root should be in yarn directories")

	// Verify that workspace packages are also detected as yarn (not npm)
	assert.Contains(t, yarnDirs, appDir, "App package should inherit yarn technology")
	assert.Contains(t, yarnDirs, backendDir, "Backend package should inherit yarn technology")
	assert.Contains(t, yarnDirs, catalogDir, "Catalog package should inherit yarn technology")

	// Verify that npm is not detected for workspace packages
	if npmDirs, exists := technologiesDetected[Npm]; exists {
		assert.NotContains(t, npmDirs, appDir, "App package should not be detected as npm")
		assert.NotContains(t, npmDirs, backendDir, "Backend package should not be detected as npm")
		assert.NotContains(t, npmDirs, catalogDir, "Catalog package should not be detected as npm")
	}

	// Verify the expected structure
	expectedYarnDirs := []string{workspaceRoot, appDir, backendDir, catalogDir}
	for _, expectedDir := range expectedYarnDirs {
		assert.Contains(t, yarnDirs, expectedDir, fmt.Sprintf("Directory %s should be detected as yarn", expectedDir))
	}

	t.Logf("Detected technologies: %v", maps.Keys(technologiesDetected))
	t.Logf("Yarn directories: %v", maps.Keys(yarnDirs))
}

func TestWorkspaceAwareTechnologyDetectionWithNpmWorkspace(t *testing.T) {
	// Create a temporary directory structure for npm workspace testing
	tempDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err, "Couldn't create temp dir")
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tempDir), "Couldn't remove temp dir")
	}()
	// Create workspace root
	workspaceRoot := tempDir
	rootPackageJson := `{
		"name": "npm-workspace-root",
		"workspaces": ["packages/*"]
	}`
	assert.NoError(t, os.WriteFile(filepath.Join(workspaceRoot, "package.json"), []byte(rootPackageJson), 0644))
	assert.NoError(t, os.WriteFile(filepath.Join(workspaceRoot, "package-lock.json"), []byte("{}"), 0644))

	// Create packages
	packagesDir := filepath.Join(workspaceRoot, "packages")
	assert.NoError(t, os.MkdirAll(packagesDir, 0755))

	appDir := filepath.Join(packagesDir, "app")
	assert.NoError(t, os.MkdirAll(appDir, 0755))
	appPackageJson := `{"name": "@workspace/app", "version": "1.0.0"}`
	assert.NoError(t, os.WriteFile(filepath.Join(appDir, "package.json"), []byte(appPackageJson), 0644))

	// Test technology detection
	technologiesDetected, err := DetectTechnologiesDescriptors(workspaceRoot, true, []string{}, map[Technology][]string{}, "")
	assert.NoError(t, err)

	// Verify that workspace root is detected as npm
	assert.Contains(t, technologiesDetected, Npm, "Workspace root should be detected as npm")
	npmDirs := technologiesDetected[Npm]
	assert.Contains(t, npmDirs, workspaceRoot, "Workspace root should be in npm directories")

	// Verify that workspace packages are also detected as npm (inheritance)
	assert.Contains(t, npmDirs, appDir, "App package should inherit npm technology")

	t.Logf("Detected technologies: %v", maps.Keys(technologiesDetected))
	t.Logf("Npm directories: %v", maps.Keys(npmDirs))
}
