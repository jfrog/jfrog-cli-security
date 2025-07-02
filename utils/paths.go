package utils

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

const (
	JfrogCurationDirName = "curation"

	CurationsDir = "JFROG_CLI_CURATION_DIR"

	// #nosec G101 -- Not credentials.
	CurationSupportFlag = "JFROG_CLI_CURATION"
)

func getJfrogCurationFolder() (string, error) {
	dependenciesDir := os.Getenv(CurationsDir)
	if dependenciesDir != "" {
		return dependenciesDir, nil
	}
	jfrogHome, err := coreutils.GetJfrogHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(jfrogHome, JfrogCurationDirName), nil
}

func GetCurationCacheFolder() (string, error) {
	curationFolder, err := getJfrogCurationFolder()
	if err != nil {
		return "", err
	}
	return filepath.Join(curationFolder, "cache"), nil
}

func GetCurationCacheFolderByTech(tech techutils.Technology) (projectDir string, err error) {
	pathHash, errFromHash := getProjectPathHash()
	if errFromHash != nil {
		err = errFromHash
		return
	}
	curationFolder, err := GetCurationCacheFolder()
	if err != nil {
		return "", err
	}
	projectDir = filepath.Join(curationFolder, tech.String(), pathHash)
	return
}

func getProjectPathHash() (string, error) {
	workingDir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return Sha1Hash(workingDir)
}

func GetCurationPipCacheFolder() (string, error) {
	curationFolder, err := GetCurationCacheFolder()
	if err != nil {
		return "", err
	}
	return filepath.Join(curationFolder, "pip"), nil
}

func GetCurationNugetCacheFolder() (string, error) {
	curationFolder, err := GetCurationCacheFolder()
	if err != nil {
		return "", err
	}
	return filepath.Join(curationFolder, "nuget"), nil
}

func GetRelativePath(fullPathWd, baseWd string) string {
	relativePath, err := filepath.Rel(baseWd, fullPathWd)
	if err != nil {
		log.Debug(fmt.Sprintf("Failed to get relative path from %s to %s: %v", fullPathWd, baseWd, err))
		return fullPathWd // Return the full path if an error occurs
	}
	if relativePath == "." {
		return "" // If the paths are the same, return an empty string
	}
	return filepath.ToSlash(filepath.Clean(relativePath))
}

// Calculate the common parent directory of the given paths.
// Examples:
//  0. [dir] -> dir
//  1. [dir/dir, dir/directory] -> dir
//  2. [dir, directory] -> "."
//  3. [dir/dir2, dir/dir2/dir3, dir/dir2/dir3/dir4] -> dir/dir2
func GetCommonParentDir(paths ...string) string {
	if len(paths) == 0 {
		return ""
	}
	commonParent := paths[0]
	if len(paths) > 1 {
		for _, path := range paths[1:] {
			commonParent = getCommonParentDir(commonParent, path)
		}
	}
	return commonParent
}

func getCommonParentDir(path1, path2 string) string {
	for {
		if path1 == path2 {
			return path1
		}
		if path1 == "" || path2 == "" {
			return ""
		}
		if len(path1) > len(path2) {
			path1 = filepath.Dir(path1)
		} else {
			path2 = filepath.Dir(path2)
		}
	}
}

func ToURI(path string) string {
	// Convert Windows path to URI format
	// Use filepath.ToSlash to make sure the path uses forward slashes
	path = filepath.ToSlash(path)

	// If it's a Windows path, prepend "file:///" and replace the drive letter
	if len(path) > 2 && path[1] == ':' {
		// Convert "C:\\path\\to\\file" to "file:///C:/path/to/file"
		path = "file:///" + path[:2] + path[2:]
	} else {
		// For Linux/Unix or other paths, just add "file://"
		path = "file:///" + path
	}
	// Parse the URL to ensure it's valid (this step is optional for simple paths)
	u, err := url.Parse(path)
	if err != nil {
		log.Warn(fmt.Sprintf("Failed to parse path %s: %v", path, err))
		return path
	}
	// Return the string representation of the URL
	return u.String()
}

func GetRepositoriesScansListUrlForArtifact(baseUrl, repoPath, artifactName, packageID string) string {
	repoName := repoPath
	if strings.Contains(repoPath, "/") {
		// If repoPath contains a slash, it may be a repository path with sub-paths.
		// We need to extract the repository name from the path.
		repoName = strings.Split(repoPath, "/")[0]
	}
	// Path
	path := fmt.Sprintf("ui/scans-list/repositories/%s/scan-descendants/%s", url.PathEscape(repoName), url.PathEscape(artifactName))

	// Query params
	query := url.Values{}
	query.Set("package_id", packageID)
	query.Set("path", fmt.Sprintf("%s/%s", repoPath, artifactName))
	query.Set("page_type", "overview")

	// Final URL
	return fmt.Sprintf("%s%s?%s", baseUrl, path, query.Encode())
}
