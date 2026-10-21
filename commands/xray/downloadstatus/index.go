package downloadstatus

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	artifactoryUtils "github.com/jfrog/jfrog-client-go/artifactory/services/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	manifestListFileName = "list.manifest.json"
	maxManifestListBytes = 4 << 20
	unknownPlatformArch  = "unknown"
)

type manifestSource interface {
	FileInfo(relativePath string) (*artifactoryUtils.FileInfo, error)
	ReadRemoteFile(readPath string) (io.ReadCloser, error)
}

type manifestList struct {
	Manifests []struct {
		Digest   string `json:"digest"`
		Platform struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
			Variant      string `json:"variant"`
		} `json:"platform"`
	} `json:"manifests"`
}

type platformManifest struct {
	platform string
	path     string
	sha256   string
}

type PlatformStatus struct {
	Platform       string `json:"platform"`
	Path           string `json:"path"`
	DownloadStatus string `json:"download_status"`
	StatusReason   string `json:"status_reason,omitempty"`
}

type platformResult struct {
	platform string
	result   *Result
}

func isManifestListPath(path string) bool {
	return strings.HasSuffix(path, "/"+manifestListFileName)
}

// Xray scans each platform manifest of a multi-arch image, and the list itself carries no violations.
func listPlatformManifests(source manifestSource, repo, listPath string) ([]platformManifest, error) {
	imagePath := strings.TrimSuffix(listPath, "/"+manifestListFileName)
	if cut := strings.LastIndex(imagePath, "/"); cut != -1 {
		imagePath = imagePath[:cut]
	}

	reader, err := source.ReadRemoteFile(repo + "/" + listPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := reader.Close(); closeErr != nil {
			log.Debug(fmt.Sprintf("Failed closing %s/%s: %s", repo, listPath, closeErr.Error()))
		}
	}()
	content, err := io.ReadAll(io.LimitReader(reader, maxManifestListBytes))
	if err != nil {
		return nil, errorutils.CheckError(err)
	}
	list := manifestList{}
	if err = json.Unmarshal(content, &list); err != nil {
		return nil, errorutils.CheckErrorf("couldn't parse manifest list %s/%s: %s", repo, listPath, err.Error())
	}

	var manifests []platformManifest
	for _, entry := range list.Manifests {
		if entry.Digest == "" || entry.Platform.Architecture == unknownPlatformArch {
			continue
		}
		platform := entry.Platform.OS + "/" + entry.Platform.Architecture
		if entry.Platform.Variant != "" {
			platform += "/" + entry.Platform.Variant
		}
		path := imagePath + "/" + strings.Replace(entry.Digest, ":", "__", 1) + "/manifest.json"
		fileInfo, err := source.FileInfo(repo + "/" + path)
		if err != nil {
			log.Debug(fmt.Sprintf("Platform manifest %s/%s (%s) is not available: %s", repo, path, platform, err.Error()))
			continue
		}
		manifests = append(manifests, platformManifest{platform: platform, path: path, sha256: fileInfo.Checksums.Sha256})
	}
	return manifests, nil
}

func downloadStatusRank(status string) int {
	switch status {
	case StatusBlocked:
		return 3
	case StatusUnknown:
		return 2
	default:
		return 1
	}
}

func mergePlatformResults(result *Result, platforms []platformResult) {
	worst, worstPlatform := result, ""
	for _, platform := range platforms {
		child := platform.result
		result.Platforms = append(result.Platforms, PlatformStatus{
			Platform:       platform.platform,
			Path:           child.Path,
			DownloadStatus: child.DownloadStatus,
			StatusReason:   child.StatusReason,
		})
		for _, row := range child.Violations {
			row.Platform = platform.platform
			result.Violations = append(result.Violations, row)
		}
		if downloadStatusRank(child.DownloadStatus) > downloadStatusRank(worst.DownloadStatus) {
			worst, worstPlatform = child, platform.platform
		}
	}
	if worst != result {
		result.DownloadStatus = worst.DownloadStatus
		result.StatusReason = fmt.Sprintf("%s (%s)", worst.StatusReason, worstPlatform)
		result.ScanStatus = worst.ScanStatus
	}
	sortViolationRows(result.Violations)
}
