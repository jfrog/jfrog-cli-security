package snapshotconvertor

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	directDependency     = "Direct"
	indirectDependency   = "Indirect"
	GithubJobEnvVar      = "GITHUB_JOB"
	GithubWorkflowEnvVar = "GITHUB_WORKFLOW"
	GithubShaEnvVar      = "GITHUB_SHA"
)

func CreateGithubSnapshotFromSbom(bom *cyclonedx.BOM, snapshotVersion int, scanTime time.Time, jobId, jobCorrelator, commitSha, gitRef, detectorName, detectorVersion, detectorUrl string) (*vcsclient.SbomSnapshot, error) {
	if bom == nil {
		return nil, errors.New("received cycloneDX is nil")
	}

	snapshot := &vcsclient.SbomSnapshot{
		Version: snapshotVersion,
		Sha:     commitSha,
		Ref:     ensureFullRef(gitRef),
		Job: &vcsclient.JobInfo{
			ID:         jobId,
			Correlator: jobCorrelator,
		},
		Detector: &vcsclient.DetectorInfo{
			Name:    detectorName,
			Version: detectorVersion,
			Url:     detectorUrl,
		},
		Scanned:   scanTime,
		Manifests: nil,
	}

	if bom.Components == nil {
		return snapshot, nil
	}

	// Collecting a descriptor -> Component map that contains all relevant components to each descriptors
	// A component with multi- descriptor occurrences appears in all relevant entries
	descriptorToComponents := make(map[string][]cyclonedx.Component)
	for _, component := range *bom.Components {
		if component.Type != cyclonedx.ComponentTypeLibrary {
			continue
		}

		if component.Evidence != nil && component.Evidence.Occurrences != nil {
			for _, occurrence := range *component.Evidence.Occurrences {
				descriptorName := occurrence.Location
				if descriptorName != "" {
					descriptorToComponents[descriptorName] = append(descriptorToComponents[descriptorName], component)
				}
			}
		}
	}

	manifests := make(map[string]*vcsclient.Manifest)
	for descriptorRelativePath, componentsList := range descriptorToComponents {
		manifest := &vcsclient.Manifest{
			Name:     filepath.Base(descriptorRelativePath),
			File:     &vcsclient.FileInfo{SourceLocation: descriptorRelativePath},
			Resolved: nil,
		}

		resolvedDependencies := make(map[string]*vcsclient.ResolvedDependency)
		for _, component := range componentsList {
			var relationship string
			bomRelationship := cdxutils.GetComponentRelation(bom, component.BOMRef, false)
			if bomRelationship == cdxutils.RootRelation {
				continue
			} else if bomRelationship == cdxutils.DirectRelation {
				relationship = directDependency
			} else {
				relationship = indirectDependency
			}

			singleDependency := &vcsclient.ResolvedDependency{
				PackageURL:   component.PackageURL,
				Relationship: relationship,
				Dependencies: cdxutils.GetDirectDependencies(bom.Dependencies, component.BOMRef),
			}
			resolvedDependencies[component.Name] = singleDependency
		}
		manifest.Resolved = resolvedDependencies
		manifests[descriptorRelativePath] = manifest
	}
	snapshot.Manifests = manifests
	log.Debug(fmt.Sprintf("Sent Snapshot:/n%v", snapshot))
	return snapshot, nil
}

func ensureFullRef(branchName string) string {
	if strings.HasPrefix(branchName, "refs/") {
		return branchName
	}
	return "refs/heads/" + branchName
}
