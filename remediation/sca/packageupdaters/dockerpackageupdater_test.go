package packageupdaters

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/stretchr/testify/assert"
)

func TestRewriteFromLine(t *testing.T) {
	testcases := []struct {
		name       string
		line       string
		component  string
		oldVersion string
		newVersion string
		expected   string
		matched    bool
	}{
		{
			name:       "bare image with tag",
			line:       "FROM nginx:1.27-alpine",
			component:  "nginx",
			oldVersion: "1.27-alpine",
			newVersion: "1.27.3-alpine",
			expected:   "FROM nginx:1.27.3-alpine",
			matched:    true,
		},
		{
			name:       "registry prefixed image",
			line:       "FROM gcr.io/distroless/base-debian12:latest",
			component:  "gcr.io/distroless/base-debian12",
			oldVersion: "latest",
			newVersion: "nonroot",
			expected:   "FROM gcr.io/distroless/base-debian12:nonroot",
			matched:    true,
		},
		{
			name:       "digest pinned image",
			line:       "FROM registry.access.redhat.com/ubi9/python-311@sha256:aaaa",
			component:  "registry.access.redhat.com/ubi9/python-311",
			oldVersion: "sha256:aaaa",
			newVersion: "sha256:bbbb",
			expected:   "FROM registry.access.redhat.com/ubi9/python-311@sha256:bbbb",
			matched:    true,
		},
		{
			name:       "multi-stage alias preserved",
			line:       "FROM golang:1.22-bookworm AS builder",
			component:  "golang",
			oldVersion: "1.22-bookworm",
			newVersion: "1.22.5-bookworm",
			expected:   "FROM golang:1.22.5-bookworm AS builder",
			matched:    true,
		},
		{
			name:       "platform flag preserved",
			line:       "FROM --platform=linux/amd64 nginx:1.27-alpine",
			component:  "nginx",
			oldVersion: "1.27-alpine",
			newVersion: "1.27.3-alpine",
			expected:   "FROM --platform=linux/amd64 nginx:1.27.3-alpine",
			matched:    true,
		},
		{
			name:       "case insensitive FROM keyword",
			line:       "from nginx:1.27-alpine",
			component:  "nginx",
			oldVersion: "1.27-alpine",
			newVersion: "1.27.3-alpine",
			expected:   "from nginx:1.27.3-alpine",
			matched:    true,
		},
		{
			name:       "non-matching name",
			line:       "FROM nginx:1.27-alpine",
			component:  "redis",
			oldVersion: "1.27-alpine",
			newVersion: "1.27.3-alpine",
			expected:   "FROM nginx:1.27-alpine",
			matched:    false,
		},
		{
			name:       "non-matching version",
			line:       "FROM nginx:1.28-alpine",
			component:  "nginx",
			oldVersion: "1.27-alpine",
			newVersion: "1.27.3-alpine",
			expected:   "FROM nginx:1.28-alpine",
			matched:    false,
		},
		{
			name:       "reference to prior stage skipped",
			line:       "FROM builder",
			component:  "builder",
			oldVersion: "",
			newVersion: "latest",
			expected:   "FROM builder",
			matched:    false,
		},
		{
			name:       "ARG-driven tag skipped",
			line:       "FROM nginx:${NGINX_VERSION}",
			component:  "nginx",
			oldVersion: "1.27-alpine",
			newVersion: "1.27.3-alpine",
			expected:   "FROM nginx:${NGINX_VERSION}",
			matched:    false,
		},
		{
			name:       "unrelated line untouched",
			line:       "RUN echo FROM nginx:1.27-alpine",
			component:  "nginx",
			oldVersion: "1.27-alpine",
			newVersion: "1.27.3-alpine",
			expected:   "RUN echo FROM nginx:1.27-alpine",
			matched:    false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got, matched := rewriteFromLine(tc.line, tc.component, tc.oldVersion, tc.newVersion)
			assert.Equal(t, tc.expected, got)
			assert.Equal(t, tc.matched, matched)
		})
	}
}

func TestDockerPackageUpdater_UpdateDependency(t *testing.T) {
	tmpDir := t.TempDir()
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	original := []byte("FROM golang:1.22-bookworm AS builder\nRUN go build .\n\nFROM nginx:1.27-alpine\nCOPY --from=builder /app /app\n")
	assert.NoError(t, os.WriteFile(dockerfilePath, original, 0644))

	fixDetails := &FixDetails{
		ImpactedDependencyName:    "nginx",
		ImpactedDependencyVersion: "1.27-alpine",
		SuggestedFixedVersion:     "1.27.3-alpine",
		Technology:                techutils.Docker,
		Components: []formats.ComponentRow{
			{
				Name:      "nginx",
				Version:   "1.27-alpine",
				Evidences: []formats.Location{{File: dockerfilePath}},
			},
		},
	}

	updater := &DockerPackageUpdater{}
	assert.NoError(t, updater.UpdateDependency(fixDetails))

	got, err := os.ReadFile(dockerfilePath)
	assert.NoError(t, err)
	expected := "FROM golang:1.22-bookworm AS builder\nRUN go build .\n\nFROM nginx:1.27.3-alpine\nCOPY --from=builder /app /app\n"
	assert.Equal(t, expected, string(got))
}

func TestDockerPackageUpdater_ReturnsErrorWhenComponentMissing(t *testing.T) {
	tmpDir := t.TempDir()
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	original := []byte("FROM golang:1.22-bookworm\n")
	assert.NoError(t, os.WriteFile(dockerfilePath, original, 0644))

	fixDetails := &FixDetails{
		ImpactedDependencyName:    "nginx",
		ImpactedDependencyVersion: "1.27-alpine",
		SuggestedFixedVersion:     "1.27.3-alpine",
		Technology:                techutils.Docker,
		Components: []formats.ComponentRow{
			{
				Name:      "nginx",
				Version:   "1.27-alpine",
				Evidences: []formats.Location{{File: dockerfilePath}},
			},
		},
	}

	updater := &DockerPackageUpdater{}
	assert.Error(t, updater.UpdateDependency(fixDetails))
}

func TestDockerPackageUpdater_NoEvidence(t *testing.T) {
	updater := &DockerPackageUpdater{}
	err := updater.UpdateDependency(&FixDetails{
		ImpactedDependencyName:    "nginx",
		ImpactedDependencyVersion: "1.27-alpine",
		SuggestedFixedVersion:     "1.27.3-alpine",
	})
	assert.Error(t, err)
}

func TestGetCompatiblePackageUpdater_Docker(t *testing.T) {
	updater, supported := GetCompatiblePackageUpdater(&FixDetails{Technology: techutils.Docker})
	assert.True(t, supported)
	_, ok := updater.(*DockerPackageUpdater)
	assert.True(t, ok)
}
