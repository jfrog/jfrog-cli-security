package docker

import (
	"testing"

	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseDockerImageWithArtifactoryUrl tests parsing WITH Artifactory URL
func TestParseDockerImageWithArtifactoryUrl(t *testing.T) {
	tests := []struct {
		name           string
		imageName      string
		artifactoryUrl string
		expectedRepo   string
		expectedImg    string
		expectedTag    string
	}{
		{
			name:           "SaaS repo path - simple image",
			imageName:      "acme.jfrog.io/docker-local/nginx:1.21",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "nginx",
			expectedTag:    "1.21",
		},
		{
			name:           "SaaS repo path - nested image",
			imageName:      "acme.jfrog.io/docker-local/bitnami/kubectl:latest",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "bitnami/kubectl",
			expectedTag:    "latest",
		},
		{
			name:           "SaaS repo path - deeply nested image",
			imageName:      "acme.jfrog.io/docker-remote/library/nginx/stable:1.25",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-remote",
			expectedImg:    "library/nginx/stable",
			expectedTag:    "1.25",
		},
		{
			name:           "SaaS repo path - version tag with dots",
			imageName:      "mycompany.jfrog.io/docker-prod/myapp:1.2.3",
			artifactoryUrl: "https://mycompany.jfrog.io/artifactory",
			expectedRepo:   "docker-prod",
			expectedImg:    "myapp",
			expectedTag:    "1.2.3",
		},
		{
			name:           "SaaS repo path - short sha tag",
			imageName:      "acme.jfrog.io/docker-local/nginx:abc123def456",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "nginx",
			expectedTag:    "abc123def456",
		},
		{
			name:           "SaaS repo path - no tag defaults to latest",
			imageName:      "acme.jfrog.io/docker-local/nginx",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "nginx",
			expectedTag:    "latest",
		},
		{
			name:           "SaaS repo path - repo with hyphen",
			imageName:      "acme.jfrog.io/docker-virtual-prod/redis:7.0",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-virtual-prod",
			expectedImg:    "redis",
			expectedTag:    "7.0",
		},
		{
			name:           "SaaS repo path - image with uppercase",
			imageName:      "acme.jfrog.io/docker-local/MyApp:v1",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "MyApp",
			expectedTag:    "v1",
		},
		{
			name:           "SaaS subdomain - simple image",
			imageName:      "acme-docker-local.jfrog.io/nginx:1.21",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "nginx",
			expectedTag:    "1.21",
		},
		{
			name:           "SaaS subdomain - nested image",
			imageName:      "acme-docker-remote.jfrog.io/bitnami/redis:7.0",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-remote",
			expectedImg:    "bitnami/redis",
			expectedTag:    "7.0",
		},
		{
			name:           "SaaS subdomain - deeply nested image",
			imageName:      "acme-docker-virtual.jfrog.io/library/nginx/stable:1.25",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-virtual",
			expectedImg:    "library/nginx/stable",
			expectedTag:    "1.25",
		},
		{
			name:           "SaaS subdomain - repo with multiple hyphens",
			imageName:      "acme-docker-prod-release.jfrog.io/myapp:v2",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-prod-release",
			expectedImg:    "myapp",
			expectedTag:    "v2",
		},
		{
			name:           "SaaS subdomain - no tag",
			imageName:      "acme-docker-local.jfrog.io/alpine",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "alpine",
			expectedTag:    "latest",
		},
		{
			name:           "SaaS subdomain - complex nested path",
			imageName:      "mycompany-docker-remote.jfrog.io/gcr.io/google-containers/pause:3.2",
			artifactoryUrl: "https://mycompany.jfrog.io/artifactory",
			expectedRepo:   "docker-remote",
			expectedImg:    "gcr.io/google-containers/pause",
			expectedTag:    "3.2",
		},
		{
			name:           "SaaS subdomain - numeric instance",
			imageName:      "company123-docker-local.jfrog.io/app:1.0",
			artifactoryUrl: "https://company123.jfrog.io/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "app",
			expectedTag:    "1.0",
		},

		// ==========================================
		// JFrog SaaS (.jfrog.io) - PORT METHOD
		// ==========================================
		{
			name:           "SaaS port - simple image",
			imageName:      "acme.jfrog.io:8081/nginx:1.21",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "8081",
			expectedImg:    "nginx",
			expectedTag:    "1.21",
		},
		{
			name:           "SaaS port - nested image",
			imageName:      "acme.jfrog.io:8082/bitnami/redis:7.0",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "8082",
			expectedImg:    "bitnami/redis",
			expectedTag:    "7.0",
		},
		{
			name:           "SaaS port - high port number",
			imageName:      "acme.jfrog.io:54321/myapp:latest",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "54321",
			expectedImg:    "myapp",
			expectedTag:    "latest",
		},
		{
			name:           "Dev repo path - simple image",
			imageName:      "z0curation211355112.jfrogdev.org/curation-test/hello-app:1.0",
			artifactoryUrl: "https://z0curation211355112.jfrogdev.org/artifactory",
			expectedRepo:   "curation-test",
			expectedImg:    "hello-app",
			expectedTag:    "1.0",
		},
		{
			name:           "Dev repo path - nested image",
			imageName:      "z0curation211355112.jfrogdev.org/curation-test/google-samples/hello-app:1.0",
			artifactoryUrl: "https://z0curation211355112.jfrogdev.org/artifactory",
			expectedRepo:   "curation-test",
			expectedImg:    "google-samples/hello-app",
			expectedTag:    "1.0",
		},
		{
			name:           "Dev repo path - deeply nested",
			imageName:      "testinstance.jfrogdev.org/docker-local/org/team/service:v1.2.3",
			artifactoryUrl: "https://testinstance.jfrogdev.org/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "org/team/service",
			expectedTag:    "v1.2.3",
		},
		{
			name:           "Dev repo path - numeric instance name",
			imageName:      "dev12345.jfrogdev.org/test-repo/app:beta",
			artifactoryUrl: "https://dev12345.jfrogdev.org/artifactory",
			expectedRepo:   "test-repo",
			expectedImg:    "app",
			expectedTag:    "beta",
		},
		{
			name:           "Dev subdomain - simple image",
			imageName:      "myinstance-docker-local.jfrogdev.org/nginx:latest",
			artifactoryUrl: "https://myinstance.jfrogdev.org/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "nginx",
			expectedTag:    "latest",
		},
		{
			name:           "Dev subdomain - nested image",
			imageName:      "myinstance-docker-local.jfrogdev.org/bitnami/nginx:alpine",
			artifactoryUrl: "https://myinstance.jfrogdev.org/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "bitnami/nginx",
			expectedTag:    "alpine",
		},
		{
			name:           "Dev subdomain - deeply nested",
			imageName:      "testdev-docker-remote.jfrogdev.org/gcr.io/distroless/static:latest",
			artifactoryUrl: "https://testdev.jfrogdev.org/artifactory",
			expectedRepo:   "docker-remote",
			expectedImg:    "gcr.io/distroless/static",
			expectedTag:    "latest",
		},
		{
			name:           "Dev subdomain - repo with hyphens",
			imageName:      "instance1-docker-prod-release.jfrogdev.org/myapp:v3",
			artifactoryUrl: "https://instance1.jfrogdev.org/artifactory",
			expectedRepo:   "docker-prod-release",
			expectedImg:    "myapp",
			expectedTag:    "v3",
		},
		{
			name:           "Self-hosted repo path - simple domain",
			imageName:      "artifactory.company.com/docker-local/nginx:1.21",
			artifactoryUrl: "https://artifactory.company.com/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "nginx",
			expectedTag:    "1.21",
		},
		{
			name:           "Self-hosted repo path - nested image",
			imageName:      "artifactory.company.com/docker-remote/bitnami/redis:7.0",
			artifactoryUrl: "https://artifactory.company.com/artifactory",
			expectedRepo:   "docker-remote",
			expectedImg:    "bitnami/redis",
			expectedTag:    "7.0",
		},
		{
			name:           "Self-hosted repo path - multi-part domain",
			imageName:      "artifactory.packages.dev.rsint.net/curation-test/google-samples/hello-app:1.0",
			artifactoryUrl: "https://artifactory.packages.dev.rsint.net/artifactory",
			expectedRepo:   "curation-test",
			expectedImg:    "google-samples/hello-app",
			expectedTag:    "1.0",
		},
		{
			name:           "Self-hosted repo path - 4-part domain",
			imageName:      "docker.artifacts.internal.net/prod-repo/myservice:v2.1.0",
			artifactoryUrl: "https://docker.artifacts.internal.net/artifactory",
			expectedRepo:   "prod-repo",
			expectedImg:    "myservice",
			expectedTag:    "v2.1.0",
		},
		{
			name:           "Self-hosted repo path - 5-part domain",
			imageName:      "registry.docker.internal.corp.net/docker-virtual/org/service:v1.2.3",
			artifactoryUrl: "https://registry.docker.internal.corp.net/artifactory",
			expectedRepo:   "docker-virtual",
			expectedImg:    "org/service",
			expectedTag:    "v1.2.3",
		},
		{
			name:           "Self-hosted repo path - simple 2-part domain",
			imageName:      "myartifactory.com/docker-local/alpine:3.18",
			artifactoryUrl: "https://myartifactory.com/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "alpine",
			expectedTag:    "3.18",
		},
		{
			name:           "Self-hosted repo path - no tag",
			imageName:      "artifactory.company.com/docker-local/ubuntu",
			artifactoryUrl: "https://artifactory.company.com/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "ubuntu",
			expectedTag:    "latest",
		},
		{
			name:           "Self-hosted repo path - deeply nested image",
			imageName:      "artifactory.company.com/docker-remote/quay.io/prometheus/prometheus:v2.45.0",
			artifactoryUrl: "https://artifactory.company.com/artifactory",
			expectedRepo:   "docker-remote",
			expectedImg:    "quay.io/prometheus/prometheus",
			expectedTag:    "v2.45.0",
		},
		{
			name:           "Self-hosted subdomain - simple",
			imageName:      "docker-local.artifactory.company.com/nginx:1.21",
			artifactoryUrl: "https://artifactory.company.com/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "nginx",
			expectedTag:    "1.21",
		},
		{
			name:           "Self-hosted subdomain - nested image",
			imageName:      "docker-local.artifactory.company.com/bitnami/nginx:alpine",
			artifactoryUrl: "https://artifactory.company.com/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "bitnami/nginx",
			expectedTag:    "alpine",
		},
		{
			name:           "Self-hosted subdomain - deeply nested",
			imageName:      "docker-remote.myartifactory.com/library/nginx/stable:1.25",
			artifactoryUrl: "https://myartifactory.com/artifactory",
			expectedRepo:   "docker-remote",
			expectedImg:    "library/nginx/stable",
			expectedTag:    "1.25",
		},
		{
			name:           "Self-hosted subdomain - repo with hyphens",
			imageName:      "docker-prod-release.artifactory.company.com/myapp:v1.0.0",
			artifactoryUrl: "https://artifactory.company.com/artifactory",
			expectedRepo:   "docker-prod-release",
			expectedImg:    "myapp",
			expectedTag:    "v1.0.0",
		},
		{
			name:           "Self-hosted subdomain - multi-part base domain",
			imageName:      "docker-virtual.registry.internal.net/app:latest",
			artifactoryUrl: "https://registry.internal.net/artifactory",
			expectedRepo:   "docker-virtual",
			expectedImg:    "app",
			expectedTag:    "latest",
		},
		{
			name:           "Self-hosted subdomain - no tag",
			imageName:      "docker-local.myartifactory.com/busybox",
			artifactoryUrl: "https://myartifactory.com/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "busybox",
			expectedTag:    "latest",
		},
		{
			name:           "Self-hosted subdomain - complex nested path",
			imageName:      "docker-remote.artifactory.company.com/gcr.io/google-containers/pause:3.2",
			artifactoryUrl: "https://artifactory.company.com/artifactory",
			expectedRepo:   "docker-remote",
			expectedImg:    "gcr.io/google-containers/pause",
			expectedTag:    "3.2",
		},
		{
			name:           "Self-hosted port - simple",
			imageName:      "artifactory.company.com:8081/nginx:1.21",
			artifactoryUrl: "https://artifactory.company.com/artifactory",
			expectedRepo:   "8081",
			expectedImg:    "nginx",
			expectedTag:    "1.21",
		},
		{
			name:           "Self-hosted port - nested image",
			imageName:      "myartifactory.com:8082/bitnami/redis:7.0",
			artifactoryUrl: "https://myartifactory.com/artifactory",
			expectedRepo:   "8082",
			expectedImg:    "bitnami/redis",
			expectedTag:    "7.0",
		},
		{
			name:           "Self-hosted port - multi-part domain",
			imageName:      "registry.internal.net:9000/myapp:v1",
			artifactoryUrl: "https://registry.internal.net/artifactory",
			expectedRepo:   "9000",
			expectedImg:    "myapp",
			expectedTag:    "v1",
		},
		{
			name:           "Tag with v prefix",
			imageName:      "acme.jfrog.io/docker-local/myapp:v1.2.3",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "myapp",
			expectedTag:    "v1.2.3",
		},
		{
			name:           "Tag with build number",
			imageName:      "acme.jfrog.io/docker-local/myapp:1.0.0-build.123",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "myapp",
			expectedTag:    "1.0.0-build.123",
		},
		{
			name:           "Tag with git sha",
			imageName:      "acme.jfrog.io/docker-local/myapp:abc123def",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "myapp",
			expectedTag:    "abc123def",
		},
		{
			name:           "Tag with date",
			imageName:      "acme.jfrog.io/docker-local/myapp:2024-01-15",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "myapp",
			expectedTag:    "2024-01-15",
		},
		{
			name:           "Tag alpha",
			imageName:      "acme.jfrog.io/docker-local/myapp:alpha",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "myapp",
			expectedTag:    "alpha",
		},
		{
			name:           "Tag beta",
			imageName:      "acme.jfrog.io/docker-local/myapp:beta",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "myapp",
			expectedTag:    "beta",
		},
		{
			name:           "Tag rc",
			imageName:      "acme.jfrog.io/docker-local/myapp:1.0.0-rc1",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "myapp",
			expectedTag:    "1.0.0-rc1",
		},
		{
			name:           "Repo name docker-local",
			imageName:      "acme.jfrog.io/docker-local/nginx:1.21",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "nginx",
			expectedTag:    "1.21",
		},
		{
			name:           "Repo name docker-remote",
			imageName:      "acme.jfrog.io/docker-remote/nginx:1.21",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-remote",
			expectedImg:    "nginx",
			expectedTag:    "1.21",
		},
		{
			name:           "Repo name docker-virtual",
			imageName:      "acme.jfrog.io/docker-virtual/nginx:1.21",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-virtual",
			expectedImg:    "nginx",
			expectedTag:    "1.21",
		},
		{
			name:           "Repo name with env - dev",
			imageName:      "acme.jfrog.io/docker-dev/nginx:1.21",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-dev",
			expectedImg:    "nginx",
			expectedTag:    "1.21",
		},
		{
			name:           "Repo name with env - prod",
			imageName:      "acme.jfrog.io/docker-prod/nginx:1.21",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-prod",
			expectedImg:    "nginx",
			expectedTag:    "1.21",
		},
		{
			name:           "Repo name with env - staging",
			imageName:      "acme.jfrog.io/docker-staging/nginx:1.21",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-staging",
			expectedImg:    "nginx",
			expectedTag:    "1.21",
		},
		{
			name:           "Custom repo name",
			imageName:      "acme.jfrog.io/my-custom-repo/nginx:1.21",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "my-custom-repo",
			expectedImg:    "nginx",
			expectedTag:    "1.21",
		},
		{
			name:           "Short repo name",
			imageName:      "acme.jfrog.io/repo/nginx:1.21",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "repo",
			expectedImg:    "nginx",
			expectedTag:    "1.21",
		},
		{
			name:           "Official image nginx",
			imageName:      "acme.jfrog.io/docker-remote/nginx:latest",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-remote",
			expectedImg:    "nginx",
			expectedTag:    "latest",
		},
		{
			name:           "Official image redis",
			imageName:      "acme.jfrog.io/docker-remote/redis:7.0",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-remote",
			expectedImg:    "redis",
			expectedTag:    "7.0",
		},
		{
			name:           "Official image postgres",
			imageName:      "acme.jfrog.io/docker-remote/postgres:15",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-remote",
			expectedImg:    "postgres",
			expectedTag:    "15",
		},
		{
			name:           "Bitnami image",
			imageName:      "acme.jfrog.io/docker-remote/bitnami/postgresql:15.3.0",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-remote",
			expectedImg:    "bitnami/postgresql",
			expectedTag:    "15.3.0",
		},
		{
			name:           "Google container",
			imageName:      "acme.jfrog.io/docker-remote/gcr.io/google-containers/pause:3.9",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-remote",
			expectedImg:    "gcr.io/google-containers/pause",
			expectedTag:    "3.9",
		},
		{
			name:           "AWS ECR image",
			imageName:      "acme.jfrog.io/docker-remote/public.ecr.aws/lambda/python:3.11",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-remote",
			expectedImg:    "public.ecr.aws/lambda/python",
			expectedTag:    "3.11",
		},
		{
			name:           "Quay.io image",
			imageName:      "acme.jfrog.io/docker-remote/quay.io/prometheus/prometheus:v2.45.0",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-remote",
			expectedImg:    "quay.io/prometheus/prometheus",
			expectedTag:    "v2.45.0",
		},
		{
			name:           "GitHub container registry",
			imageName:      "acme.jfrog.io/docker-remote/ghcr.io/actions/runner:latest",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-remote",
			expectedImg:    "ghcr.io/actions/runner",
			expectedTag:    "latest",
		},

		// ==========================================
		// Edge cases - Artifactory URL variations
		// ==========================================
		{
			name:           "Artifactory URL without trailing slash",
			imageName:      "acme.jfrog.io/docker-local/nginx:1.21",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "nginx",
			expectedTag:    "1.21",
		},
		{
			name:           "Artifactory URL with trailing slash",
			imageName:      "acme.jfrog.io/docker-local/nginx:1.21",
			artifactoryUrl: "https://acme.jfrog.io/artifactory/",
			expectedRepo:   "docker-local",
			expectedImg:    "nginx",
			expectedTag:    "1.21",
		},
		{
			name:           "Artifactory URL http",
			imageName:      "acme.jfrog.io/docker-local/nginx:1.21",
			artifactoryUrl: "http://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "nginx",
			expectedTag:    "1.21",
		},
		{
			name:           "Artifactory URL with port",
			imageName:      "myartifactory.com/docker-local/nginx:1.21",
			artifactoryUrl: "https://myartifactory.com:8443/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "nginx",
			expectedTag:    "1.21",
		},
		{
			name:           "Kubernetes deployment image",
			imageName:      "acme.jfrog.io/docker-prod/mycompany/backend-service:v2.3.1",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-prod",
			expectedImg:    "mycompany/backend-service",
			expectedTag:    "v2.3.1",
		},
		{
			name:           "CI/CD built image",
			imageName:      "acme-docker-local.jfrog.io/builds/myapp:build-1234",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "builds/myapp",
			expectedTag:    "build-1234",
		},
		{
			name:           "Helm chart container",
			imageName:      "acme.jfrog.io/docker-virtual/charts/mychart:0.1.0",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-virtual",
			expectedImg:    "charts/mychart",
			expectedTag:    "0.1.0",
		},
		{
			name:           "Multi-arch image",
			imageName:      "acme.jfrog.io/docker-local/myapp:1.0.0-amd64",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-local",
			expectedImg:    "myapp",
			expectedTag:    "1.0.0-amd64",
		},
		{
			name:           "Distroless image",
			imageName:      "acme.jfrog.io/docker-remote/gcr.io/distroless/static-debian11:nonroot",
			artifactoryUrl: "https://acme.jfrog.io/artifactory",
			expectedRepo:   "docker-remote",
			expectedImg:    "gcr.io/distroless/static-debian11",
			expectedTag:    "nonroot",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := ParseDockerImageWithArtifactoryUrl(tt.imageName, tt.artifactoryUrl)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedRepo, info.Repo, "repo mismatch")
			assert.Equal(t, tt.expectedImg, info.Image, "image mismatch")
			assert.Equal(t, tt.expectedTag, info.Tag, "tag mismatch")
		})
	}
}

func TestBuildDependencyTree(t *testing.T) {
	tests := []struct {
		name            string
		dockerImageName string
		expectError     bool
		errorContains   string
	}{
		{
			name:            "Empty image name",
			dockerImageName: "",
			expectError:     true,
			errorContains:   "docker image name is required",
		},
		{
			name:            "No registry - single part image",
			dockerImageName: "nginx",
			expectError:     true,
			errorContains:   "invalid docker image format",
		},
		{
			name:            "No registry - image with tag only",
			dockerImageName: "nginx:1.21",
			expectError:     true,
			errorContains:   "invalid docker image format",
		},
		{
			name:            "Whitespace only",
			dockerImageName: "   ",
			expectError:     true,
			errorContains:   "invalid docker image format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := technologies.BuildInfoBomGeneratorParams{DockerImageName: tt.dockerImageName}
			_, _, err := BuildDependencyTree(params)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
