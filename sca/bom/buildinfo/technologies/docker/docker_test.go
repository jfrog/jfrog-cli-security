package docker

import (
	"testing"

	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDockerImage(t *testing.T) {
	tests := []struct {
		name         string
		imageName    string
		expectedRepo string
		expectedImg  string
		expectedTag  string
		expectError  bool
	}{
		// SaaS: Repository path
		{
			name:         "SaaS repository path",
			imageName:    "acme.jfrog.io/docker-local/nginx:1.21",
			expectedRepo: "docker-local",
			expectedImg:  "nginx",
			expectedTag:  "1.21",
		},
		{
			name:         "SaaS repository path with nested image",
			imageName:    "acme.jfrog.io/docker-local/bitnami/kubectl:latest",
			expectedRepo: "docker-local",
			expectedImg:  "bitnami/kubectl",
			expectedTag:  "latest",
		},
		// SaaS: Subdomain
		{
			name:         "SaaS subdomain format",
			imageName:    "acme-docker-local.jfrog.io/nginx:1.21",
			expectedRepo: "docker-local",
			expectedImg:  "nginx",
			expectedTag:  "1.21",
		},
		{
			name:         "SaaS subdomain with nested image",
			imageName:    "acme-docker-remote.jfrog.io/bitnami/redis:7.0",
			expectedRepo: "docker-remote",
			expectedImg:  "bitnami/redis",
			expectedTag:  "7.0",
		},
		// Subdomain CNAME
		{
			name:         "Subdomain CNAME format",
			imageName:    "docker-local.acme.com/nginx:alpine",
			expectedRepo: "docker-local",
			expectedImg:  "nginx",
			expectedTag:  "alpine",
		},
		// Self-Managed: Repository path
		{
			name:         "Self-managed repository path",
			imageName:    "myartifactory.com/docker-local/redis:7.0",
			expectedRepo: "docker-local",
			expectedImg:  "redis",
			expectedTag:  "7.0",
		},
		// Self-Managed: Subdomain
		{
			name:         "Self-managed subdomain",
			imageName:    "docker-virtual.myartifactory.com/alpine:3.18",
			expectedRepo: "docker-virtual",
			expectedImg:  "alpine",
			expectedTag:  "3.18",
		},
		// Port method (port IS the repo, no repo in path)
		{
			name:         "Port method",
			imageName:    "myartifactory.com:8876/nginx:1.21",
			expectedRepo: "8876",
			expectedImg:  "nginx",
			expectedTag:  "1.21",
		},
		// Registry with port (repo in path)
		{
			name:         "Localhost with port and repo",
			imageName:    "localhost:8046/docker-local/nginx:1.21",
			expectedRepo: "docker-local",
			expectedImg:  "nginx",
			expectedTag:  "1.21",
		},
		{
			name:         "IP address with port and repo",
			imageName:    "192.168.50.230:8046/docker-local/nginx:1.21",
			expectedRepo: "docker-local",
			expectedImg:  "nginx",
			expectedTag:  "1.21",
		},
		{
			name:         "IP address with port and nested image",
			imageName:    "192.168.50.230:8046/docker-local/bitnami/kubectl:latest",
			expectedRepo: "docker-local",
			expectedImg:  "bitnami/kubectl",
			expectedTag:  "latest",
		},
		// Default tag
		{
			name:         "No tag defaults to latest",
			imageName:    "acme.jfrog.io/docker-local/nginx",
			expectedRepo: "docker-local",
			expectedImg:  "nginx",
			expectedTag:  "latest",
		},
		// Error cases
		{
			name:        "Empty image name",
			imageName:   "",
			expectError: true,
		},
		{
			name:        "No registry",
			imageName:   "nginx:latest",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := ParseDockerImage(tt.imageName)
			if tt.expectError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectedRepo, info.Repo)
			assert.Equal(t, tt.expectedImg, info.Image)
			assert.Equal(t, tt.expectedTag, info.Tag)
		})
	}
}

func TestBuildDependencyTree(t *testing.T) {
	tests := []struct {
		name            string
		dockerImageName string
		expectError     bool
	}{
		{name: "Empty image name", dockerImageName: "", expectError: true},
		{name: "No registry", dockerImageName: "image:tag", expectError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := technologies.BuildInfoBomGeneratorParams{DockerImageName: tt.dockerImageName}
			_, _, err := BuildDependencyTree(params)
			if tt.expectError {
				assert.Error(t, err)
			}
		})
	}
}
