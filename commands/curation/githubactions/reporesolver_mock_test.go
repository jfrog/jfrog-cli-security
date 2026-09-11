package githubactions

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMockArtifactoryVcsRepoResolver(t *testing.T) {
	tests := []struct {
		name       string
		githubRepo string
		want       string
		wantErr    bool
	}{
		{"owner and repo", "my-org/my-repo", "my-org" + mockVcsRepoSuffix, false},
		{"a different owner resolves differently", "other-org/my-repo", "other-org" + mockVcsRepoSuffix, false},
		{"same owner, different repo resolves the same", "my-org/another-repo", "my-org" + mockVcsRepoSuffix, false},
		{"no slash", "my-org", "", true},
		{"empty", "", "", true},
		{"missing owner", "/my-repo", "", true},
		{"missing repo", "my-org/", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewMockArtifactoryVcsRepoResolver().Resolve(context.Background(), tt.githubRepo)
			if tt.wantErr {
				assert.Error(t, err, "an unmappable repository must not resolve to a default")
				assert.Empty(t, got)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMockArtifactoryVcsRepoResolver_IsDeterministic(t *testing.T) {
	// Unlike the timestamp-parity decider mock, this one needs no injected state: repeated
	// calls must agree, so tests and two consecutive runs never see different mappings.
	resolver := NewMockArtifactoryVcsRepoResolver()
	first, err := resolver.Resolve(context.Background(), "my-org/my-repo")
	assert.NoError(t, err)
	for range 50 {
		again, err := resolver.Resolve(context.Background(), "my-org/my-repo")
		assert.NoError(t, err)
		assert.Equal(t, first, again)
	}
}
