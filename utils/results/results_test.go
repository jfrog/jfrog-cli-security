package results

import (
	"github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetUniqueWatchesFromAllSources(t *testing.T) {
	testCases := []struct {
		name           string
		resultsContext ResultContext
		expectedOutput []string
	}{
		{
			name:           "No watches exists",
			resultsContext: ResultContext{},
			expectedOutput: []string{},
		},
		{
			name: "No Platform Watches",
			resultsContext: ResultContext{
				Watches:         []string{"Watch-1", "Watch-2"},
				PlatformWatches: &utils.ResourcesWatchesBody{},
			},
			expectedOutput: []string{"Watch-1", "Watch-2"},
		},
		// This case of getting watches from Watches and from ProjectWatches together is not possible, but we want to check the functions filtering logic regardless
		{
			name: "All watches kinds",
			resultsContext: ResultContext{
				Watches: []string{"Watch-1", "Watch-2"},
				PlatformWatches: &utils.ResourcesWatchesBody{
					GitRepositoryWatches: []string{"Watch-1", "Watch-3", "Watch-5"},
					ProjectWatches:       []string{"Watch-2", "Watch-4"},
				},
			},
			expectedOutput: []string{"Watch-1", "Watch-2", "Watch-3", "Watch-4", "Watch-5"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			results := tc.resultsContext.GetUniqueWatchesFromAllSources()
			assert.ElementsMatch(t, tc.expectedOutput, results)
		})
	}
}
