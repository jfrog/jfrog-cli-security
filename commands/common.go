package commands

import "github.com/jfrog/jfrog-client-go/utils/errorutils"

const (
	TotalConcurrentRequests = 10
)

func DetectNumOfThreads(threadsCount int) (int, error) {
	if threadsCount > TotalConcurrentRequests {
		return 0, errorutils.CheckErrorf("number of threads crossed the maximum, the maximum threads allowed is %v", TotalConcurrentRequests)
	}
	return threadsCount, nil
}
