package technologies

import (
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
)

func CreateTestWorkspace(t *testing.T, sourceDir string) (string, func()) {
	return tests.CreateTestWorkspace(t, filepath.Join("..", "..", "..", "..", "tests", "testdata", sourceDir))
}