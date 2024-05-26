package auditgit

import (
	"github.com/sourcegraph/go-diff/diff"
)

type Edits struct {
	FilesToEdit []FileEdit
}

func (e *Edits) GetFilesToChange() []string {
	return []string{}
}

type FileEdit struct {
	MetaDataEdit FileChange
	ContentEdits []ContentEdit
}

const (
	NoEditOperation EditOperation = " "
	EditOperationAdd    EditOperation = "+"
	EditOperationDelete EditOperation = "-"

	FileChangeAdd    FileChange = "added"
	FileChangeDelete FileChange = "deleted"
	FileChangeModify FileChange = "modified"

	// If file was created the source (pre-change) is /dev/null
	// If file was deleted the target (post-change) is /dev/null
	FileNotExists = "/dev/null"

	// Default - could be diff depend on git config
	Source = "a/"
	Target = "b/"
)

type EditOperation string
type FileChange string

type FileMetaDataEdit struct {
	Operation FileChange
	Source    string
	// For rename operation
	Target    string
}

// Content should be the output of git diff command (Unified format): https://git-scm.com/docs/git-diff
func ParseUnifiedDiffToEditOperations(unifiedDiffFormatContent string) (edits Edits, err error) {
	fileDiff, err := diff.ParseMultiFileDiff([]byte(unifiedDiffFormatContent))
	if err != nil {
		return
	}
	return ConvertFileDiffToEditOperations(fileDiff)
}

// Get the edit operations to apply in order to transform the source to be the target based on the diff
func ConvertFileDiffToEditOperations(fd []*diff.FileDiff) (Edits, error) {
	return Edits{}, nil
}
