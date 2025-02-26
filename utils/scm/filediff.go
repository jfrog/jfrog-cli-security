package scm

import (
	"fmt"

	goDiff "github.com/go-git/go-git/v5/plumbing/format/diff"

	"github.com/jfrog/jfrog-client-go/utils/log"
)

type Range struct {
	StartRow int
	StartCol int
	EndRow   int
	EndCol   int
}

func (r Range) String() string {
	return fmt.Sprintf("%d:%d-%d:%d", r.StartRow, r.StartCol, r.EndRow, r.EndCol)
}

// Contains checks if the range contains (fully) the given range
func (r Range) Contains(startRow, startCol, endRow, endCol int) bool {
	return r.StartRow <= startRow && r.StartCol <= startCol && r.EndRow >= endRow && r.EndCol >= endCol
}

// Overlaps checks if the range overlaps (partially or fully) the given range
func (r Range) Overlaps(startRow, startCol, endRow, endCol int) bool {
	return r.StartRow < endRow && r.EndRow > startRow && r.StartCol < endCol && r.EndCol > startCol
}

type FileChanges struct {
	Path   string
	Ranges []Range
}

func (f FileChanges) String() string {
	return fmt.Sprintf("%s: %v", f.Path, f.Ranges)
}

type DiffContent struct {
	ChangedFiles []FileChanges
}

func (dc DiffContent) HasChanges() bool {
	return len(dc.ChangedFiles) > 0
}

func (dc DiffContent) GetChangedFilesPaths() (paths []string) {
	for _, file := range dc.ChangedFiles {
		paths = append(paths, file.Path)
	}
	return
}

// Source is always after the target in the branches working tree.
// i.e, to get to the target from the source, you need to go back in the history. (remove content)
// This method will the ranges of the removed content from the file patches
func FilePatchToDiffContent(filePatches ...goDiff.FilePatch) (content DiffContent) {
	for _, filePatch := range filePatches {
		changes := FileChanges{Path: getFilePathFromFiles(filePatch)}
		if changes.Path == "" || filePatch.IsBinary() {
			// Not relevant file
			continue
		}
		// Get the relevant changes for the file
		startRow, startCol := 1, 1
		for _, chunk := range filePatch.Chunks() {
			// Create the content for the chunk
			change := Range{StartRow: startRow, StartCol: startCol}
			// Parse cursor based on the operation
			switch chunk.Type() {
			case goDiff.Delete:
				// Deleted content = content that was added in the source (target is always a commit behind)
				change.EndRow, change.EndCol = getCursorNewPosition(startRow, startCol, chunk.Content())
				// Move the cursor to the end of the deleted content
				startRow, startCol = change.EndRow, change.EndCol
				// Add the range of the content
				changes.Ranges = append(changes.Ranges, change)
			case goDiff.Equal:
				// Unchanged content, Move the cursor to the end of the unchanged content
				startRow, startCol = getCursorNewPosition(startRow, startCol, chunk.Content())
			}
		}
		if len(changes.Ranges) > 0 {
			// Add the changes to the diff content
			content.ChangedFiles = append(content.ChangedFiles, changes)
		}
	}
	return
}

func getFilePathFromFiles(filePatch goDiff.FilePatch) string {
	from, to := filePatch.Files()
	fromPath := ""
	if from != nil {
		fromPath = from.Path()
	}
	toPath := ""
	if to != nil {
		toPath = to.Path()
	}
	log.Debug(fmt.Sprintf("Checking Diff between: %s (from) and %s (to)", fromPath, toPath))
	if fromPath == "" {
		return toPath
	}
	if toPath == "" {
		return fromPath
	}
	return fromPath
}

func getCursorNewPosition(cursorRow, cursorCol int, chunk string) (newRow, newCol int) {
	newRow, newCol = cursorRow, cursorCol
	for _, char := range chunk {
		if char == '\n' {
			newRow++
			newCol = 1
		} else {
			newCol++
		}
	}
	return
}