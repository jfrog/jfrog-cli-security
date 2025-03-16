package scm

import (
	"fmt"
	"strings"

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

func (f FileChanges) Contains(startRow, startCol, endRow, endCol int) bool {
	for _, r := range f.Ranges {
		if r.Contains(startRow, startCol, endRow, endCol) {
			return true
		}
	}
	return false
}

func (f FileChanges) Overlaps(startRow, startCol, endRow, endCol int) bool {
	for _, r := range f.Ranges {
		if r.Overlaps(startRow, startCol, endRow, endCol) {
			return true
		}
	}
	return false
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

// Source is always after the target common ancestor in the branches working tree.
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
			content := chunk.Content()
			er, ec := getContentEndPosition(startRow, startCol, content)
			log.Info(fmt.Sprintf("Chunk type: %d, content: '%s'\nStartRow: %d, StartCol: %d (EndRow: %d, EndCol: %d)", chunk.Type(), content, change.StartRow, change.StartCol, er, ec))
			// Parse cursor based on the operation
			switch chunk.Type() {
				// TODO: if remove + add, edge (start or end) can be the same for both, we should trim the shared content as changed
			case goDiff.Delete:
				
				// Deleted content = content that was added in the source (target is always behind source)
				change.EndRow, change.EndCol = getContentEndPosition(startRow, startCol, content)
				// Move the cursor to the end of the deleted content
				startRow, startCol = getCursorNewPosition(startRow, startCol, content)
				// Add the range of the content
				changes.Ranges = append(changes.Ranges, change)
			case goDiff.Equal:
				// Unchanged content, Move the cursor to the end of the unchanged content
				startRow, startCol = getCursorNewPosition(startRow, startCol, content)
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

func getContentEndPosition(startRow, startCol int, content string) (endRow, endCol int) {
	endRow, endCol = startRow, startCol
	for i, char := range content {
		if char == '\n' {
			if i < len(content)-1 {
				// New line should take into account only if it is not the last character
				endRow++
				endCol = 1
			}
		} else {
			endCol++
		}
	}
	return
}

func getCursorNewPosition(cursorRow, cursorCol int, chunk string) (newRow, newCol int) {
	newRow, newCol = getContentEndPosition(cursorRow, cursorCol, chunk)
	if chunk[len(chunk)-1] == '\n' {
		// new position should take into account the new line character
		newRow++
		newCol = 1
	}
	return
}

// Function to find the shared substring where the suffix of str1 matches the prefix of str2
func findSharedSubstring(str1, str2 string) string {
	maxLength := min(len(str1), len(str2))

	// Iterate to find the longest matching suffix-prefix
	for i := 1; i <= maxLength; i++ {
		if strings.HasSuffix(str1, str2[:i]) {
			return str2[:i] // Return the shared substring
		}
	}
	return "" // No shared substring
}