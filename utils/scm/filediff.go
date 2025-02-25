package scm

import (
	"fmt"
	// "strings"

	goDiff "github.com/go-git/go-git/v5/plumbing/format/diff"

	"github.com/jfrog/gofrog/datastructures"
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

type MarkedRange struct {
	goDiff.Operation
	Range
}

func (mr MarkedRange) String() string {
	return fmt.Sprintf("(%s) %s", opToStr(mr.Operation), mr.Range)
}

func opToStr(op goDiff.Operation) string {
	switch op {
	case goDiff.Add:
		return "Add"
	case goDiff.Delete:
		return "Delete"
	case goDiff.Equal:
		return "Equal"
	default:
		return "Unknown"
	}
}

type FileDiffGenerator struct {
	Path           string
	OrderedContent []MarkedRange
}

func (fdg FileDiffGenerator) String() string {
	return fmt.Sprintf("%s: %v", fdg.Path, fdg.OrderedContent)
}

func FilePatchToFileDiffGenerator(filePatches ...goDiff.FilePatch) (fileDiffs []FileDiffGenerator) {
	for _, filePatch := range filePatches {
		fileDiff := FileDiffGenerator{Path: getFilePathFromFiles(filePatch)}
		startRow, startCol := 1, 1
		for _, chunk := range filePatch.Chunks() {
			// Create the content for the chunk
			content := MarkedRange{Operation: chunk.Type(), Range: Range{StartRow: startRow, StartCol: startCol}}

			log.Debug(fmt.Sprintf("Chunk (type = %s): \"%s\"", opToStr(content.Operation), chunk.Content()))
			// Parse cursor based on the operation
			// switch content.Operation {
			// case goDiff.Equal:

			// }

			// Update the cursor position and content end position
			startRow, startCol = getCursorNewPosition(startRow, startCol, chunk.Content())
			content.EndRow, content.EndCol = startRow, startCol
			// Add the content to the ordered content
			log.Debug(fmt.Sprintf("Adding ordered content: %s", content))
			fileDiff.OrderedContent = append(fileDiff.OrderedContent, content)
		}
		fileDiffs = append(fileDiffs, fileDiff)
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

// TODO: DELETE

type ChangesRelevantToScan struct {
	ChangedFiles    []FileChanges
	ChangedBinaries []string
}

func (c ChangesRelevantToScan) HasChanges() bool {
	return c.HasFileChanges() || c.HasBinaryChanges()
}

func (c ChangesRelevantToScan) HasFileChanges() bool {
	return len(c.ChangedFiles) > 0
}

func (c ChangesRelevantToScan) HasBinaryChanges() bool {
	return len(c.ChangedBinaries) > 0
}

func (c ChangesRelevantToScan) GetChangedFilesPaths() (paths []string) {
	for _, file := range c.ChangedFiles {
		paths = append(paths, file.Path)
	}
	return
}

func (c ChangesRelevantToScan) GetFileChanges(path string) (changes *FileChanges) {
	for _, file := range c.ChangedFiles {
		if file.Path == path {
			return &file
		}
	}
	return
}

// FileChangeRanges represents the changes in the
type FileChanges struct {
	Path    string
	Changes []Range
}

func (f FileChanges) String() string {
	return fmt.Sprintf("%s: %v", f.Path, f.Changes)
}

func (f FileChanges) Contains(startRow, startCol, endRow, endCol int) bool {
	for _, change := range f.Changes {
		if change.Contains(startRow, startCol, endRow, endCol) {
			return true
		}
	}
	return false
}

func (f FileChanges) Overlaps(startRow, startCol, endRow, endCol int) bool {
	for _, change := range f.Changes {
		if change.Overlaps(startRow, startCol, endRow, endCol) {
			return true
		}
	}
	return false
}

// The Source code is the code at the cwd, the target
// if removedContent is true, the content of the removed files is relevant. else only the added content is relevant
func detectRelevantChanges(filePatches []goDiff.FilePatch, removedContent bool) (changes ChangesRelevantToScan, err error) {
	binariesChanged := datastructures.MakeSet[string]()
	// Go over the file patches and detect the relevant changes
	for _, filePatch := range filePatches {
		relevantFileName := getRelevantFileName(filePatch, removedContent)
		if relevantFileName == "" {
			// Not relevant file
			continue
		}
		// Get the relevant changes for the file
		if filePatch.IsBinary() {
			// Binary file, only file path is relevant
			binariesChanged.Add(relevantFileName)
			continue
		}
		// Get the relevant changes in the file, if new file (from is nil) all the content is relevant
		if fileChanges := processFileChunksForRelevantChanges(filePatch.Chunks(), removedContent); len(fileChanges) > 0 {
			changes.ChangedFiles = append(changes.ChangedFiles, FileChanges{Path: relevantFileName, Changes: fileChanges})
		}
	}
	changes.ChangedBinaries = binariesChanged.ToSlice()
	return
}

func getRelevantFileName(filePatch goDiff.FilePatch, removedContent bool) string {
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
	if removedContent && from != nil {
		// removedContent = source is after target, if content is removed from 'from' it is relevant
		log.Debug(fmt.Sprintf("Removed content: %s", from.Path()))
		return from.Path()
	} else if !removedContent && to != nil {
		// addedContent = source is before target, if content is added to 'to' it is relevant
		log.Debug(fmt.Sprintf("Added content: %s", to.Path()))
		return to.Path()
	}
	// No relevant file name
	log.Debug("No relevant file name")
	return ""
}

func processFileChunksForRelevantChanges(fileChunks []goDiff.Chunk, removedContent bool) (relevantChanges []Range) {
	// SARIF locations start at 1
	row, col := 1, 1
	for _, diffChunk := range fileChunks {
		chunkContent := diffChunk.Content()
		log.Debug(fmt.Sprintf("Chunk (type = %d): \"%s\"", diffChunk.Type(), chunkContent))
		switch diffChunk.Type() {
		case goDiff.Add:
			// Added content
			// Add the range of the added content
			if !removedContent {
				relevantChanges = append(relevantChanges, Range{StartRow: row, StartCol: col, EndRow: row, EndCol: col + len(chunkContent)})
			}
			// Move the cursor to the end of the added content

		case goDiff.Delete:
			// Deleted content
			if removedContent {
				relevantChanges = append(relevantChanges, Range{StartRow: row, StartCol: col, EndRow: row, EndCol: col + len(chunkContent)})
			}

			// Move the cursor to the end of the deleted content

		case goDiff.Equal:
			// Unchanged content
			// Move the cursor to the end of the unchanged content

		}
	}
	return
}

// func createRangeAtChunk(cursorRow, cursorCol int, chunk string) Range {
// 	return Range{StartRow: row, StartCol: col, EndRow: row, EndCol: col + len(chunk)}
// }

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
