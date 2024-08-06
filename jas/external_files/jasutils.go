package external_files

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/jfrog/gofrog/unarchive"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/utils"
)

func FileExists(name string) bool {
	if fi, err := os.Stat(name); err == nil {
		if fi.Mode().IsRegular() {
			return true
		}
	}
	return false
}

func UnzipSource(source, destination string) error {
	dst := destination
	archive, err := zip.OpenReader(source)
	if err != nil {
		panic(err)
	}
	defer archive.Close()

	for _, f := range archive.File {
		filePath := filepath.Join(dst, f.Name)
		print("unzipping file ")
		print(filePath)
		print("\n")

		if !strings.HasPrefix(filePath, filepath.Clean(dst)+string(os.PathSeparator)) {
			print("invalid file path\n")

		}
		if f.FileInfo().IsDir() {
			continue
		}

		if FileExists(filepath.Dir(filepath.Dir(filePath))) {
			print("Removing file")
			os.RemoveAll(filePath)

		}

		if FileExists(filepath.Dir(filePath)) {
			print("Removing file")
			os.RemoveAll(filePath)

		}

		if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
			print("AWHDOASDOASO\n")
			print(filepath.Dir(filePath))
			print("\n")
			panic(err)
		}

		dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			panic(err)
		}

		fileInArchive, err := f.Open()
		if err != nil {
			panic(err)
		}

		if _, err := io.Copy(dstFile, fileInArchive); err != nil {
			panic(err)
		}

		dstFile.Close()
		fileInArchive.Close()
	}
	return nil
}

func copy(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}

func SwapScanners(destinationSuffixFolder string, destinationExecutableName string) {
	exePath, _ := os.Executable()    // Get the executable file's path
	dirPath := filepath.Dir(exePath) // Get the directory of the executable file
	analyzerManagerDir, err := utils.GetAnalyzerManagerDirAbsolutePath()
	if err != nil {
		print("Error: can't get deps folder\n")
	}
	jfrogDirHome, err := coreutils.GetJfrogHomeDir()
	if err != nil {
		print("Error: can't get deps folder\n")
	}

	analyzerManagerPath := filepath.Join(analyzerManagerDir, destinationSuffixFolder)
	print("switching executable directory:" + analyzerManagerPath + "\n")
	err = os.RemoveAll(analyzerManagerPath) //remove the path

	if err != nil {
		print("Failed to delete analyzerManagerPath folder\n")
	}

	unarchiver := &unarchive.Unarchiver{
		BypassInspection: true,
	}
	if err != nil {
		panic(err)
	}

	print("Creating just in case:" + jfrogDirHome + "\n")
	err = os.MkdirAll(jfrogDirHome, 0755)
	if err != nil {
		panic(err)
	}

	err = os.MkdirAll(analyzerManagerPath, 0755)
	if err != nil {
		panic(err)
	}
	err = unarchiver.Unarchive(filepath.Join(dirPath, "jas.zip"), "jas.zip", analyzerManagerPath)
	if err != nil {
		panic(err)
	}

	if destinationExecutableName != "jas_scanner" {
		if runtime.GOOS == "windows" {
			_, err = copy(filepath.Join(analyzerManagerPath, "jas_scanner.exe"), filepath.Join(analyzerManagerPath, destinationExecutableName+".exe"))
		} else {
			if destinationSuffixFolder != "jas_scanner" {
				_, err = copy(filepath.Join(analyzerManagerPath, "jas_scanner"), filepath.Join(analyzerManagerPath, destinationExecutableName))
			}
		}
		if err != nil {
			panic(err)
		}
	}

	switch runtime.GOOS {
	case "windows":
	case "darwin":
		cmd := exec.Command("chmod", "755", filepath.Join(analyzerManagerPath, destinationExecutableName))
		cmd.Run()
		cmd = exec.Command("xattr", "-rd", "com.apple.quarantine", analyzerManagerPath)
		cmd.Run()
	case "linux":
		cmd := exec.Command("chmod", "755", filepath.Join(analyzerManagerPath, destinationExecutableName))
		cmd.Run()
	default:
	}
}

func SwapAnalyzerManager() {
	exePath, _ := os.Executable()    // Get the executable file's path
	dirPath := filepath.Dir(exePath) // Get the directory of the executable file
	analyzerManagerDir, err := utils.GetAnalyzerManagerDirAbsolutePath()
	if err != nil {
		panic(err)
	}
	analyzerManagerZipPath := filepath.Join(dirPath, "analyzerManager.zip")
	analyzerManagerZipPathDest := filepath.Join(analyzerManagerDir, "analyzerManager")

	if _, err := os.Stat(analyzerManagerZipPath); err == nil {
		print("analyzermanager.zip found, overwriting\n")
		if err != nil {
			print("Error: can't get deps folder\n")
		}
		if err != nil {
			print("Error: can't get deps folder\n")
		}

		unarchiver := &unarchive.Unarchiver{
			BypassInspection: true,
		}
		if err != nil {
			panic(err)
		}

		err = unarchiver.Unarchive(analyzerManagerZipPath, "analyzerManager.zip", analyzerManagerDir)
		if err != nil {
			panic(err)
		}

		switch runtime.GOOS {
		case "windows":
		case "darwin":
			cmd := exec.Command("chmod", "755", analyzerManagerZipPathDest)
			cmd.Run()
			cmd = exec.Command("xattr", "-rd", "com.apple.quarantine", analyzerManagerZipPathDest)
			cmd.Run()
		case "linux":
			cmd := exec.Command("chmod", "755", analyzerManagerZipPathDest)
			cmd.Run()
		default:
		}

	} else {
		print("No analyzerManager.zip found, not overwriting\n")
	}

}
