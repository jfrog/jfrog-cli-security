//go:build windows

package jas

import (
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

// setProcessGroupAttr is a no-op on Windows; process tree termination is handled by enumerating child processes.
func setProcessGroupAttr(_ *exec.Cmd) {}

// killProcessTree terminates the process and all its descendants by walking the system process snapshot.
func killProcessTree(p *os.Process) {
	if p == nil {
		return
	}
	killChildProcesses(uint32(p.Pid))
	_ = p.Kill()
}

// killChildProcesses recursively finds and kills all descendants of the given PID using a process snapshot.
func killChildProcesses(parentPID uint32) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return
	}

	for {
		if entry.ParentProcessID == parentPID {
			killChildProcesses(entry.ProcessID)
			if child, err := os.FindProcess(int(entry.ProcessID)); err == nil {
				_ = child.Kill()
			}
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
}
