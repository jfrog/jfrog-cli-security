//go:build !windows

package jas

import (
	"os"
	"os/exec"
	"syscall"
)

// setProcessGroupAttr places the child process in its own process group so the entire tree can be signaled at once.
func setProcessGroupAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessTree terminates the process and all its descendants by sending SIGKILL to the process group.
func killProcessTree(p *os.Process) {
	if p == nil {
		return
	}
	_ = syscall.Kill(-p.Pid, syscall.SIGKILL)
}
