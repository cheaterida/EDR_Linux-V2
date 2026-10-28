package respond

import (
	"fmt"
	"syscall"
)

// pidfd syscalls (x86_64, kernel 5.3+). Not in the syscall package yet.
const (
	sysPidfdOpen       = 434
	sysPidfdSendSignal = 424
)

// pidfdSignal sends sig to pid via a pidfd, which is immune to PID reuse.
func pidfdSignal(pid int, sig syscall.Signal) error {
	fd, _, errno := syscall.RawSyscall(sysPidfdOpen, uintptr(pid), 0, 0)
	if errno != 0 {
		return fmt.Errorf("pidfd_open(%d): %v", pid, errno)
	}
	defer syscall.Close(int(fd))
	_, _, errno = syscall.RawSyscall6(sysPidfdSendSignal, fd, uintptr(sig), 0, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("pidfd_send_signal(%d): %v", pid, errno)
	}
	return nil
}

// pidfdKill sends SIGKILL via pidfd.
func pidfdKill(pid int) error {
	return pidfdSignal(pid, syscall.SIGKILL)
}
