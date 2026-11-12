package exec

import (
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/zouuup/landrun/internal/log"
)

// firstExtraFD is the first descriptor beyond the standard streams.
// Descriptors 0, 1 and 2 are always inherited by the sandboxed command.
const firstExtraFD = 3

// ValidateInheritFDs verifies that every descriptor requested via
// --inherit-fd refers to an open, non-standard descriptor and is listed at
// most once. It must run before the sandbox is applied so that invalid or
// overlapping configurations are rejected before anything is executed.
func ValidateInheritFDs(fds []int) error {
	seen := make(map[int]struct{}, len(fds))
	for _, fd := range fds {
		if fd < 0 {
			return fmt.Errorf("invalid file descriptor %d: must not be negative", fd)
		}
		if fd < firstExtraFD {
			return fmt.Errorf("invalid file descriptor %d: standard descriptors 0, 1 and 2 are always inherited", fd)
		}
		if _, ok := seen[fd]; ok {
			return fmt.Errorf("duplicate file descriptor %d", fd)
		}
		seen[fd] = struct{}{}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return fmt.Errorf("file descriptor %d is not open", fd)
		}
	}
	return nil
}

func Run(args []string, env []string, inheritFDs []int) error {
	binary, err := exec.LookPath(args[0])
	if err != nil {
		return err
	}

	if err := CloseInheritedFDs(inheritFDs); err != nil {
		return err
	}

	log.Info("Executing: %v", args)

	// Only pass the explicitly specified environment variables
	// If env is empty, no environment variables will be passed
	return syscall.Exec(binary, args, env)
}

// CloseInheritedFDs closes every inherited descriptor other than 0, 1, 2 and
// the descriptors listed in keep. This prevents open files of the parent
// process (e.g. pipeline log files) from remaining writable inside the
// sandbox, which would bypass Landlock path restrictions. Kept descriptors
// have FD_CLOEXEC cleared so they survive the execve(2) that follows;
// descriptors not listed in keep retain their usual close-on-exec behavior.
func CloseInheritedFDs(keep []int) error {
	for _, fd := range keep {
		if fd < firstExtraFD {
			continue
		}
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, 0); err != nil {
			return fmt.Errorf("failed to clear close-on-exec on file descriptor %d: %w", fd, err)
		}
	}

	sorted := append([]int(nil), keep...)
	sort.Ints(sorted)

	first := firstExtraFD
	for _, fd := range sorted {
		if fd < firstExtraFD {
			continue
		}
		if err := closeRange(uint(first), uint(fd-1)); err != nil {
			return err
		}
		first = fd + 1
	}
	return closeRange(uint(first), math.MaxUint32)
}

// closeRange closes every open descriptor in [first, last]. It prefers the
// close_range(2) syscall, which needs no filesystem access and therefore
// works even after Landlock restrictions are in place, and falls back to
// enumerating /proc/self/fd on kernels without close_range(2).
func closeRange(first, last uint) error {
	if first > last {
		return nil
	}
	err := unix.CloseRange(first, last, 0)
	if err == nil {
		return nil
	}
	if !errors.Is(err, unix.ENOSYS) {
		return fmt.Errorf("failed to close inherited file descriptors: %w", err)
	}
	return closeRangeProc(first, last)
}

func closeRangeProc(first, last uint) error {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return fmt.Errorf("failed to list open file descriptors: %w", err)
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil || fd < 0 {
			continue
		}
		if uint(fd) < first || uint(fd) > last {
			continue
		}
		// Best effort: the descriptor may already be gone.
		_ = unix.Close(fd)
	}
	return nil
}
