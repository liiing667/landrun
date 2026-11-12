package exec

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

func TestValidateInheritFDs(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	openFD := int(w.Fd())

	closedR, closedW, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	closedFD := int(closedW.Fd())
	closedR.Close()
	closedW.Close()

	tests := []struct {
		name    string
		fds     []int
		wantErr bool
	}{
		{name: "nil", fds: nil, wantErr: false},
		{name: "empty", fds: []int{}, wantErr: false},
		{name: "open fd", fds: []int{openFD}, wantErr: false},
		{name: "negative", fds: []int{-1}, wantErr: true},
		{name: "stdin", fds: []int{0}, wantErr: true},
		{name: "stdout", fds: []int{1}, wantErr: true},
		{name: "stderr", fds: []int{2}, wantErr: true},
		{name: "duplicate", fds: []int{openFD, openFD}, wantErr: true},
		{name: "closed fd", fds: []int{closedFD}, wantErr: true},
		{name: "one valid one closed", fds: []int{openFD, closedFD}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateInheritFDs(tc.fds)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for fds %v, got nil", tc.fds)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error for fds %v, got %v", tc.fds, err)
			}
		})
	}
}

// TestRunInheritedFDPolicy exercises Run end to end in a helper subprocess:
// the helper re-executes the test binary through Run, and the resulting
// checker process verifies which inherited descriptors survived.
func TestRunInheritedFDPolicy(t *testing.T) {
	switch os.Getenv("LANDRUN_TEST_ROLE") {
	case "helper-keep":
		runHelper(t, []int{100})
		return
	case "helper-default":
		runHelper(t, nil)
		return
	case "checker-keep":
		expectFD(t, 100, true)
		expectFD(t, 101, false)
		return
	case "checker-default":
		expectFD(t, 100, false)
		expectFD(t, 101, false)
		return
	}

	for _, mode := range []string{"keep", "default"} {
		t.Run(mode, func(t *testing.T) {
			kept, err := os.Open("/dev/null")
			if err != nil {
				t.Fatalf("failed to open /dev/null: %v", err)
			}
			defer kept.Close()
			dropped, err := os.Open("/dev/null")
			if err != nil {
				t.Fatalf("failed to open /dev/null: %v", err)
			}
			defer dropped.Close()

			cmd := exec.Command(os.Args[0], "-test.run=TestRunInheritedFDPolicy")
			cmd.Env = append(os.Environ(),
				"LANDRUN_TEST_ROLE=helper-"+mode,
				"LANDRUN_TEST_MODE="+mode,
			)
			// Become descriptors 3 and 4 in the helper process.
			cmd.ExtraFiles = []*os.File{kept, dropped}

			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("helper failed: %v\n%s", err, out)
			}
		})
	}
}

// runHelper moves the extra files to stable, high descriptor numbers (so the
// checker's Go runtime cannot reuse them) and then replaces itself via Run.
func runHelper(t *testing.T, keep []int) {
	t.Helper()

	// Descriptor 100 is marked close-on-exec on purpose: Run must clear the
	// flag for whitelisted descriptors so they survive execve(2).
	if err := unix.Dup3(3, 100, unix.O_CLOEXEC); err != nil {
		t.Fatalf("failed to duplicate fd 3 to 100: %v", err)
	}
	if err := unix.Dup3(4, 101, 0); err != nil {
		t.Fatalf("failed to duplicate fd 4 to 101: %v", err)
	}

	mode := os.Getenv("LANDRUN_TEST_MODE")
	err := Run(
		[]string{os.Args[0], "-test.run=TestRunInheritedFDPolicy"},
		[]string{"LANDRUN_TEST_ROLE=checker-" + mode},
		keep,
	)
	// Run only returns when the exec failed.
	t.Fatalf("Run returned unexpectedly: %v", err)
}

func expectFD(t *testing.T, fd int, wantOpen bool) {
	t.Helper()

	var stat unix.Stat_t
	err := unix.Fstat(fd, &stat)
	if wantOpen && err != nil {
		t.Errorf("expected fd %d to be open, got %v", fd, err)
	}
	if !wantOpen && !errors.Is(err, unix.EBADF) {
		t.Errorf("expected fd %d to be closed, got err=%v", fd, err)
	}
}
