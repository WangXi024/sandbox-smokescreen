package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func workspaceTestCall(t *testing.T, request workspaceFSRequest) workspaceFSReply {
	t.Helper()
	reply := workspaceFilesystem(request)
	if reply.ErrorCode != "" {
		t.Fatalf("%s: %s", request.Op, reply.ErrorCode)
	}
	return reply
}
func TestWorkspacePOSIX(t *testing.T) {
	base := t.TempDir()
	file := filepath.Join(base, "data")
	payload := bytes.Repeat([]byte{0, 255, 17, 93}, workspaceFileLimit/4)
	workspaceTestCall(t, workspaceFSRequest{Op: "write", Path: file, Data: payload, Mode: 0640})
	if got := workspaceTestCall(t, workspaceFSRequest{Op: "read", Path: file}).Data; !bytes.Equal(got, payload) {
		t.Fatal("8MiB roundtrip mismatch")
	}
	stat := workspaceTestCall(t, workspaceFSRequest{Op: "stat", Path: file}).Entries[0]
	if stat.Size != uint64(len(payload)) || stat.Mode != 0640 {
		t.Fatalf("wrong native metadata %+v", stat)
	}
	workspaceTestCall(t, workspaceFSRequest{Op: "chmod", Path: file, Mode: 0600})
	if got := workspaceTestCall(t, workspaceFSRequest{Op: "stat", Path: file}).Entries[0].Mode; got != 0600 {
		t.Fatal(got)
	}
	dir := filepath.Join(base, "directory")
	os.Mkdir(dir, 0700)
	workspaceTestCall(t, workspaceFSRequest{Op: "symlink", Path: filepath.Join(base, "link"), Target: "directory"})
	if !workspaceTestCall(t, workspaceFSRequest{Op: "stat", Path: filepath.Join(base, "link")}).Entries[0].IsDir {
		t.Fatal("stat must follow directory link")
	}
	entries := workspaceTestCall(t, workspaceFSRequest{Op: "list", Path: base}).Entries
	found := false
	for _, entry := range entries {
		if entry.Name == "link" {
			found = true
			if entry.Kind != "symlink" || !entry.IsDir || entry.LinkTarget != "directory" {
				t.Fatal(entry)
			}
		}
	}
	if !found {
		t.Fatal("no symlink entry")
	}
	if got := workspaceTestCall(t, workspaceFSRequest{Op: "list", Path: dir}); len(got.Entries) != 0 {
		t.Fatal("empty directory")
	}
	cases := []struct {
		op, path           string
		recursive, parents bool
		want               string
	}{
		{"read", dir, false, false, "IS_DIRECTORY"},
		{"remove", filepath.Join(base, "missing"), true, false, "MISSING"},
		{"mkdir", file, false, true, "ALREADY_EXISTS"},
		{"list", file, false, false, "NOT_DIRECTORY"},
	}
	for _, tc := range cases {
		got := workspaceFilesystem(workspaceFSRequest{Op: tc.op, Path: tc.path, Recursive: tc.recursive, Parents: tc.parents})
		if got.ErrorCode != tc.want {
			t.Fatalf("%s got %s want %s", tc.op, got.ErrorCode, tc.want)
		}
	}
	fifo := filepath.Join(base, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if got := workspaceFilesystem(workspaceFSRequest{Op: "read", Path: fifo}).ErrorCode; got != "UNSUPPORTED_FILE_TYPE" {
		t.Fatal(got)
	}
	if time.Since(started) > time.Second {
		t.Fatal("FIFO read blocked")
	}
	if got := workspaceFilesystem(workspaceFSRequest{Op: "write", Path: file, Data: append(payload, 0)}).ErrorCode; got != "LIMIT_EXCEEDED" {
		t.Fatal(got)
	}
}
func TestWorkspaceRemoveProtection(t *testing.T) {
	base := t.TempDir()
	link := filepath.Join(base, "root-link")
	os.Symlink("/", link)
	if got := workspaceFilesystem(workspaceFSRequest{Op: "remove", Path: link, Recursive: true}).ErrorCode; got != "" {
		t.Fatal("unlink symlink itself must be safe: ", got)
	}
	if got := workspaceFilesystem(workspaceFSRequest{Op: "remove", Path: "/", Recursive: true}).ErrorCode; got != "PERMISSION_DENIED" {
		t.Fatal("root deletion must be rejected before remove: ", got)
	}
}
func TestWorkspaceRealpath(t *testing.T) {
	base := t.TempDir()
	os.MkdirAll(filepath.Join(base, "deep", "nested"), 0700)
	os.Symlink("deep/nested", filepath.Join(base, "link"))
	got := workspaceTestCall(t, workspaceFSRequest{Op: "realpath", Path: base + "/link/../missing/child"}).Path
	if got != filepath.Join(base, "deep/missing/child") {
		t.Fatalf("link/.. semantics: %s", got)
	}
	os.Symlink("loop", filepath.Join(base, "loop"))
	if got := workspaceFilesystem(workspaceFSRequest{Op: "realpath", Path: filepath.Join(base, "loop")}).ErrorCode; got != "SYMLINK_LOOP" {
		t.Fatal(got)
	}
}
func TestWorkspaceHelperIdentityAndPermissions(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("root control process required")
	}
	if err := os.MkdirAll("/workspace", 0755); err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp("/workspace", "fshelper-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	os.Chmod(base, 0777)
	call := func(request workspaceFSRequest) workspaceFSReply {
		t.Helper()
		payload, _ := json.Marshal(request)
		reply, err := workspaceFilesystemAsUser(context.Background(), payload)
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}
	file := filepath.Join(base, "user.txt")
	if r := call(workspaceFSRequest{Op: "write", Path: file, Data: []byte("native")}); r.ErrorCode != "" {
		t.Fatal(r.ErrorCode)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	if st.Uid != 1000 || st.Gid != 1000 {
		t.Fatalf("wrong owner %d:%d", st.Uid, st.Gid)
	}
	if r := call(workspaceFSRequest{Op: "chmod", Path: file, Mode: 0}); r.ErrorCode != "" {
		t.Fatal(r.ErrorCode)
	}
	for _, op := range []string{"read", "write"} {
		if r := call(workspaceFSRequest{Op: op, Path: file, Data: []byte("blocked")}); r.ErrorCode != "PERMISSION_DENIED" {
			t.Fatal("owner chmod000 bypass: ", op, r.ErrorCode)
		}
	}
	rootFile := filepath.Join(base, "root.txt")
	os.WriteFile(rootFile, []byte("must not read"), 0600)
	if r := call(workspaceFSRequest{Op: "read", Path: rootFile}); r.ErrorCode != "PERMISSION_DENIED" {
		t.Fatal("UID1000 permissions bypass: ", r.ErrorCode)
	}
	if r := call(workspaceFSRequest{Op: "write", Path: "/proc/self/fd/3", Data: []byte("forged-control")}); r.ErrorCode == "" {
		t.Fatal("control FD must not be reopened via proc")
	}

}

func TestWorkspaceMagicControlPaths(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("root helper required")
	}
	os.MkdirAll("/workspace", 0755)
	base, err := os.MkdirTemp("/workspace", "magic-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	os.Chmod(base, 0777)
	for i, path := range []string{"/proc/self/fd/3", "/proc/thread-self/fd/3", "/dev/fd/3"} {
		alias := filepath.Join(base, "alias"+strconv.Itoa(i))
		if err := os.Symlink(path, alias); err != nil {
			t.Fatal(err)
		}
		for _, candidate := range []string{path, alias} {
			for _, op := range []string{"read", "write", "realpath"} {
				payload, _ := json.Marshal(workspaceFSRequest{Op: op, Path: candidate, Data: []byte("forged-control")})
				reply, err := workspaceFilesystemAsUser(context.Background(), payload)
				if err != nil || reply.ErrorCode != "PERMISSION_DENIED" {
					t.Fatalf("%s %s: %s %v", op, candidate, reply.ErrorCode, err)
				}
			}
		}
		payload, _ := json.Marshal(workspaceFSRequest{Op: "remove", Path: alias})
		reply, err := workspaceFilesystemAsUser(context.Background(), payload)
		// Directory root is 0777 and alias is root-owned: UID1000 can safely unlink it.
		if err != nil || reply.ErrorCode != "" {
			t.Fatalf("unlink alias: %s %v", reply.ErrorCode, err)
		}
	}
	if fd, err := workspaceOpen("/proc/self/fd/1", syscall.O_WRONLY, 0); err == nil {
		syscall.Close(fd)
		t.Fatal("kernel NO_MAGICLINKS guard bypassed")
	}
}

func init() {
	if len(os.Args) == 3 && os.Args[1] == "--lazyx-test-control-attack" {
		pid, err := strconv.Atoi(os.Args[2])
		if err != nil {
			os.Exit(2)
		}
		fd, openErr := syscall.Open("/proc/"+strconv.Itoa(pid)+"/fd/3", syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
		if openErr == nil {
			syscall.Close(fd)
		}
		ptraceErr := syscall.PtraceAttach(pid)
		if ptraceErr == nil {
			syscall.PtraceDetach(pid)
		}
		readFD, readErr := syscall.Open("/proc/"+strconv.Itoa(pid)+"/fd/3", syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
		if readErr == nil {
			syscall.Close(readFD)
		}
		stdinFD, stdinErr := syscall.Open("/proc/"+strconv.Itoa(pid)+"/fd/0", syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
		if stdinErr == nil {
			syscall.Close(stdinFD)
		}
		memFD, memErr := syscall.Open("/proc/"+strconv.Itoa(pid)+"/mem", syscall.O_RDWR, 0)
		if memErr == nil {
			syscall.Close(memFD)
		}
		signalErr := syscall.Kill(pid, 0)
		if openErr == nil || ptraceErr == nil || readErr == nil || stdinErr == nil || memErr == nil || signalErr == nil {
			os.Exit(3)
		}
		os.Exit(0)
	}
}
func TestWorkspaceCrossUIDControlBoundary(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("root helper required")
	}
	os.MkdirAll("/workspace", 0755)
	base, err := os.MkdirTemp("/workspace", "boundary-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	os.Chmod(base, 0777)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(base, "test-attacker")
	if err = os.WriteFile(copyPath, binary, 0755); err != nil {
		t.Fatal(err)
	}
	inputRead, inputWrite, _ := os.Pipe()
	controlRead, controlWrite, _ := os.Pipe()
	defer inputWrite.Close()
	defer controlRead.Close()
	command := exec.Command(executable, "--lazyx-workspace-filesystem")
	command.Stdin = inputRead
	command.ExtraFiles = []*os.File{controlWrite}
	command.Dir = "/workspace"
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	inputRead.Close()
	controlWrite.Close()
	defer func() { command.Process.Kill(); command.Wait() }()
	ready := false
	for i := 0; i < 200; i++ {
		data, _ := os.ReadFile("/proc/" + strconv.Itoa(command.Process.Pid) + "/status")
		status := string(data)
		if strings.Contains(status, "Uid:\t0\t1000\t0\t1000") && strings.Contains(status, "Gid:\t0\t1000\t0\t1000") && strings.Contains(status, "CapEff:\t0000000000000000") {
			ready = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !ready {
		t.Fatal("helper control root identity / UID1000 FS / zero capabilities not observed")
	}
	threads, err := os.ReadDir("/proc/" + strconv.Itoa(command.Process.Pid) + "/task")
	if err != nil {
		t.Fatal(err)
	}
	for _, thread := range threads {
		data, err := os.ReadFile("/proc/" + strconv.Itoa(command.Process.Pid) + "/task/" + thread.Name() + "/status")
		if err != nil {
			t.Fatal(err)
		}
		status := string(data)
		if !strings.Contains(status, "CapEff:\t0000000000000000") || !strings.Contains(status, "CapPrm:\t0000000000000000") {
			t.Fatal("helper thread retained capabilities")
		}
	}

	attack := func(path string) ([]byte, error) {
		attacker := exec.Command(path, "--lazyx-test-control-attack", strconv.Itoa(command.Process.Pid))
		attacker.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
		return attacker.CombinedOutput()
	}
	// Docker tmpfs is noexec by default. The fixed image binary is executable
	// in gVisor; Go's transient unit-test binary may instead have a 0700 parent.
	out, attackErr := attack(executable)
	if errors.Is(attackErr, os.ErrPermission) {
		out, attackErr = attack(copyPath)
	}
	if attackErr != nil {
		t.Fatalf("UID1000 proc/ptrace/signal boundary failed: %v %s", attackErr, out)
	}
	inputWrite.Write([]byte("{\"op\":\"stat\",\"path\":\"/workspace\"}"))
	inputWrite.Close()
	payload, err := io.ReadAll(controlRead)
	if err != nil {
		t.Fatal(err)
	}
	var reply workspaceFSReply
	if err = json.Unmarshal(payload, &reply); err != nil || reply.ErrorCode != "" {
		t.Fatalf("control reply corrupted: %v %+v", err, reply)
	}
}
