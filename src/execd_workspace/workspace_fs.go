// Copyright 2026 LazyX contributors; Apache-2.0.
// Native workspace filesystem control. Results use a private pipe, never workload stdout.
package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/gin-gonic/gin"
	"golang.org/x/sys/unix"
)

const workspaceFileLimit = 8 << 20
const workspaceWireLimit = 20 << 20
const workspaceEntriesLimit = 4096

type workspaceFSRequest struct {
	Op        string `json:"op"`
	Path      string `json:"path"`
	Target    string `json:"target"`
	Data      []byte `json:"data"`
	Mode      uint32 `json:"mode"`
	Parents   bool   `json:"parents"`
	Recursive bool   `json:"recursive"`
}
type workspaceFSEntry struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	Kind       string `json:"kind"`
	IsDir      bool   `json:"is_dir"`
	Size       uint64 `json:"size"`
	Mode       uint32 `json:"mode"`
	Modified   int64  `json:"modified_unix_ns"`
	LinkTarget string `json:"link_target"`
}
type workspaceFSReply struct {
	Data       []byte             `json:"data,omitempty"`
	Entries    []workspaceFSEntry `json:"entries,omitempty"`
	Path       string             `json:"path,omitempty"`
	LinkTarget string             `json:"link_target,omitempty"`
	ErrorCode  string             `json:"error_code,omitempty"`
}

func init() {
	if len(os.Args) == 2 && os.Args[1] == "--lazyx-workspace-filesystem" {
		if os.Getuid() != 0 || os.Geteuid() != 0 {
			os.Exit(1)
		}
		runtime.LockOSThread()
		if stage := workspaceDropFilesystemCredentials(); stage != "" {
			control := os.NewFile(3, "workspace-control")
			if control != nil {
				json.NewEncoder(control).Encode(workspaceFSReply{ErrorCode: "CONTROL_" + stage})
				control.Close()
			}
			os.Exit(0)
		}
		reply := workspaceFSReply{}
		var request workspaceFSRequest
		decoder := json.NewDecoder(io.LimitReader(os.Stdin, workspaceWireLimit+1))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			reply.ErrorCode = "INVALID_PATH"
		} else {
			reply = workspaceFilesystem(request)
		}
		control := os.NewFile(3, "workspace-control")
		if control == nil {
			os.Exit(1)
		}
		if err := json.NewEncoder(control).Encode(reply); err != nil {
			os.Exit(1)
		}
		control.Close()
		os.Exit(0)
	}
}

// Keep root real/saved IDs so UID1000 code cannot inspect/ptrace the worker.
// Effective IDs are 1000, which also sets filesystem IDs on Linux and gVisor.
// gVisor intentionally returns ENOSYS for setfsuid/setfsgid; do not depend on them.
func workspaceDropFilesystemCredentials() string {
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Sprintf("SETGROUPS_%v", err)
	}
	if err := syscall.Setresgid(0, 1000, 0); err != nil {
		return fmt.Sprintf("SETRESGID_%v", err)
	}
	if err := syscall.Setresuid(0, 1000, 0); err != nil {
		return fmt.Sprintf("SETRESUID_%v", err)
	}
	if os.Getuid() != 0 || os.Geteuid() != 1000 || os.Getgid() != 0 || os.Getegid() != 1000 {
		return "IDENTITY_MISMATCH"
	}
	header := struct {
		Version uint32
		PID     int32
	}{0x20080522, 0}
	data := [2]struct{ Effective, Permitted, Inheritable uint32 }{}
	// Both production and conformance helper are CGO_ENABLED=0. Apply capset to
	// every Go thread; none may retain permitted capabilities after ID changes.
	_, _, errno := syscall.AllThreadsSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data[0])), 0)
	if errno != 0 {
		return fmt.Sprintf("CAPSET_%d", errno)
	}
	_, _, errno = syscall.RawSyscall(syscall.SYS_PRCTL, 4, 0, 0) // PR_SET_DUMPABLE=0
	if errno != 0 {
		return fmt.Sprintf("SET_DUMPABLE_%d", errno)
	}
	value, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, 3, 0, 0) // PR_GET_DUMPABLE
	if errno != 0 || value != 0 {
		return fmt.Sprintf("GET_DUMPABLE_%d_%d", errno, value)
	}
	return ""
}

func workspaceFilesystemHandler(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, workspaceWireLimit)
	var request workspaceFSRequest
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		c.JSON(http.StatusBadRequest, workspaceFSReply{ErrorCode: "INVALID_PATH"})
		return
	}
	payload, err := json.Marshal(request)
	if err != nil {
		c.JSON(http.StatusBadRequest, workspaceFSReply{ErrorCode: "INVALID_PATH"})
		return
	}
	reply, err := workspaceFilesystemAsUser(c.Request.Context(), payload)
	if err != nil {
		c.JSON(http.StatusOK, workspaceFSReply{ErrorCode: "UNAVAILABLE"})
		return
	}
	c.JSON(http.StatusOK, reply)
}

func workspaceFilesystemAsUser(parent context.Context, payload []byte) (workspaceFSReply, error) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		return workspaceFSReply{}, err
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return workspaceFSReply{}, err
	}
	defer reader.Close()
	command := exec.CommandContext(ctx, executable, "--lazyx-workspace-filesystem")
	command.Dir = "/workspace"
	command.Stdin = bytes.NewReader(payload)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.ExtraFiles = []*os.File{writer}
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/home/sandbox", "TMPDIR=/tmp", "LANG=C.UTF-8"}
	if err = command.Start(); err != nil {
		writer.Close()
		return workspaceFSReply{}, err
	}
	writer.Close()
	result, readErr := io.ReadAll(io.LimitReader(reader, workspaceWireLimit+1))
	waitErr := command.Wait()
	if readErr != nil {
		return workspaceFSReply{}, readErr
	}
	if waitErr != nil {
		return workspaceFSReply{}, waitErr
	}
	if len(result) > workspaceWireLimit {
		return workspaceFSReply{}, syscall.EFBIG
	}
	var reply workspaceFSReply
	if err = json.Unmarshal(result, &reply); err != nil {
		return workspaceFSReply{}, err
	}
	return reply, nil
}

func workspaceFSError(err error) workspaceFSReply {
	code := "UNAVAILABLE"
	switch {
	case errors.Is(err, os.ErrNotExist):
		code = "MISSING"
	case errors.Is(err, os.ErrPermission):
		code = "PERMISSION_DENIED"
	case errors.Is(err, os.ErrExist):
		code = "ALREADY_EXISTS"
	case errors.Is(err, syscall.ELOOP):
		code = "SYMLINK_LOOP"
	case errors.Is(err, syscall.ENOTDIR):
		code = "NOT_DIRECTORY"
	case errors.Is(err, syscall.EISDIR):
		code = "IS_DIRECTORY"
	case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.ENAMETOOLONG), errors.Is(err, syscall.EXDEV):
		code = "INVALID_PATH"
	case errors.Is(err, syscall.EFBIG), errors.Is(err, syscall.ENOSPC):
		code = "LIMIT_EXCEEDED"
	case errors.Is(err, syscall.EOPNOTSUPP), errors.Is(err, syscall.ENXIO):
		code = "UNSUPPORTED_FILE_TYPE"
	}
	return workspaceFSReply{ErrorCode: code}
}

func workspacePath(value string) (string, error) {
	if value == "" || len(value) > 4096 || strings.IndexByte(value, 0) >= 0 {
		return "", syscall.EINVAL
	}
	if !filepath.IsAbs(value) {
		value = "/workspace/" + value
	}
	return value, nil
}

// User filesystem calls must not re-open the helper's own control descriptors.
// Reject virtual mounts through symlink aliases as well as direct paths. Native
// read/write/list also use openat2(NO_MAGICLINKS), so a racing symlink swap cannot
// turn a verified user file into /proc/self/fd/3. Command /proc access is unchanged.
func workspaceRejectVirtual(path string, followFinal bool) error {
	pending := strings.Split(path, "/")
	current := "/"
	links := 0
	for len(pending) > 0 {
		component := pending[0]
		pending = pending[1:]
		if component == "" || component == "." {
			continue
		}
		if component == ".." {
			current = filepath.Dir(current)
			continue
		}
		candidate := filepath.Join(current, component)
		if candidate == "/proc" || candidate == "/sys" || candidate == "/dev" {
			return syscall.EACCES
		}
		if !followFinal && len(pending) == 0 {
			return nil
		}
		info, err := os.Lstat(candidate)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
				current = candidate
				continue
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			links++
			if links > 40 {
				return syscall.ELOOP
			}
			target, err := os.Readlink(candidate)
			if err != nil {
				return err
			}
			if filepath.IsAbs(target) {
				current = "/"
			}
			pending = append(strings.Split(target, "/"), pending...)
		} else {
			current = candidate
		}
	}
	return nil
}
func workspaceOpen(path string, flags int, mode uint32) (int, error) {
	return unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: uint64(flags), Mode: uint64(mode), Resolve: unix.RESOLVE_NO_MAGICLINKS})
}

func workspacePermissions(mode os.FileMode) uint32 {
	value := uint32(mode.Perm())
	if mode&os.ModeSetuid != 0 {
		value |= 04000
	}
	if mode&os.ModeSetgid != 0 {
		value |= 02000
	}
	if mode&os.ModeSticky != 0 {
		value |= 01000
	}
	return value
}
func workspaceMode(value uint32) os.FileMode {
	mode := os.FileMode(value & 0777)
	if value&04000 != 0 {
		mode |= os.ModeSetuid
	}
	if value&02000 != 0 {
		mode |= os.ModeSetgid
	}
	if value&01000 != 0 {
		mode |= os.ModeSticky
	}
	return mode
}
func workspaceEntry(path string, info os.FileInfo) workspaceFSEntry {
	kind := "unknown"
	mode := info.Mode()
	switch {
	case mode.IsRegular():
		kind = "file"
	case mode.IsDir():
		kind = "directory"
	case mode&os.ModeSymlink != 0:
		kind = "symlink"
	case mode&os.ModeNamedPipe != 0:
		kind = "fifo"
	case mode&os.ModeSocket != 0:
		kind = "socket"
	case mode&os.ModeCharDevice != 0:
		kind = "char_device"
	case mode&os.ModeDevice != 0:
		kind = "block_device"
	}
	target := ""
	if mode&os.ModeSymlink != 0 {
		target, _ = os.Readlink(path)
	}
	size := info.Size()
	if size < 0 {
		size = 0
	}
	return workspaceFSEntry{Name: filepath.Base(path), Path: path, Kind: kind, IsDir: workspaceIsDirectory(path, info), Size: uint64(size), Mode: workspacePermissions(mode), Modified: info.ModTime().UnixNano(), LinkTarget: target}
}

func workspaceIsDirectory(path string, info os.FileInfo) bool {
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Stat(path)
		return err == nil && target.IsDir()
	}
	return info.IsDir()
}

// Resolve one component at a time: cleaning link/.. before following the link
// changes POSIX meaning. Like realpath(strict=False), missing suffixes are valid.
func workspaceRealpath(path string) (string, error) {
	pending := strings.Split(path, "/")
	current := "/"
	links := 0
	for len(pending) > 0 {
		component := pending[0]
		pending = pending[1:]
		if component == "" || component == "." {
			continue
		}
		if component == ".." {
			current = filepath.Dir(current)
			continue
		}
		candidate := filepath.Join(current, component)
		info, err := os.Lstat(candidate)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
				current = candidate
				continue
			}
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			links++
			if links > 40 {
				return "", syscall.ELOOP
			}
			target, err := os.Readlink(candidate)
			if err != nil {
				return "", err
			}
			if filepath.IsAbs(target) {
				current = "/"
			}
			pending = append(strings.Split(target, "/"), pending...)
		} else {
			current = candidate
		}
	}
	return current, nil
}

func workspaceFilesystem(request workspaceFSRequest) workspaceFSReply {
	if request.Mode > 07777 || len(request.Data) > workspaceFileLimit {
		return workspaceFSError(syscall.EFBIG)
	}
	path, err := workspacePath(request.Path)
	if err != nil {
		return workspaceFSError(err)
	}
	followFinal := request.Op != "lstat" && request.Op != "readlink" && request.Op != "remove" && request.Op != "rename" && request.Op != "symlink"
	if err = workspaceRejectVirtual(path, followFinal); err != nil {
		return workspaceFSError(err)
	}
	var target string
	if request.Op == "rename" {
		target, err = workspacePath(request.Target)
		if err == nil {
			err = workspaceRejectVirtual(target, false)
		}
		if err != nil {
			return workspaceFSError(err)
		}
	}
	reply := workspaceFSReply{Path: path}
	switch request.Op {
	case "stat", "lstat":
		var info os.FileInfo
		if request.Op == "stat" {
			info, err = os.Stat(path)
		} else {
			info, err = os.Lstat(path)
		}
		if err == nil {
			reply.Entries = []workspaceFSEntry{workspaceEntry(path, info)}
		}
	case "list":
		var directory *os.File
		var fd int
		fd, err = workspaceOpen(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
		if err == nil {
			directory = os.NewFile(uintptr(fd), path)
		}
		if err == nil {
			var entries []os.DirEntry
			entries, err = directory.ReadDir(workspaceEntriesLimit + 1)
			directory.Close()
			if errors.Is(err, io.EOF) {
				err = nil
			}
			if err == nil && len(entries) > workspaceEntriesLimit {
				err = syscall.EFBIG
			}
			if err == nil {
				for _, entry := range entries {
					var info os.FileInfo
					info, err = entry.Info()
					if err != nil {
						break
					}
					reply.Entries = append(reply.Entries, workspaceEntry(strings.TrimRight(path, "/")+"/"+entry.Name(), info))
				}
			}
		}
	case "read":
		var fd int
		fd, err = workspaceOpen(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err == nil {
			file := os.NewFile(uintptr(fd), path)
			var info os.FileInfo
			info, err = file.Stat()
			if err == nil && info.IsDir() {
				err = syscall.EISDIR
			}
			if err == nil && !info.Mode().IsRegular() {
				err = syscall.EOPNOTSUPP
			}
			if err == nil && info.Size() > workspaceFileLimit {
				err = syscall.EFBIG
			}
			if err == nil {
				reply.Data, err = io.ReadAll(io.LimitReader(file, workspaceFileLimit+1))
				if len(reply.Data) > workspaceFileLimit {
					err = syscall.EFBIG
				}
			}
			file.Close()
		}
	case "write":
		if request.Parents {
			err = os.MkdirAll(filepath.Dir(path), 0700)
		}
		if err == nil {
			var fd int
			mode := request.Mode
			if mode == 0 {
				mode = 0600
			}
			fd, err = workspaceOpen(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_NONBLOCK|syscall.O_CLOEXEC, uint32(mode&0777))
			if err == nil {
				file := os.NewFile(uintptr(fd), path)
				var info os.FileInfo
				info, err = file.Stat()
				if err == nil && info.IsDir() {
					err = syscall.EISDIR
				}
				if err == nil && !info.Mode().IsRegular() {
					err = syscall.EOPNOTSUPP
				}
				if err == nil {
					err = file.Truncate(0)
				}
				if err == nil {
					_, err = file.Write(request.Data)
				}
				file.Close()
			}
		}
	case "mkdir":
		mode := request.Mode
		if mode == 0 {
			mode = 0700
		}
		if info, e := os.Stat(path); e == nil && !info.IsDir() {
			err = syscall.EEXIST
		} else if request.Parents {
			err = os.MkdirAll(path, workspaceMode(mode))
		} else {
			err = os.Mkdir(path, workspaceMode(mode))
		}
	case "remove":
		var info os.FileInfo
		info, err = os.Lstat(path)
		if err == nil && info.Mode()&os.ModeSymlink == 0 {
			var resolved string
			resolved, err = workspaceRealpath(path)
			if err == nil && (resolved == "/" || resolved == "/workspace") {
				err = syscall.EACCES
			}
		}
		if err == nil {
			if request.Recursive {
				err = os.RemoveAll(path)
			} else {
				err = os.Remove(path)
			}
		}
	case "rename":
		err = os.Rename(path, target)
	case "chmod":
		err = os.Chmod(path, workspaceMode(request.Mode))
	case "symlink":
		if request.Target == "" || len(request.Target) > 4096 || strings.IndexByte(request.Target, 0) >= 0 {
			err = syscall.EINVAL
		} else {
			err = os.Symlink(request.Target, path)
		}
	case "readlink":
		reply.LinkTarget, err = os.Readlink(path)
	case "realpath":
		reply.Path, err = workspaceRealpath(path)
	default:
		err = syscall.EINVAL
	}
	if err != nil {
		return workspaceFSError(err)
	}
	return reply
}
