// +build linux

package libcontainer

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/opencontainers/runc/libcontainer/apparmor"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/keys"
	"github.com/opencontainers/runc/libcontainer/label"
	"github.com/opencontainers/runc/libcontainer/seccomp"
	"github.com/opencontainers/runc/libcontainer/system"
)

type linuxStandardInit struct {
	pipe       *os.File
	parentPid  int
	stateDirFD int
	config     *initConfig
}

func (l *linuxStandardInit) getSessionRingParams() (string, uint32, uint32) {
	var newperms uint32

	if l.config.Config.Namespaces.Contains(configs.NEWUSER) {
		// with user ns we need 'other' search permissions
		newperms = 0x8
	} else {
		// without user ns we need 'UID' search permissions
		newperms = 0x80000
	}

	// create a unique per session container name that we can
	// join in setns; however, other containers can also join it
	return fmt.Sprintf("_ses.%s", l.config.ContainerId), 0xffffffff, newperms
}

// PR_SET_NO_NEW_PRIVS isn't exposed in Golang so we define it ourselves copying the value
// the kernel
const PR_SET_NO_NEW_PRIVS = 0x26

func (l *linuxStandardInit) Init() error {
	fmt.Println("[linuxStandardInit] init")
	if !l.config.Config.NoNewKeyring {
		fmt.Println("[linuxStandardInit] setting keyring")
		ringname, keepperms, newperms := l.getSessionRingParams()

		fmt.Printf("[linuxStandardInit] NoNewKeyring = %v, ringname = %v\n", l.config.Config.NoNewKeyring, ringname)
		// do not inherit the parent's session keyring
		sessKeyId, err := keys.JoinSessionKeyring(ringname)
		if err != nil {
			return err
		}
		fmt.Printf("[linuxStandardInit] keepperms = %x, newperms= %x\n", keepperms, newperms)
		// make session keyring searcheable
		if err := keys.ModKeyringPerm(sessKeyId, keepperms, newperms); err != nil {
			return err
		}
	}

	fmt.Println("[linuxStandardInit] 准备设置网络 set network")
	if err := setupNetwork(l.config); err != nil {
		return err
	}
	fmt.Println("[linuxStandardInit] 准备设置路由 set route")
	if err := setupRoute(l.config.Config); err != nil {
		return err
	}

	fmt.Println("[linuxStandardInit] label.Init")
	label.Init()

	fmt.Println("[linuxStandardInit] 设置文件系统  prepare rootfs")
	// prepareRootfs() can be executed only for a new mount namespace.
	if l.config.Config.Namespaces.Contains(configs.NEWNS) {
		if err := prepareRootfs(l.pipe, l.config.Config); err != nil {
			return err
		}
	}

	fmt.Printf("[linuxStandardInit] config= %v\n", l.config)
	// Set up the console. This has to be done *before* we finalize the rootfs,
	// but *after* we've given the user the chance to set up all of the mounts
	// they wanted.
	if l.config.CreateConsole {
		fmt.Printf("[linuxStandardInit] set console from path, console = %v\n", l.config.CreateConsole)
		if err := setupConsole(l.pipe, l.config, true); err != nil {
			return err
		}
		// Make the given terminal the controlling terminal of the calling process.
		if err := system.Setctty(); err != nil {
			return err
		}
	}

	fmt.Println("[linuxStandardInit] 设置文件系统  finalize rootfs")
	// Finish the rootfs setup.
	if l.config.Config.Namespaces.Contains(configs.NEWNS) {
		if err := finalizeRootfs(l.config.Config); err != nil {
			return err
		}
	}

	fmt.Printf("[linuxStandardInit] set hostname to \"%s\"\n", l.config.Config.Hostname)
	if hostname := l.config.Config.Hostname; hostname != "" {
		if err := syscall.Sethostname([]byte(hostname)); err != nil {
			return err
		}
	}
	fmt.Println("[linuxStandardInit] apply apparmor profile")
	if err := apparmor.ApplyProfile(l.config.AppArmorProfile); err != nil {
		return err
	}
	fmt.Println("[linuxStandardInit] set process label")
	if err := label.SetProcessLabel(l.config.ProcessLabel); err != nil {
		return err
	}

	fmt.Println("[linuxStandardInit] write system ctl property")
	for key, value := range l.config.Config.Sysctl {
		if err := writeSystemProperty(key, value); err != nil {
			return err
		}
	}
	fmt.Println("[linuxStandardInit] remountReadonly")
	for _, path := range l.config.Config.ReadonlyPaths {
		if err := readonlyPath(path); err != nil {
			return err
		}
	}
	fmt.Println("[linuxStandardInit] makeFile")
	for _, path := range l.config.Config.MaskPaths {
		if err := maskPath(path); err != nil {
			return err
		}
	}
	// 为了后面恢复它
	fmt.Println("[linuxStandardInit] GetParentDeathSignal 获取父进程退出时，调用进程应该收到的信号")
	pdeath, err := system.GetParentDeathSignal()
	if err != nil {
		return err
	}
	fmt.Println("[linuxStandardInit] prctl ")
	if l.config.NoNewPrivileges {
		if err := system.Prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return err
		}
	}
	// Tell our parent that we're ready to Execv. This must be done before the
	// Seccomp rules have been applied, because we need to be able to read and
	// write to a socket.
	fmt.Println("[linuxStandardInit] tell our parent that we arereday to execv")
	fmt.Println("[linuxStandardInit] 此时此刻，父进程才能够设置子进程的cgroup信息")
	if err := syncParentReady(l.pipe); err != nil {
		return err
	}
	// Without NoNewPrivileges seccomp is a privileged operation, so we need to
	// do this before dropping capabilities; otherwise do it as late as possible
	// just before execve so as few syscalls take place after it as possible.
	fmt.Println("[linuxStandardInit] InitSeccomp")
	if l.config.Config.Seccomp != nil && !l.config.NoNewPrivileges {
		if err := seccomp.InitSeccomp(l.config.Config.Seccomp); err != nil {
			return err
		}
	}
	fmt.Println("[linuxStandardInit] finalizeNamespace")
	if err := finalizeNamespace(l.config); err != nil {
		return err
	}
	// finalizeNamespace can change user/group which clears the parent death
	// signal, so we restore it here.
	// finalizeNamespace 可能会清空 parent death 信号，在这里恢复它
	fmt.Println("[linuxStandardInit] pdeath.Restore ")
	if err := pdeath.Restore(); err != nil {
		return err
	}
	// compare the parent from the initial start of the init process and make sure that it did not change.
	// if the parent changes that means it died and we were reparented to something else so we should
	// just kill ourself and not cause problems for someone else.
	if syscall.Getppid() != l.parentPid {
		return syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
	}
	// check for the arg before waiting to make sure it exists and it is returned
	// as a create time error.
	name, err := exec.LookPath(l.config.Args[0])
	if err != nil {
		return err
	}
	// close the pipe to signal that we have completed our init.
	fmt.Println("[linuxStandardInit] close the pipe, 这样父进程就可以退出循环了")
	l.pipe.Close()
	// wait for the fifo to be opened on the other side before
	// exec'ing the users process.
	fmt.Printf("[linuxStandardInit] openat exec fifo l.stateDirFD = %d, execFifoFilename = %s\n", l.stateDirFD, execFifoFilename)
	fd, err := syscall.Openat(l.stateDirFD, execFifoFilename, os.O_WRONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return newSystemErrorWithCause(err, "openat exec fifo")
	}
	fmt.Println("[linuxStandardInit] wirte 0 exec info")
	if _, err := syscall.Write(fd, []byte("0")); err != nil {
		return newSystemErrorWithCause(err, "write 0 exec fifo")
	}
	fmt.Println("[linuxStandardInit] init seccomp ")
	if l.config.Config.Seccomp != nil && l.config.NoNewPrivileges {
		if err := seccomp.InitSeccomp(l.config.Config.Seccomp); err != nil {
			return newSystemErrorWithCause(err, "init seccomp")
		}
	}
	// close the statedir fd before exec because the kernel resets dumpable in the wrong order
	// https://github.com/torvalds/linux/blob/v4.9/fs/exec.c#L1290-L1318
	syscall.Close(l.stateDirFD)
	fmt.Println("[linuxStandardInit] exec user process ")
	if err := syscall.Exec(name, l.config.Args[0:], os.Environ()); err != nil {
		return newSystemErrorWithCause(err, "exec user process")
	}
	return nil
}
