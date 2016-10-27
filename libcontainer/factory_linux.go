// +build linux

package libcontainer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"syscall"

	"github.com/docker/docker/pkg/mount"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fs"
	"github.com/opencontainers/runc/libcontainer/cgroups/systemd"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/configs/validate"
	"github.com/opencontainers/runc/libcontainer/utils"
)

const (
	stateFilename    = "state.json"
	execFifoFilename = "exec.fifo"
)

var (
	idRegex  = regexp.MustCompile(`^[\w+-\.]+$`)
	maxIdLen = 1024
)

// InitArgs returns an options func to configure a LinuxFactory with the
// provided init binary path and arguments.
func InitArgs(args ...string) func(*LinuxFactory) error {
	return func(l *LinuxFactory) error {
		l.InitArgs = args
		return nil
	}
}

// SystemdCgroups is an options func to configure a LinuxFactory to return
// containers that use systemd to create and manage cgroups.
func SystemdCgroups(l *LinuxFactory) error {
	l.NewCgroupsManager = func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
		return &systemd.Manager{
			Cgroups: config,
			Paths:   paths,
		}
	}
	return nil
}

// Cgroupfs is an options func to configure a LinuxFactory to return
// containers that use the native cgroups filesystem implementation to
// create and manage cgroups.
func Cgroupfs(l *LinuxFactory) error {
	fmt.Println("设置 LinuxFactory 的 l.NewCgroupManager")
	l.NewCgroupsManager = func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
		fmt.Println("[Cgroupfs] create new CgroupManager")
		fmt.Printf("[Cgroupfs] $$$$ config = %v\n", config)
		fmt.Printf("[Cgroupfs] $$$$ paths = %v\n", paths)
		return &fs.Manager{
			Cgroups: config,
			Paths:   paths,
		}
	}
	return nil
}

// TmpfsRoot is an option func to mount LinuxFactory.Root to tmpfs.
func TmpfsRoot(l *LinuxFactory) error {
	mounted, err := mount.Mounted(l.Root)
	if err != nil {
		return err
	}
	if !mounted {
		if err := syscall.Mount("tmpfs", l.Root, "tmpfs", 0, ""); err != nil {
			return err
		}
	}
	return nil
}

// CriuPath returns an option func to configure a LinuxFactory with the
// provided criupath
func CriuPath(criupath string) func(*LinuxFactory) error {
	fmt.Printf("return an option func to configure LinuxFactory with the criupath = %v\n", criupath)
	return func(l *LinuxFactory) error {
		fmt.Println("设置 LinuxFactory 的 l.criuPath")
		l.CriuPath = criupath
		return nil
	}
}

// New returns a linux based container factory based in the root directory and
// configures the factory with the provided option funcs.
func New(root string, options ...func(*LinuxFactory) error) (Factory, error) {
	fmt.Printf("[libcontainer.New] create root dir = \"%s\"\n", root)
	if root != "" {
		if err := os.MkdirAll(root, 0700); err != nil {
			return nil, newGenericError(err, SystemError)
		}
	}
	fmt.Println("[libcontainer.New] default factory is \"LinuxFactory\"")
	l := &LinuxFactory{
		Root:      root,
		InitArgs:  []string{"/proc/self/exe", "init"},
		Validator: validate.New(),
		CriuPath:  "criu",
	}
	fmt.Println("[libcontainer.New] set default cgroupManager to fs")
	Cgroupfs(l)
	for _, opt := range options {
		fmt.Printf("[libcontainer.New] call option funcs = %v\n", opt)
		if err := opt(l); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// LinuxFactory implements the default factory interface for linux based systems.
type LinuxFactory struct {
	// Root directory for the factory to store state.
	Root string

	// InitArgs are arguments for calling the init responsibilities for spawning
	// a container.
	InitArgs []string

	// CriuPath is the path to the criu binary used for checkpoint and restore of
	// containers.
	CriuPath string

	// Validator provides validation to container configurations.
	Validator validate.Validator

	// NewCgroupsManager returns an initialized cgroups manager for a single container.
	NewCgroupsManager func(config *configs.Cgroup, paths map[string]string) cgroups.Manager
}

func (l *LinuxFactory) Create(id string, config *configs.Config) (Container, error) {
	if l.Root == "" {
		return nil, newGenericError(fmt.Errorf("invalid root"), ConfigInvalid)
	}
	fmt.Printf("[LinuxFactory.Create] l.Root = %v\n", l.Root)
	fmt.Printf("[LinuxFactory.Create] validate the container-id = %v\n", id)
	if err := l.validateID(id); err != nil {
		return nil, err
	}
	fmt.Printf("[LinuxFactory.Create] validate the container config = %v\n", config)
	if err := l.Validator.Validate(config); err != nil {
		return nil, newGenericError(err, ConfigInvalid)
	}
	uid, err := config.HostUID()
	if err != nil {
		return nil, newGenericError(err, SystemError)
	}
	gid, err := config.HostGID()
	if err != nil {
		return nil, newGenericError(err, SystemError)
	}
	containerRoot := filepath.Join(l.Root, id)
	if _, err := os.Stat(containerRoot); err == nil {
		return nil, newGenericError(fmt.Errorf("container with id exists: %v", id), IdInUse)
	} else if !os.IsNotExist(err) {
		return nil, newGenericError(err, SystemError)
	}
	fmt.Printf("[LinuxFactory.Create] create containerRoot = %s\n", containerRoot)
	if err := os.MkdirAll(containerRoot, 0711); err != nil {
		return nil, newGenericError(err, SystemError)
	}
	if err := os.Chown(containerRoot, uid, gid); err != nil {
		return nil, newGenericError(err, SystemError)
	}
	fifoName := filepath.Join(containerRoot, execFifoFilename)
	oldMask := syscall.Umask(0000)
	fmt.Printf("[LinuxFactory.Create] create fifoName= %s\n", fifoName)
	if err := syscall.Mkfifo(fifoName, 0622); err != nil {
		syscall.Umask(oldMask)
		return nil, newGenericError(err, SystemError)
	}
	syscall.Umask(oldMask)
	fmt.Printf("[LinuxFactory.Create] create fifo's uid(%d) and  gid (%d)\n", uid, gid)
	if err := os.Chown(fifoName, uid, gid); err != nil {
		return nil, newGenericError(err, SystemError)
	}
	c := &linuxContainer{
		id:            id,
		root:          containerRoot,
		config:        config,
		initArgs:      l.InitArgs,
		criuPath:      l.CriuPath,
		cgroupManager: l.NewCgroupsManager(config.Cgroups, nil),
	}
	c.state = &stoppedState{c: c}
	fmt.Printf("[LinuxFactory.Create] create linuxContainer = %v\n", c)
	return c, nil
}

func (l *LinuxFactory) Load(id string) (Container, error) {
	if l.Root == "" {
		return nil, newGenericError(fmt.Errorf("invalid root"), ConfigInvalid)
	}
	containerRoot := filepath.Join(l.Root, id)
	fmt.Printf("[Load] containerRoot = %v\n", containerRoot)
	state, err := l.loadState(containerRoot, id)
	if err != nil {
		return nil, err
	}
	fmt.Printf("[Load] state = %v\n", state)
	r := &nonChildProcess{
		processPid:       state.InitProcessPid,
		processStartTime: state.InitProcessStartTime,
		fds:              state.ExternalDescriptors,
	}
	c := &linuxContainer{
		initProcess:          r,
		initProcessStartTime: state.InitProcessStartTime,
		id:                   id,
		config:               &state.Config,
		initArgs:             l.InitArgs,
		criuPath:             l.CriuPath,
		cgroupManager:        l.NewCgroupsManager(state.Config.Cgroups, state.CgroupPaths),
		root:                 containerRoot,
		created:              state.Created,
	}
	c.state = &loadedState{c: c}
	if err := c.refreshState(); err != nil {
		return nil, err
	}
	fmt.Printf("[Load] linuxContainer = %v\n\n", c)
	return c, nil
}

func (l *LinuxFactory) Type() string {
	return "libcontainer"
}

// StartInitialization loads a container by opening the pipe fd from the parent to read the configuration and state
// This is a low level implementation detail of the reexec and should not be consumed externally
func (l *LinuxFactory) StartInitialization() (err error) {
	var pipefd, rootfd int
	for _, pair := range []struct {
		k string
		v *int
	}{
		{"_LIBCONTAINER_INITPIPE", &pipefd},
		{"_LIBCONTAINER_STATEDIR", &rootfd},
	} {

		s := os.Getenv(pair.k)

		i, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("unable to convert %s=%s to int", pair.k, s)
		}
		*pair.v = i
	}

	fmt.Println("[LinuxFactory.StartInitialization] 根据环境变量，获得pipe和root的文件描述符，和初始化类型")
	fmt.Printf("[LinuxFactory.StartInitialization] LIBCONTAINER_INITPIPE=%d\n", pipefd)
	fmt.Printf("[LinuxFactory.StartInitialization] LIBCONTAINER_STATEDIR=%d\n", rootfd)

	var (
		pipe = os.NewFile(uintptr(pipefd), "pipe")
		it   = initType(os.Getenv("_LIBCONTAINER_INITTYPE"))
	)
	fmt.Printf("[LinuxFactory.StartInitialization] LIBCONTAINER_INITTYPE=%v\n", os.Getenv("_LIBCONTAINER_INITTYPE"))
	// clear the current process's environment to clean any libcontainer
	// specific env vars.
	os.Clearenv()
	fmt.Println("[LinuxFactory.StartInitialization] 清空当前进程的环境变量")

	var i initer
	defer func() {
		// We have an error during the initialization of the container's init,
		// send it back to the parent process in the form of an initError.
		// If container's init successed, syscall.Exec will not return, hence
		// this defer function will never be called.
		if werr := utils.WriteJSON(pipe, syncT{procError}); werr != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if werr := utils.WriteJSON(pipe, newSystemError(err)); werr != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		// ensure that this pipe is always closed
		pipe.Close()
	}()
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("panic from initialization: %v, %v", e, string(debug.Stack()))
		}
	}()
	i, err = newContainerInit(it, pipe, rootfd)
	if err != nil {
		return err
	}
	fmt.Printf("[StartInitialization] run %v's Init\n", it)
	return i.Init()
}

func (l *LinuxFactory) loadState(root, id string) (*State, error) {
	f, err := os.Open(filepath.Join(root, stateFilename))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, newGenericError(fmt.Errorf("container %q does not exist", id), ContainerNotExists)
		}
		return nil, newGenericError(err, SystemError)
	}
	defer f.Close()
	var state *State
	if err := json.NewDecoder(f).Decode(&state); err != nil {
		return nil, newGenericError(err, SystemError)
	}
	return state, nil
}

func (l *LinuxFactory) validateID(id string) error {
	if !idRegex.MatchString(id) {
		return newGenericError(fmt.Errorf("invalid id format: %v", id), InvalidIdFormat)
	}
	if len(id) > maxIdLen {
		return newGenericError(fmt.Errorf("invalid id format: %v", id), InvalidIdFormat)
	}
	return nil
}
