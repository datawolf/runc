// +build linux

package main

import (
	"os"
	"runtime"

	"github.com/Sirupsen/logrus"
	"github.com/opencontainers/runc/libcontainer"
	_ "github.com/opencontainers/runc/libcontainer/nsenter"
	"github.com/urfave/cli"
)

func init() {
	logrus.Info("Enter main_unix.go init, 如果参数为init，则设置go的运行环境，否则，直接退出init")
	if len(os.Args) > 1 && os.Args[1] == "init" {
		logrus.Info("设置 rumtime gomaxprocs and lockosthread")
		runtime.GOMAXPROCS(1)
		runtime.LockOSThread()
	} else {
		logrus.Info("os.Args[1] != init, 直接退出")
	}
}

var initCommand = cli.Command{
	Name:  "init",
	Usage: `initialize the namespaces and launch the process (do not call it outside of runc)`,
	Action: func(context *cli.Context) error {
		logrus.Info("###### 别把这货给忘记了 ########")
		factory, _ := libcontainer.New("")
		if err := factory.StartInitialization(); err != nil {
			// as the error is sent back to the parent there is no need to log
			// or write it to stderr because the parent process will handle this
			os.Exit(1)
		}
		panic("libcontainer: container init failed to exec")
	},
}
