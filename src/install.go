// secureknockd
package main

import (
	"bufio"
	"fmt"
	"os"

	"golang.org/x/term"
)

func installServerComponents() (err error) {
	if os.Geteuid() != 0 {
		err = fmt.Errorf("installation must be run as root")
		return
	}

	interactiveTerminal := term.IsTerminal(int(os.Stdout.Fd()))

	if interactiveTerminal {
		fmt.Print("Press Enter to start installation ")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	}

	// Default Installation Params
	const defaultExePath string = "/usr/local/bin/secureknockd"
	const defaultConfPath string = "/etc/secureknockd.json"
	const defaultServiceName string = "secureknockd.service"
	const defaultServicePath string = "/etc/systemd/system/" + defaultServiceName
	const defaultAAProfDir string = "/etc/apparmor.d/"
	const defaultLogName string = "secureknockd.log"
	defaultRunAsUser := "skduser"
	var defaultLogPath string
	var runAsUserID int

	err = installExeFile(defaultExePath)
	if err != nil {
		err = fmt.Errorf("failed to move executable into place: %v", err)
		return
	}
	os.Args[0] = defaultExePath

	_, userRequestsRunAsRoot := os.LookupEnv("runAsRoot")
	if userRequestsRunAsRoot {
		log(verbosityProgress, "Skipping unprivileged user setup, found 'runAsRoot' env variable\n")
		defaultRunAsUser = "root"
		defaultLogPath = "/var/log/" + defaultLogName
	} else {
		runAsUserID, err = installUser(defaultRunAsUser, interactiveTerminal)
		if err != nil {
			err = fmt.Errorf("failed to install user: %v", err)
			return
		}

		defaultLogPath = "/tmp/" + defaultLogName
		_, err = os.Stat(defaultLogPath)
		if err == nil {
			err = os.Chown(defaultLogPath, runAsUserID, runAsUserID)
			if err != nil {
				err = fmt.Errorf("failed to change ownership of log file to run as user: %v", err)
				return
			}
		}
		err = nil

		err = setCapabilities()
		if err != nil {
			err = fmt.Errorf("failed to set cap_net_raw on executable file: %v", err)
			return
		}
	}

	err = installConfig(defaultConfPath, defaultLogPath, runAsUserID)
	if err != nil {
		err = fmt.Errorf("failed to install config: %v", err)
		return
	}

	err = installApparmorProfile(defaultAAProfDir, defaultExePath, defaultConfPath, defaultLogPath)
	if err != nil {
		err = fmt.Errorf("failed to install apparmor profile: %v", err)
		return
	}

	err = installSystemdService(defaultExePath, defaultConfPath, defaultRunAsUser, defaultServiceName, defaultServicePath)
	if err != nil {
		err = fmt.Errorf("failed to install systemd service: %v", err)
		return
	}

	log(verbosityStandard, "Installation Successful\n")
	return
}
