// secureknockd
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/syndtr/gocapability/capability"
)

// Ensures program when not running as root has cap_net_raw capability
// Also sets global sudoRequired for bailing early in packet parsing
func checkCapabilities() (err error) {
	log(verbosityProgress, " Checking executable capabilities\n")

	if os.Geteuid() == 0 {
		log(verbosityProgress, "  Running as root, no need to check capabilities\n")
		return
	}

	log(verbosityProgress, "  Retrieving capabilities\n")

	// Get current capabilities
	caps, err := capability.NewPid2(0)
	if err != nil {
		err = fmt.Errorf("failed to retrieve process capabilities: %v", err)
		return
	}
	err = caps.Load()
	if err != nil {
		err = fmt.Errorf("failed to load process capabilities: %v", err)
		return
	}

	log(verbosityProgress, "  Checking for 'CAP_NET_RAW' capability\n")

	// Check if program has packet capture capability
	HasCapNetRaw := caps.Get(capability.PERMITTED, capability.CAP_NET_RAW)
	if !HasCapNetRaw {
		err = fmt.Errorf("executable file needs cap_net_raw when running as non-root user")
		return
	}

	log(verbosityProgress, "  Not running as root, but 'CAP_NET_RAW' is present, clients need to use Sudo password\n")

	// Set global for awareness that program needs a sudo password to perform actions
	sudoRequired = true

	return
}

func setCapabilities() (err error) {
	log(verbosityProgress, " Setting 'cap_net_raw' executable capabilities\n")

	exeAbsPath, err := exec.LookPath(filepath.Base(os.Args[0]))
	if err != nil {
		err = fmt.Errorf("failed to find absolute path of executable: %v", err)
		return
	}

	cmd := exec.Command("setcap", "cap_net_raw=ep", exeAbsPath)
	err = cmd.Run()
	if err != nil {
		err = fmt.Errorf("failed to set capabilities on executable file (%s): %v", cmd.String(), err)
		return
	}

	log(verbosityProgress, " Successfully set 'cap_net_raw=ep' executable capability\n")
	return
}
