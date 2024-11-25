// secureknockd
package main

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// Runs commands from config action array based on received packet action name
func runCommands(actionName string, commands []string, sudoPassword string) (err error) {
	// Recover from panic
	defer func() {
		if r := recover(); r != nil {
			logError(fmt.Sprintf("panic while running action commands"), fmt.Errorf("%v", r), false, true)
		}
	}()

	// Bail if client didn't give a password and program isn't root
	if sudoPassword == "" && sudoRequired {
		err = fmt.Errorf("program not running as root and client did not supply sudo password, unable to run commands")
		return
	}

	// Run authorized commands
	for _, command := range commands {
		// If there is a password, prepend to sudo to command
		if sudoPassword != "" {
			command = "sudo -S " + command
		}

		// Separate binary from arguments
		commandArgs := strings.Fields(command)
		commandExe := commandArgs[0]

		// Prepare command struct
		cmd := exec.Command(commandExe, commandArgs[1:]...)

		// Prepare stdin for sudo password (might be empty)
		var stdin io.WriteCloser
		stdin, err = cmd.StdinPipe()
		if err != nil {
			err = fmt.Errorf("failed to create stdin writer: %v", err)
			return
		}

		// Run the command
		err = cmd.Start()
		if err != nil {
			err = fmt.Errorf("failed to start command: %v", err)
			return
		}

		// Write the password to standard (might be empty)
		_, err = stdin.Write([]byte(sudoPassword))
		if err != nil {
			err = fmt.Errorf("failed to write stdin to command: %v", err)
			return
		}

		// Close stdin to signal command we are done writing
		err = stdin.Close()
		if err != nil {
			err = fmt.Errorf("failed to close stdin: %v", err)
			return
		}

		// Wait for command to complete
		err = cmd.Wait()
		if err != nil {
			fmt.Errorf("command failed: %v", err)
			return
		}
	}

	return
}
