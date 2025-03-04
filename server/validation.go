// secureknockd
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/google/gopacket"
	"github.com/syndtr/gocapability/capability"
)

// Ensures program when not running as root has cap_net_raw capability
// Also sets global sudoRequired for bailing early in packet parsing
func checkCapabilities() (err error) {
	// Only continue if not root
	if os.Geteuid() == 0 {
		log(VerbosityProgress, "  Not root, cannot check capabilities\n")
		return
	}

	log(VerbosityProgress, "  Retrieving capabilities\n")

	// Get current capabilities
	caps, err := capability.NewPid2(0)
	if err != nil {
		err = fmt.Errorf("failed to retrieve process capabilities: %v", err)
		return
	}

	log(VerbosityProgress, "  Checking for 'CAP_NET_RAW' capability\n")

	// Check if program has packet capture capability
	HasCapNetRaw := caps.Get(capability.PERMITTED, capability.CAP_NET_RAW)

	// Exit if not
	if !HasCapNetRaw {
		err = fmt.Errorf("executable file needs cap_net_raw when running as non-root user")
		return
	}

	log(VerbosityProgress, "  Not running as root, but 'CAP_NET_RAW' is present, clients need to use Sudo password\n")

	// Set global for awareness that program needs a sudo password to perform actions
	sudoRequired = true

	return
}

// Ensure config is not missing required fields
func checkConfigForEmpty(config *Config) (err error) {
	if config.CaptureFilter.CaptureInterface == "" {
		err = fmt.Errorf("CaptureInterface")
	} else if config.EncryptionKey == "" {
		err = fmt.Errorf("EncryptionKey")
	} else if config.CaptureFilter.IncludeFilter == "" {
		err = fmt.Errorf("IncludeFilter")
	}
	return
}

// Goes through config action commands array to ensure the commands are present in PATH
// Also validates that they don't have the payload separator character in them
func validateActionCommands(actions []map[string][]string) (err error) {
	for _, action := range actions {
		for name, commands := range action {
			log(VerbosityFullData, "  Validating action '%s'\n", name)

			// Disallow action names using reserved separator character
			if strings.Contains(name, payloadSeparator) {
				err = fmt.Errorf("cannot use '%s' character in action name, it is reserved", payloadSeparator)
				return
			}

			for _, command := range commands {
				log(VerbosityFullData, "    Validating command: '%s'\n", commands)

				// Split on space to get binary name
				exeAndArgs := strings.Split(command, " ")

				// Ensure fields exist
				if len(exeAndArgs) < 1 {
					err = fmt.Errorf("invalid command under in '%v'", action)
					return
				}

				// Ensure binary name is in path
				_, err = exec.LookPath(exeAndArgs[0])
				if err != nil {
					err = fmt.Errorf("%s", exeAndArgs[0])
					return
				}
			}
		}
	}

	return
}

// Quick checks to confirm data payload from packet is roughly valid
// checks for empty payload, and size is within expected bounds
func validatePacket(packet gopacket.Packet) (payload []byte, err error) {
	// Recover from panic
	defer func() {
		if r := recover(); r != nil {
			logError("panic while validating received packet", fmt.Errorf("%v", r), true, true)
		}
	}()

	// Get only transport layer payload of received packet
	packeyTransportLayer := packet.TransportLayer()

	// Skip if empty payload
	if packeyTransportLayer == nil {
		err = fmt.Errorf("packet contains no payload")
		return
	}

	// Get bytes of payload
	payload = packeyTransportLayer.LayerPayload()

	// Validate length to within bounds for smallest messages or largest
	if len(payload) < minPayloadLengthB {
		err = fmt.Errorf("packet too small (less than %d bytes)", minPayloadLengthB)
		return
	}
	if len(payload) > maxPayloadLengthB {
		err = fmt.Errorf("packet too large (over %d bytes)", maxPayloadLengthB)
		return
	}

	// Packet is valid
	return
}
