// secureknockd
package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"os/exec"
	"strings"

	"github.com/google/gopacket"
)

// Ensure config is not missing required fields
func checkConfigForEmpty(config *Config) (err error) {
	log(verbosityProgress, "Looking for empty config fields that are required\n")

	if config.CaptureFilter.CaptureInterface == "" {
		err = fmt.Errorf("CaptureInterface")
	} else if config.EncryptionKey == "" {
		err = fmt.Errorf("EncryptionKey")
	} else if config.CaptureFilter.IncludeFilter == "" {
		err = fmt.Errorf("IncludeFilter")
	}
	return
}

// Resolves domain names, ensures IP is a valid address
// Joins IP and port, and creates a socket for use with net Dial
// Does not check if port is destination or source, if destination is empty, it will generate a random destination port
func validateIPandPort(address string, port int, isSource bool) (socket net.Addr, l4Protocol string, err error) {
	// Catch empty destination port
	if port == 0 && !isSource {
		err = fmt.Errorf("must specify a destination port")
		return
	}

	// Generate random port if port is nil (0)
	// Should only happen for source ports - function is guarded against random destination ports outside function
	if port == 0 {
		log(verbosityProgress, "Generating random port\n")

		// Define port range
		min := int64(1024)
		max := int64(65535)

		// Calculate number of ports in range
		rangeSize := max - min + 1

		// Get random port
		var randomNumber *big.Int
		randomNumber, err = rand.Int(rand.Reader, big.NewInt(rangeSize))
		if err != nil {
			err = fmt.Errorf("failed to generate random port number: %v", err)
			return
		}

		// Adjust random into range
		randomNumber = randomNumber.Add(randomNumber, big.NewInt(min))

		// Save over existing source port
		port = int(randomNumber.Int64())
	}

	// Reject empty IP and port
	if address == "" && !isSource {
		err = fmt.Errorf("must specify address")
		return
	}

	// Set any source if not specified
	if address == "" && isSource {
		log(verbosityProgress, "Using automatic source IP address\n")
		address = "::"
	}

	// Resolve domain name if present, otherwise validate ip
	IP := net.ParseIP(address)
	if IP == nil {
		// If domain name, resolve to an IP
		var IPs []net.IP
		IPs, err = net.LookupIP(address)
		if err != nil {
			err = fmt.Errorf("failed to resolve address: %v", err)
			return
		}
		if len(IPs) == 0 {
			err = fmt.Errorf("no IPs found for address %s", address)
			return
		}
		IP = IPs[0] // Use first resolved IP address
	}

	// Reject invalid port
	if port < 1 || port > 65535 {
		err = fmt.Errorf("port must be 1-65535")
		return
	}

	log(verbosityProgress, "Using port %d\n", port)

	// Create destination socket
	IPPort := net.JoinHostPort(IP.String(), fmt.Sprintf("%d", port))

	// Create source and destination socket for connection
	l4Protocol = "udp"
	socket, err = net.ResolveUDPAddr(l4Protocol, IPPort)
	if err != nil {
		err = fmt.Errorf("failed to resolve address: %v", err)
		return
	}

	// Show user what whole socket we will be using after resolution
	if isSource {
		log(verbosityProgress, "Using source socket %s\n", socket.String())
	} else if !isSource {
		log(verbosityProgress, "Using destination socket %s\n", socket.String())
	}

	return
}

// Goes through config action commands array to ensure the commands are present in PATH
// Also validates that they don't have the payload separator character in them
func validateActionCommands(actions []map[string][]string) (err error) {
	log(verbosityProgress, "Validating supplied action commands are in programs PATH\n")

	for _, action := range actions {
		for name, commands := range action {
			log(verbosityFullData, "  Validating action '%s'\n", name)

			// Disallow action names using reserved separator character
			if strings.Contains(name, payloadSeparator) {
				err = fmt.Errorf("cannot use '%s' character in action name, it is reserved", payloadSeparator)
				return
			}

			for _, command := range commands {
				log(verbosityFullData, "    Validating command: '%s'\n", commands)

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

// Ensures
//   - supplied action name is ASCII
//   - does not contain the payload separator character
//   - does not exceed the maximum allow size to fit in the packet payload
func validateActionName(actionName string) (err error) {
	if len(actionName) == 0 {
		err = fmt.Errorf("must not be null")
		return
	}

	if !isPrintableASCII(actionName) {
		err = fmt.Errorf("must be ASCII text only")
		return
	}

	// Reject reserved characters in action name
	if strings.Contains(actionName, payloadSeparator) {
		err = fmt.Errorf("must not contain character '%s'", payloadSeparator)
		return
	}

	if len(actionName) >= maxPayloadTextSize {
		err = fmt.Errorf("must be less than or equal to %d bytes/characters", maxPayloadTextSize)
		return
	}

	log(verbosityProgress, "Using action name %s\n", actionName)

	// Valid
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

func isPrintableASCII(input string) bool {
	for i := range len(input) {
		if input[i] > 127 {
			return false
		}
	}
	return true
}
