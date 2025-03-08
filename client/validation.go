// secureknock
package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"
)

// Resolves domain names, ensures IP is a valid address
// Joins IP and port, and creates a socket for use with net Dial
// Does not check if port is destination or source, if destination is empty, it will generate a random destination port
func validateIPandPort(address string, port int, isSource bool) (socket net.Addr, l4Protocol string, err error) {
	// Generate random port if port is nil (0)
	// Should only happen for source ports - function is guarded against random destination ports outside function
	if port == 0 {
		log(VerbosityProgress, "Generating random port\n")

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
		log(VerbosityProgress, "Using automatic source IP address\n")
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

	log(VerbosityProgress, "Using port %d\n", port)

	// Create destination socket
	IPPort := net.JoinHostPort(IP.String(), fmt.Sprintf("%d", port))

	// Create source and destination socket for connection
	l4Protocol = "udp"
	socket, err = net.ResolveUDPAddr(l4Protocol, IPPort)
	logError("failed to create socket", err)

	return
}

// Ensures
//   - supplied action name is ASCII
//   - does not contain the payload separator character
//   - does not exceed the maximum allow size to fit in the packet payload
func validateActionName(actionName string) (err error) {
	// Reject invalid action name
	if !ASCIIRegEx.MatchString(actionName) {
		err = fmt.Errorf("must be ASCII text only")
		return
	}

	// Reject invalid characters in action name
	if strings.Contains(actionName, payloadSeparator) {
		err = fmt.Errorf("must not contain character '%s'", payloadSeparator)
		return
	}

	// Reject invalid action name length
	if len(actionName) >= maxPayloadTextSize {
		err = fmt.Errorf("must be less than or equal to %d bytes/characters", maxPayloadTextSize)
		return
	}

	// Valid
	return
}
