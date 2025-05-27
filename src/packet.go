// secureknock
package main

import (
	"crypto/cipher"
	"fmt"
	"net"
)

// Encrypts action name and optional password
// Sends UDP packet to chosen server
func sendPacket(payloadClearText string, AEAD cipher.AEAD, TOTPSecret []byte, sourceSocket net.Addr, destinationSocket net.Addr, l4Protocol string) (err error) {
	log(verbosityProgress, "Opening local socket\n")

	// Create a Dialer with the local address
	dialer := net.Dialer{
		LocalAddr: sourceSocket,
	}

	log(verbosityProgress, "Opening remote socket\n")

	// Open socket to remote
	socket, err := dialer.Dial(l4Protocol, destinationSocket.String())
	if err != nil {
		err = fmt.Errorf("failed to open local socket: %v", err)
		return
	}
	defer socket.Close()

	// Encrypt the message with time-based IV
	log(verbosityProgress, "Waiting for preferred time window to send packet...\n")
	WaitForTimeWindow()
	log(verbosityProgress, "Encrypting payload...\n")
	sessionIV := MutateIVwithTime(TOTPSecret)
	CipherText := AEAD.Seal(nil, sessionIV, []byte(payloadClearText), nil)

	// Send the message to the remote host
	log(verbosityProgress, "Sending knock packet\n")
	_, err = socket.Write(CipherText)
	if err != nil {
		err = fmt.Errorf("failed to write to socket: %v", err)
		return
	}

	// Show progress to user
	log(verbosityStandard, "Sent knock from %s to %s\n", sourceSocket.String(), destinationSocket)
	return
}
