// secureknock
package main

import (
	"crypto/cipher"
	"fmt"
	"net"
)

// Encrypts action name and optional password
// Sends UDP packet to chosen server
func sendPacket(payloadClearText string, AESGCMCipherBlock cipher.AEAD, TOTPSecret []byte, sourceSocket net.Addr, destinationSocket net.Addr, l4Protocol string) (err error) {
	// Create a Dialer with the local address
	dialer := net.Dialer{
		LocalAddr: sourceSocket,
	}

	// Open socket to remote
	socket, err := dialer.Dial(l4Protocol, destinationSocket.String())
	if err != nil {
		err = fmt.Errorf("failed to open local socket: %v", err)
		return
	}
	defer socket.Close()

	// Encrypt the message with time-based IV
	WaitForTimeWindow()
	sessionIV := MutateIVwithTime(TOTPSecret)
	CipherText := AESGCMCipherBlock.Seal(nil, sessionIV, []byte(payloadClearText), nil)

	// Send the message to the remote host
	_, err = socket.Write(CipherText)
	if err != nil {
		err = fmt.Errorf("failed to write to socket: %v", err)
		return
	}

	// Show progress to user
	fmt.Printf("Sent knock to %s\n", destinationSocket)
	return
}
