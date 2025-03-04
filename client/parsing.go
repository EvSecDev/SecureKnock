// secureknock
package main

import (
	"fmt"
	"os"

	"golang.org/x/crypto/ssh/terminal"
)

// If using a password, this asks the user for the password (using the terminal package)
// Validates the password is ASCII and and is below max payload size
// Creates plain text payload consisting of action name and password
func createPayloadText(actionName string, usePassword bool) (payloadClearText string, err error) {
	// If not  using password, set payload and return early
	if !usePassword {
		payloadClearText = actionName
		return
	}

	// Ask for password
	fmt.Print("Password: ")
	input, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		err = fmt.Errorf("failed reading password: %v", err)
		return
	}

	// Convert to string
	sudoPassword := string(input)

	// Reject invalid password characters
	if !ASCIIRegEx.MatchString(sudoPassword) {
		err = fmt.Errorf("password must be ASCII text only")
		return
	}

	// Reject invalid password length
	if len(sudoPassword) >= maxPayloadTextSize {
		err = fmt.Errorf("password must be less than or equal to %d bytes/characters", maxPayloadTextSize)
		return
	}

	// Create payload from action name and password
	payloadClearText = actionName + payloadSeparator + sudoPassword

	return
}
