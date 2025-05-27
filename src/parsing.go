// secureknockd
package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
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
	input, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		err = fmt.Errorf("failed reading password: %v", err)
		return
	}

	log(verbosityTrace, "    Received stdin: %x\n", input)

	// Convert to string
	sudoPassword := string(input)

	log(verbosityTrace, "    Received stdin string for password: %s\n", sudoPassword)

	// Reject invalid password characters
	if !isPrintableASCII(sudoPassword) {
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

	log(verbosityDebug, "    Payload to be sent: %s\n", payloadClearText)

	return
}

// Decrypts packet data payload and extracts ASCII text from it
// separates action name from password
// checks action name against config to ensure validity
func parsePayload(decryptedPayload []byte, actions []map[string][]string) (actionName string, commands []string, sudoPassword string, err error) {
	// Recover from panic
	defer func() {
		if r := recover(); r != nil {
			logError("panic while parsing packet payload", fmt.Errorf("%v", r), false, true)
		}
	}()

	payload := string(decryptedPayload)
	if !isPrintableASCII(payload) {
		err = fmt.Errorf("packet payload string is not ASCII")
		return
	}

	// For use with sudo, attempt to extract the password (if no password, whole string will remain)
	sepIndex := strings.Index(payload, payloadSeparator)
	if sepIndex != -1 {
		// Get the password after the first occurence of separator
		sudoPassword = payload[sepIndex+len(payloadSeparator):]

		log(verbosityDebug, "  Received sudo password '%s' from client\n", sudoPassword)

		// Set action name
		payload = payload[:sepIndex]
	}

	// Ensure received payload text is an authorized action name
	var payloadAuthorized bool
	for _, action := range actions {
		log(verbosityDebug, "  Validating action '%s' received from client\n", action)

		// Check map key against payload text
		_, validAction := action[payload]
		if validAction {
			// Add map command array to return value
			commands = action[payload]
			actionName = payload
			payloadAuthorized = true
			break
		}
	}

	// Unauthorized payload
	if !payloadAuthorized {
		err = fmt.Errorf("packet payload does not match an authorized action")
		return
	}

	return
}
