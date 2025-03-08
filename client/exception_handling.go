// secureknock
package main

import (
	"fmt"
	"os"
)

// Send message to log file and stdout
// No formatting is done to the stdout message
// Message will only print/log if the global verbosity level is equal to or smaller than requiredVerbosityLevel
// Can directly take variables as values to print just like fmt.Printf
func log(requiredVerbosityLevel int, message string, vars ...interface{}) {
	// No output for verbosity level 0
	if globalVerbosityLevel == 0 {
		return
	}

	// Required message verbosity level is equal to or less than global verbosity level
	if requiredVerbosityLevel <= globalVerbosityLevel {
		fmt.Printf(message, vars...)
	}
}

// Will return immediately if errorMessage is nil
// Formats received description and error
// Prints as "[-] Error: errorDescription: errorMessage\n"
// Exits with exit code 1
func logError(errorDescription string, errorMessage error) {
	// return early if no error to process
	if errorMessage == nil {
		return
	}

	// Combine description with error and print
	fmt.Printf("[-] Error: %s: %v\n", errorDescription, errorMessage)
	os.Exit(1)
}
