// secureknock
package main

import (
	"fmt"
	"os"
)

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
