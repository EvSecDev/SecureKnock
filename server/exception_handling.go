// secureknockd
package main

import (
	"fmt"
	"os"
	"time"
)

// Send message to log file and stdout
// No formatting is done to the stdout message (except newline)
func log(message string) {
	// Send to file (if log was specified in config)
	if logFilePath != "" {
		err := logToFile(message)
		logError("failed to create log entry", err, true, false)
	}

	// Print
	fmt.Printf("%s\n", message)
}

// Log to requested location and exit if requested
// Formats stdout messages like:
// If exiting: "Error: errorDescription: errorMessage\n"
// If not exit: "Warning: errorDescription: errorMessage\n\n"
func logError(errorDescription string, errorMessage error, exitRequested bool, logRequested bool) {
	// return early if no error to process
	if errorMessage == nil {
		return
	}

	// Combine description with error
	message := fmt.Sprintf("%s: %v", errorDescription, errorMessage)

	// Send to syslog if requested and log file was specified in config
	if logFilePath != "" && logRequested {
		err := logToFile(message)
		if err != nil {
			message = err.Error()
		}
	}

	// Exit if requested, otherwise print as warning
	if exitRequested {
		fmt.Printf("Error: %s\n", message)
		os.Exit(1)
	} else {
		fmt.Printf("Warning: %s\n", message)
	}
}

// Creates a log message in config specified log file with entries like /var/log/syslog
// Example: "2006-01-02T15:04:05.000000-1:00 Hostname SecureKnockd[4252]: message\n"
func logToFile(message string) (err error) {
	// Get the current time
	currentTime := time.Now()

	// Convert the offset from seconds to hours and minutes
	_, offset := currentTime.Zone()
	hours := offset / 3600
	minutes := (offset % 3600) / 60

	// Details for log entry
	time := currentTime.Format("2006-01-02T15:04:05.000000")
	timestamp := time + fmt.Sprintf("%+03d:%02d", hours, minutes)
	pid := os.Getpid()
	hostname, _ := os.Hostname()
	if hostname != "" {
		// If hostname was retrieved, add space at start to separate the string from timestamp
		hostname = " " + hostname
	}

	// Format the log message with timestamp (no space between timestamp and hostname on purpose)
	logEntry := fmt.Sprintf("%s%s %s[%d]: %s\n", timestamp, hostname, logProgramName, pid, message)

	// Open the log file in append mode, create if it doesn't exist
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		err = fmt.Errorf("could not open log file: %w", err)
		return
	}
	defer logFile.Close()

	// Write the log message to file
	_, err = logFile.WriteString(logEntry)
	if err != nil {
		err = fmt.Errorf("could not write to log file: %w", err)
		return
	}
	return
}
