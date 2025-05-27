// secureknockd
package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Creates a new encryption key
// Prints key to user on success
// OR, if given a key file path
// Writes key to supplied key file path
// Prints key location to user on successful write
func generateNewKey(keyFilePath string) (err error) {
	log(verbosityProgress, "Creating a new random cryptographic key\n")
	newKey, err := createKeyHex()
	if err != nil {
		return
	}

	// Write key to file if given, otherwise print to stdout
	if keyFilePath != "" {
		// Open key file
		var keyFile *os.File
		keyFile, err = os.OpenFile(keyFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return
		}
		defer keyFile.Close()

		// Write the string content to the file
		_, err = keyFile.WriteString(newKey)
		if err != nil {
			return
		}

		// Show key location
		fmt.Printf("New encryption key written to %s\n", keyFilePath)
	} else {
		// Give to user
		fmt.Printf("New Encryption Key: %s\n", newKey)
	}

	return
}

func createKeyHex() (key string, err error) {
	// Create a byte slice of the expected length
	randomBytes := make([]byte, 32)

	// Fill the byte slice with cryptographically secure random data
	_, err = rand.Read(randomBytes)
	if err != nil {
		return
	}

	// Pretty output - hex representation consumes half the bytes
	key = hex.EncodeToString(randomBytes)
	return
}

// Reads in keyfile and extracts only hex characters from it
// Validates length is exactly 64 characters
// Separates into key and TOTP secret
// Creates the ChaCha20-Poly1305 cipher with the key
func prepareEncryption(keyAndIV string, keyFile string) (AEAD cipher.AEAD, TOTPSecret []byte, err error) {
	log(verbosityProgress, "Creating ChaCha20-Poly1305 Cipher\n")

	// Extract key from file if file path was supplied
	if keyFile != "" {
		// Grab configuration options from file
		var keyFileBytes []byte
		keyFileBytes, err = os.ReadFile(keyFile)
		if err != nil {
			err = fmt.Errorf("failed to read key file: %v", err)
			return
		}

		keyAndIV = string(keyFileBytes)
	}

	// Trim misc from key if present
	keyAndIV = strings.TrimSpace(keyAndIV)
	keyAndIV = strings.ReplaceAll(keyAndIV, "\n", "")
	keyAndIV = strings.ReplaceAll(keyAndIV, "\r", "")

	// Validate key length
	if len(keyAndIV) != 64 {
		err = fmt.Errorf("invalid encryption key: must be 64 hexadecimal characters")
		return
	}

	// Validate key characters
	var foundInvalidChars bool
	for index := range len(keyAndIV) {
		keyChar := keyAndIV[index]
		if !((keyChar >= '0' && keyChar <= '9') ||
			(keyChar >= 'a' && keyChar <= 'f') ||
			(keyChar >= 'A' && keyChar <= 'F')) {
			foundInvalidChars = true
		}
	}
	if foundInvalidChars {
		err = fmt.Errorf("invalid encryption key: must be 64 hexadecimal characters")
		return
	}

	// Extract IV from key
	KeyBytes := []byte(keyAndIV[:32])
	TOTPSecret = []byte(keyAndIV[32:])

	log(verbosityTrace, "  Using Key (size:%dB): %s\n", len(KeyBytes), string(KeyBytes))
	log(verbosityTrace, "  Using IV (size:%dB): %s\n", len(TOTPSecret), string(TOTPSecret))

	// Reject invalid key length
	if len(KeyBytes) != 32 {
		err = fmt.Errorf("invalid key size, it must be 64 bytes(characters)")
		return
	}

	log(verbosityTrace, "  Key Bytes: %x\n", KeyBytes)

	// Create a new ChaCha20-Poly1305 instance
	AEAD, err = chacha20poly1305.New(KeyBytes)
	if err != nil {
		err = fmt.Errorf("failed to create aead cipher: %v", err)
		return
	}

	return
}

// This adds a time factor to mutate an IV that normally provides altered cipher text per encrypted payload
// With a shared secret, this creates time-based authentication
func MutateIVwithTime(TOTPSecret []byte) (IV []byte) {
	// Recover from panic
	defer func() {
		if r := recover(); r != nil {
			logError("panic while mutating encryption IV", fmt.Errorf("%v", r), false, true)
		}
	}()

	log(verbosityTrace, "    IVMutation: Using TOTP Secret: %x\n", TOTPSecret)

	// Get current time
	currentUTCTime := time.Now().UTC()

	log(verbosityTrace, "    IVMutation: current UTC time: %v\n", currentUTCTime)

	// Get the current second
	currentSecond := currentUTCTime.Second()

	log(verbosityTrace, "    IVMutation: current second: %d\n", currentSecond)

	// Determine the 15sec block that the current second is in
	secondBlockTime := (currentSecond / 15) * 15

	log(verbosityTrace, "    IVMutation: current seconds block: %d\n", secondBlockTime)

	// 64bit slice for current time in block form
	currentBlockTime := make([]byte, 8)

	// Create full time block which current time is in
	binary.BigEndian.PutUint64(currentBlockTime, uint64(currentUTCTime.Unix()-int64(currentSecond)+int64(secondBlockTime)))

	log(verbosityTrace, "    IVMutation: current full time block bytes: %x\n", currentBlockTime)

	// Add current time block to the shared secret
	TimeBlockAndSecret := append(currentBlockTime, TOTPSecret...)

	log(verbosityTrace, "    IVMutation: time block and IV combination: %x\n", TimeBlockAndSecret)

	// Hash combination of current time block and shared secret
	TOTP := sha256.Sum256(TimeBlockAndSecret)

	log(verbosityTrace, "    IVMutation: full time-based one-time password: '%x'\n", TOTP)

	// Return truncated hash for use as the current sessions encryption IV
	IV = TOTP[:12]

	log(verbosityTrace, "    IVMutation: Truncated IV to be used with AEAD Cipher: '%x'\n", IV)

	return
}

// Network latency compensator
// Allows for small drift between client and server before totp is invalid
func WaitForTimeWindow() {
	for {
		// Current second for this loop
		currentUTCTime := time.Now().UTC()
		currentSecond := currentUTCTime.Second()

		// Break loops when within bounds
		if (currentSecond >= 1 && currentSecond <= 14) ||
			(currentSecond >= 16 && currentSecond <= 29) ||
			(currentSecond >= 31 && currentSecond <= 44) ||
			(currentSecond >= 46 && currentSecond <= 59) {
			break
		}

		// Sleep for a short duration to avoid busy waiting
		time.Sleep(50 * time.Millisecond)
	}
}
