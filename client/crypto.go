// secureknock
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"time"
)

// Creates a new 28 byte (56 char) encryption key
// Writes key to supplied key file path
// Prints key location to user on successful write
func generateNewKey(keyFilePath string) (err error) {
	// Open key file
	keyFile, err := os.OpenFile(keyFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	defer keyFile.Close()

	// Create a byte slice of the expected length
	randomBytes := make([]byte, 28)

	// Fill the byte slice with cryptographically secure random data
	_, err = rand.Read(randomBytes)
	if err != nil {
		return
	}

	// Convert to string
	newKey := hex.EncodeToString(randomBytes)

	// Write the string content to the file
	_, err = keyFile.WriteString(newKey)
	if err != nil {
		return
	}

	// Show key location
	fmt.Printf("New encryption key written to %s\n", keyFilePath)
	return
}

// Reads in keyfile and extracts only hex characters from it
// Validates length is exactly 56 characters
// Separates into key and TOTP secret
// Creates the AESGCM cipher with the key
func prepareEncryption(keyFile string) (AESGCMCipherBlock cipher.AEAD, TOTPSecret []byte, err error) {
	// Grab configuration options from file
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		err = fmt.Errorf("failed to read key file: %v", err)
		return
	}

	// Extract just hex from key file
	key := HexRegEx.FindString(string(keyBytes))

	// Reject invalid key length
	if len(key) != 56 {
		err = fmt.Errorf("must be 28 bytes (56 characters)")
		return
	}

	// Extract IV from key
	hexKey := key[:32]
	hexIV := key[32:]

	// Decode key
	encryptionKey, err := hex.DecodeString(hexKey)
	if err != nil {
		err = fmt.Errorf("hex decode failed for key: %v", err)
		return
	}

	// Decode TOTP
	TOTPSecret, err = hex.DecodeString(hexIV)
	if err != nil {
		err = fmt.Errorf("hex decode failed for totp: %v", err)
		return
	}

	// Setup cipher
	CipherBlock, err := aes.NewCipher(encryptionKey)
	if err != nil {
		err = fmt.Errorf("failed to create cipher: %v", err)
		return
	}

	AESGCMCipherBlock, err = cipher.NewGCM(CipherBlock)
	if err != nil {
		err = fmt.Errorf("failed to create aead cipher: %v", err)
		return
	}

	return
}

// This adds a time factor to mutate an IV that normally provides altered cipher text per encrypted payload
// With a shared secret, this creates time-based authentication
func MutateIVwithTime(totpSecret []byte) []byte {
	// Get current time
	currentUTCTime := time.Now().UTC()

	// Get the current second
	currentSecond := currentUTCTime.Second()

	// Determine the 15sec block that the current second is in
	secondBlockTime := (currentSecond / 15) * 15

	// 64bit slice for current time in block form
	currentBlockTime := make([]byte, 8)

	// Create full time block which current time is in
	binary.BigEndian.PutUint64(currentBlockTime, uint64(currentUTCTime.Unix()-int64(currentSecond)+int64(secondBlockTime)))

	// Add current time block to the shared secret
	TimeBlockAndSecret := append(currentBlockTime, totpSecret...)

	// Hash combination of current time block and shared secret
	TOTP := sha256.Sum256(TimeBlockAndSecret)

	// Return truncated hash for use as the current sessions encryption IV
	return TOTP[:12]
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
