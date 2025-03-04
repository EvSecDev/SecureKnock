// secureknockd
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"time"
)

// Creates a new 28 byte (56 char) encryption key
// Prints key to user on success
func generateNewKey() (err error) {
	// Create a byte slice of the expected length
	randomBytes := make([]byte, 28)

	// Fill the byte slice with cryptographically secure random data
	_, err = rand.Read(randomBytes)
	if err != nil {
		return
	}

	// Convert to string
	newKey := hex.EncodeToString(randomBytes)

	// Give to user
	fmt.Printf("New Encryption Key: %s\n", newKey)
	return
}

// Reads in keyfile and extracts only hex characters from it
// Validates length is exactly 56 characters
// Separates into key and TOTP secret
// Creates the AESGCM cipher with the key
func prepareEncryption(keyAndIV string) (AESGCMCipherBlock cipher.AEAD, TOTPSecret []byte, err error) {
	// Extract just hex from key
	HexRegEx := regexp.MustCompile(`[0-9a-fA-F]+`)
	key := HexRegEx.FindString(keyAndIV)

	// Reject invalid key length
	if len(key) != 56 {
		err = fmt.Errorf("invalid key size, it must be 28 bytes (56 characters)")
		return
	}

	// Extract IV from key
	hexKey := key[:32]
	hexIV := key[32:]

	log(VerbosityTrace, "    EncryptionPrep: key: %x\n", hexKey)
	log(VerbosityTrace, "    EncryptionPrep: IV: %x\n", hexIV)

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
func MutateIVwithTime(TOTPSecret []byte) []byte {
	// Recover from panic
	defer func() {
		if r := recover(); r != nil {
			logError("panic while mutating encryption IV", fmt.Errorf("%v", r), false, true)
		}
	}()

	// Get current time
	currentUTCTime := time.Now().UTC()

	log(VerbosityTrace, "    IVMutation: current UTC time: %v\n", currentUTCTime)

	// Get the current second
	currentSecond := currentUTCTime.Second()

	log(VerbosityTrace, "    IVMutation: current second: %d\n", currentSecond)

	// Determine the 15sec block that the current second is in
	secondBlockTime := (currentSecond / 15) * 15

	log(VerbosityTrace, "    IVMutation: current second block: %d\n", secondBlockTime)

	// 64bit slice for current time in block form
	currentBlockTime := make([]byte, 8)

	log(VerbosityTrace, "    IVMutation: current second block bytes: %x\n", currentBlockTime)

	// Create full time block which current time is in
	binary.BigEndian.PutUint64(currentBlockTime, uint64(currentUTCTime.Unix()-int64(currentSecond)+int64(secondBlockTime)))

	log(VerbosityTrace, "    IVMutation: current full time block bytes: %x\n", currentBlockTime)

	// Add current time block to the shared secret
	TimeBlockAndSecret := append(currentBlockTime, TOTPSecret...)

	log(VerbosityTrace, "    IVMutation: time block and IV combination: %x\n", TimeBlockAndSecret)

	// Hash combination of current time block and shared secret
	TOTP := sha256.Sum256(TimeBlockAndSecret)

	log(VerbosityTrace, "    IVMutation: full time-based one-time password: '%x'\n", TOTP)

	// Return truncated hash for use as the current sessions encryption IV
	return TOTP[:12]
}
