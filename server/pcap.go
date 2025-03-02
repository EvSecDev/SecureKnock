// secureknockd
package main

import (
	"crypto/cipher"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Starts packet capture and handles data payload processing
func captureAndProcess(filter PCAPFilter, actions []map[string][]string, AESGCMCipherBlock cipher.AEAD, TOTPSecret []byte, wetRun bool) {
	// Recover from panic
	defer func() {
		if r := recover(); r != nil {
			logError("panic while processing packets", fmt.Errorf("%v", r), true, true)
		}
	}()

	// Prepare filter
	captureFilter := "udp and " + filter.IncludeFilter

	// Add user defined BPF to capture filter
	if len(filter.ExcludeFilter) > 0 {
		captureFilter += fmt.Sprintf("(%s) and not (%s)", captureFilter, filter.ExcludeFilter)

		log(VerbosityData, "  Using exclusion filter '%s'\n", filter.ExcludeFilter)
	}

	log(VerbosityData, "  Full BPF: '%s'\n", captureFilter)

	// Open packet capture device
	captureHandle, err := pcap.OpenLive(filter.CaptureInterface, 1600, false, pcap.BlockForever)
	logError("failed to open capture device", err, true, true)
	defer captureHandle.Close()

	log(VerbosityProgress, "  Setting BPF on capture handle\n")

	// Set filter
	err = captureHandle.SetBPFFilter(captureFilter)
	logError("failed to set BPF filter", err, true, true)

	// If testing, exit here
	if wetRun {
		log(VerbosityStandard, "Wet-run requested, all configuration and packet capture settings are valid. Exiting...\n")
		return
	}

	// Show progress to user
	log(VerbosityStandard, "Listening for knocks on interface %s\n", filter.CaptureInterface)

	// Loop over packets captured
	packetSource := gopacket.NewPacketSource(captureHandle, captureHandle.LinkType())
	for packet := range packetSource.Packets() {
		// Get headers
		l3meta := packet.NetworkLayer().NetworkFlow()
		l4meta := packet.TransportLayer().TransportFlow()

		log(VerbosityFullData, "  Received packet from: %s:%s\n", l3meta.Src(), l4meta.Src())

		// Ensure received packet is within expected bounds
		payload, err := validatePacket(packet)
		if err != nil {
			logError(fmt.Sprintf("received invalid packet from %s:%s", l3meta.Src(), l4meta.Src()), err, false, true)
			continue
		}

		log(VerbosityFullData, "  Received packet payload:\n\n%s\n\n", string(payload))

		// Decrypt payload
		sessionIV := MutateIVwithTime(TOTPSecret)
		decryptedPayload, err := AESGCMCipherBlock.Open(nil, sessionIV, payload, nil)
		if err != nil {
			logError(fmt.Sprintf("failed decryption of payload from %s:%s", l3meta.Src(), l4meta.Src()), err, false, true)
			continue
		}

		log(VerbosityFullData, "  Decrypted packet payload:\n\n%s\n\n", string(decryptedPayload))

		// Parse decrypted payload
		actionName, commands, sudoPassword, err := parsePayload(decryptedPayload, actions)
		if err != nil {
			logError(fmt.Sprintf("received unauthorized payload from %s:%s", l3meta.Src(), l4meta.Src()), err, false, true)
			continue
		}

		// Log received knock packet
		log(VerbosityStandard, "Received knock packet (action:%s) from %s:%s\n", actionName, l3meta.Src(), l4meta.Src())

		// Run commands for the action
		err = runCommands(commands, sudoPassword)
		if err != nil {
			logError(fmt.Sprintf("failed action command issued from %s:%s", l3meta.Src(), l4meta.Src()), err, false, true)
			continue
		}

		// Log action
		log(VerbosityStandard, "Completed action '%s' issued from %s:%s\n", actionName, l3meta.Src(), l4meta.Src())
	}
}
