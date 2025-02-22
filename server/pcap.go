// secureknockd
package main

import (
	"crypto/cipher"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Starts packet capture and handles data payload processing
func captureAndProcess(filter PCAPFilter, actions []map[string][]string, AESGCMCipherBlock cipher.AEAD, TOTPSecret []byte) {
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
	}

	// Open packet capture device
	captureHandle, err := pcap.OpenLive(filter.CaptureInterface, 1600, false, pcap.BlockForever)
	logError("failed to open capture device", err, true, true)
	defer captureHandle.Close()

	// Set filter
	err = captureHandle.SetBPFFilter(captureFilter)
	logError("failed to set BPF filter", err, true, true)

	// Show progress to user
	log(fmt.Sprintf("Listening for knocks on interface %s", filter.CaptureInterface))

	// Loop over packets captured
	packetSource := gopacket.NewPacketSource(captureHandle, captureHandle.LinkType())
	for packet := range packetSource.Packets() {
		// Get headers
		l3meta := packet.NetworkLayer().NetworkFlow()
		l4meta := packet.TransportLayer().TransportFlow()

		// Ensure received packet is within expected bounds
		payload, err := validatePacket(packet)
		if err != nil {
			logError(fmt.Sprintf("received invalid packet from %s:%s", l3meta.Src(), l4meta.Src()), err, false, true)
			continue
		}

		// Decrypt payload
		sessionIV := MutateIVwithTime(TOTPSecret)
		decryptedPayload, err := AESGCMCipherBlock.Open(nil, sessionIV, payload, nil)
		if err != nil {
			logError(fmt.Sprintf("failed decryption of payload from %s:%s", l3meta.Src(), l4meta.Src()), err, false, true)
			continue
		}

		// Parse decrypted payload
		actionName, commands, sudoPassword, err := parsePayload(decryptedPayload, actions)
		if err != nil {
			logError(fmt.Sprintf("received unauthorized payload from %s:%s", l3meta.Src(), l4meta.Src()), err, false, true)
			continue
		}

		// Log received knock packet
		log(fmt.Sprintf("Received knock packet (action:%s) from %s:%s", actionName, l3meta.Src(), l4meta.Src()))

		// Run commands for the action
		err = runCommands(commands, sudoPassword)
		if err != nil {
			logError(fmt.Sprintf("failed action command issued from %s:%s", l3meta.Src(), l4meta.Src()), err, false, true)
			continue
		}

		// Log action
		log(fmt.Sprintf("Completed action '%s' issued from %s:%s", actionName, l3meta.Src(), l4meta.Src()))
	}
}
