// secureknock
package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"runtime"
)

// Reserved separator character for action name in payload
const payloadSeparator string = ":"

// Regex
const payloadRegex string = "^[\x00-\x7F]*$"
const encryptionKeyRegex string = "[0-9a-fA-F]+"

// Reserved max lengths for action name and password (500 byte/chars for each)
const maxPayloadTextSize int = 500

// Written to only in main
var ASCIIRegEx *regexp.Regexp
var HexRegEx *regexp.Regexp

// Program Meta Info
const progVersion string = "v0.2.0"
const usage = `
Options:
    -k, --keyfile </path/to/keyfile>  Path to the encryption key file [default: priv.key]
    -a, --action <action name>        Send knock packet with specified action name
    -p, --use-password                Send knock packet with password for sudo (required if server is not running as root)
    -s, --saddr <domain|IP>           Send knock packet with source address
    -S, --sport <port number>         Send knock packet with source port
    -d, --daddr <domain|IP>           Send knock packet to destination address
    -D, --dport <port number>         Send knock packet to destination port
        --generate-key                Generate encryption key for use with server or client (requires '--keyfile')
    -h, --help                        Show this help menu
    -V, --version                     Show version and packages
    -v, --versionid                   Show only version number

Documentation: <https://github.com/EvSecDev/SecureKnock
`

func main() {
	// Program Argument Variables
	var keyFile string
	var actionName string
	var usePassword bool
	var sourceAddress string
	var sourcePort int
	var destinationAddress string
	var destinationPort int
	var genNewKey bool
	var versionFlagExists bool
	var versionNumberFlagExists bool

	// Read Program Arguments - allowing both short and long args
	flag.StringVar(&keyFile, "k", "priv.key", "")
	flag.StringVar(&keyFile, "keyfile", "", "")
	flag.StringVar(&actionName, "a", "", "")
	flag.StringVar(&actionName, "action", "", "")
	flag.BoolVar(&usePassword, "p", false, "")
	flag.BoolVar(&usePassword, "use-password", false, "")
	flag.StringVar(&sourceAddress, "s", "", "")
	flag.StringVar(&sourceAddress, "saddr", "", "")
	flag.IntVar(&sourcePort, "S", 0, "")
	flag.IntVar(&sourcePort, "sport", 0, "")
	flag.StringVar(&destinationAddress, "d", "", "")
	flag.StringVar(&destinationAddress, "daddr", "", "")
	flag.IntVar(&destinationPort, "D", 0, "")
	flag.IntVar(&destinationPort, "dport", 0, "")
	flag.BoolVar(&genNewKey, "generate-key", false, "")
	flag.BoolVar(&versionFlagExists, "V", false, "")
	flag.BoolVar(&versionFlagExists, "version", false, "")
	flag.BoolVar(&versionNumberFlagExists, "v", false, "")
	flag.BoolVar(&versionNumberFlagExists, "versionid", false, "")

	// Custom help menu
	flag.Usage = func() { fmt.Printf("Usage: %s [OPTIONS]...\n%s", os.Args[0], usage) }
	flag.Parse()

	// Meta info print out
	if versionFlagExists {
		fmt.Printf("SecureKnock %s compiled using %s(%s) on %s architecture %s\n", progVersion, runtime.Version(), runtime.Compiler, runtime.GOOS, runtime.GOARCH)
		fmt.Print("Packages: \n")
	} else if versionNumberFlagExists {
		fmt.Println(progVersion)
	} else if genNewKey && keyFile != "" {
		err := generateNewKey(keyFile)
		logError("failed to generate new encryption key", err)
	} else if actionName != "" && destinationAddress != "" {
		// Set regex vars
		ASCIIRegEx = regexp.MustCompile(payloadRegex)
		HexRegEx = regexp.MustCompile(encryptionKeyRegex)

		// Validate source
		sourceSocket, l4Protocol, err := validateIPandPort(sourceAddress, sourcePort)
		logError("invalid source", err)

		// Catch empty destination port
		if destinationPort == 0 {
			logError("invalid destination", fmt.Errorf("destination port is not specified"))
		}
		// Validate destination
		destinationSocket, l4Protocol, err := validateIPandPort(destinationAddress, destinationPort)
		logError("invalid destination", err)

		// Validate action name
		err = validateActionName(actionName)
		logError("invalid action name", err)

		// Prepare encryption
		AESGCMCipherBlock, TOTPSecret, err := prepareEncryption(keyFile)
		logError("failed encryption prep", err)

		// Create packet payload text
		payloadClearText, err := createPayloadText(actionName, usePassword)
		logError("failed to create text payload", err)

		// Send packet
		err = sendPacket(payloadClearText, AESGCMCipherBlock, TOTPSecret, sourceSocket, destinationSocket, l4Protocol)
		logError("failed to send packet", err)
	} else {
		fmt.Printf("No arguments specified or incorrect argument combination. Use '-h' or '--help' to guide your way.\n")
	}
}
