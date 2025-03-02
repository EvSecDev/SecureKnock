// secureknockd
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

type Config struct {
	LogFile       string                `json:"logFile,omitempty"`
	EncryptionKey string                `json:"encryptionKey"`
	CaptureFilter PCAPFilter            `json:"pcapFilter"`
	Actions       []map[string][]string `json:"actions"`
}
type PCAPFilter struct {
	CaptureInterface string `json:"captureInterface"`
	IncludeFilter    string `json:"inclusionBPF"`
	ExcludeFilter    string `json:"exclusionBPF,omitempty"`
}

// Reserved separator character for action name in payload
const payloadSeparator string = ":"

// Min and max byte length for expected payload (assuming 1500 byte mtu)
const minPayloadLengthB int = 10
const maxPayloadLengthB int = 1458

// Written to only in main
var logFilePath string
var sudoRequired bool

// Integer for printing increasingly detailed information as program progresses
//
//	0 - None: quiet (prints nothing but errors)
//	1 - Standard: normal progress messages
//	2 - Progress: more progress messages (no actual data outputted)
//	3 - Data: shows limited data being processed
//	4 - FullData: shows full data being processed
//	5 - Debug: shows extra data during processing (raw bytes)
var globalVerbosityLevel int

// Descriptive Names for available verbosity levels
const (
	VerbosityNone int = iota
	VerbosityStandard
	VerbosityProgress
	VerbosityData
	VerbosityFullData
	VerbosityDebug
	VerbosityTrace
)

// Program Meta Info
const progVersion string = "v0.3.0"
const logProgramName string = "SecurceKnockd"
const usage = `
Options:
    -s, --start-server              Start server
    -c, --config </path/to/json>    Path to the configuration file [default: secureknockd.json]
    -t, --dry-run                   Test config and environment validity only
    -T, --wet-run                   Test dry-run and PCAP validity
        --set-caps                  Add PCAP permissions to executable (for running as non-root user)
        --generate-key              Generate encryption key for use with server or client
    -v, --verbose <0...6>           Increase details of program execution (Higher=more verbose) [default: 1]
    -h, --help                      Show this help menu
    -V, --version                   Show version and packages
        --versionid                 Show only version number

Documentation: <https://github.com/EvSecDev/SecureKnock
`

func main() {
	// Program Argument Variables
	var configFilePath string
	var startServer bool
	var dryRun bool
	var wetRun bool
	var addCaps bool
	var genNewKey bool
	var versionFlagExists bool
	var versionNumberFlagExists bool

	// Read Program Arguments - allowing both short and long args
	flag.StringVar(&configFilePath, "c", "secureknockd.json", "")
	flag.StringVar(&configFilePath, "config", "secureknockd.json", "")
	flag.BoolVar(&startServer, "s", false, "")
	flag.BoolVar(&startServer, "start-server", false, "")
	flag.BoolVar(&dryRun, "t", false, "")
	flag.BoolVar(&dryRun, "dry-run", false, "")
	flag.BoolVar(&wetRun, "T", false, "")
	flag.BoolVar(&wetRun, "wet-run", false, "")
	flag.BoolVar(&addCaps, "set-caps", false, "")
	flag.BoolVar(&genNewKey, "generate-key", false, "")
	flag.BoolVar(&versionFlagExists, "V", false, "")
	flag.BoolVar(&versionFlagExists, "version", false, "")
	flag.BoolVar(&versionNumberFlagExists, "versionid", false, "")
	flag.IntVar(&globalVerbosityLevel, "v", 1, "")
	flag.IntVar(&globalVerbosityLevel, "verbosity", 1, "")

	// Custom help menu
	flag.Usage = func() { fmt.Printf("Usage: %s [OPTIONS]...\n%s", os.Args[0], usage) }
	flag.Parse()

	// Act on arguments
	if versionFlagExists {
		fmt.Printf("SecureKnockd %s compiled using %s(%s) on %s architecture %s\n", progVersion, runtime.Version(), runtime.Compiler, runtime.GOOS, runtime.GOARCH)
		fmt.Print("Packages: \n")
	} else if versionNumberFlagExists {
		fmt.Println(progVersion)
	} else if startServer {
		log(VerbosityProgress, "Reading config file '%s'\n", configFilePath)

		// Grab configuration options from file
		configFile, err := os.ReadFile(configFilePath)
		logError("failed to read config file", err, true, false)

		log(VerbosityProgress, "Parsing config file JSON\n")

		// Parse json from config file
		var config Config
		err = json.Unmarshal(configFile, &config)
		logError("failed to parse JSON config", err, true, false)

		// Set file log path (doesn't matter if its empty)
		logFilePath = config.LogFile

		log(VerbosityProgress, "Checking executable capabilities\n")

		// Check required capabilities
		err = checkCapabilities()
		logError("failed PCAP permission check", err, true, true)

		log(VerbosityProgress, "Looking for empty config fields that are required\n")

		// Ensure required config fields are present
		err = checkConfigForEmpty(&config)
		logError("missing required config fields", err, true, true)

		log(VerbosityProgress, "Validating supplied action commands are in programs PATH\n")

		// Ensure user supplied commands are in path
		err = validateActionCommands(config.Actions)
		logError("unable to find commands in config", err, true, true)

		// If running as a test, exit here
		if dryRun {
			log(VerbosityStandard, "Dry-run requested, all configuration settings are valid. Exiting...\n")
			return
		}

		log(VerbosityProgress, "Creating AES Cipher\n")

		// Validate and create cipher with config
		AESGCMCipherBlock, TOTPSecret, err := prepareEncryption(config.EncryptionKey)
		logError("failed to prepare encryption", err, true, true)

		// Start packet capture listener and begin processing captured packets
		captureAndProcess(config.CaptureFilter, config.Actions, AESGCMCipherBlock, TOTPSecret, wetRun)
	} else if addCaps {
		log(VerbosityProgress, "Adding 'cap_net_raw' capability to executable file\n")

		cmd := exec.Command("setcap", "cap_net_raw=ep", os.Args[0])
		_, err := cmd.CombinedOutput()
		logError(fmt.Sprintf("failed to set PCAP capability on executable (%s)", cmd.String()), err, true, false)
	} else if genNewKey {
		log(VerbosityProgress, "Creating a new random cryptographic key\n")

		err := generateNewKey()
		logError("failed to generate new encryption key", err, true, false)
	} else {
		fmt.Printf("No arguments specified or incorrect argument combination. Use '-h' or '--help' to guide your way.\n")
	}
}
