// secureknock
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
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
const maxPayloadLengthB int = 500

// Reserved max lengths for action name and password (500 byte/chars for each)
const maxPayloadTextSize int = 249

// Written to only in main
var logFilePath string
var sudoRequired bool
var disableSudo bool

// Integer for printing increasingly detailed information as program progresses
//
//	0 - None: quiet (prints nothing but errors)
//	1 - Standard: normal progress messages
//	2 - Progress: more progress messages (no actual data outputted)
//	3 - Data: shows limited data being processed
//	4 - FullData: shows full data being processed
//	5 - Debug: shows extra data during processing (raw bytes)
//	6 - Trace: shows even more data
var globalVerbosityLevel int

// Descriptive Names for available verbosity levels
const (
	verbosityNone int = iota
	verbosityStandard
	verbosityProgress
	verbosityData
	verbosityFullData
	verbosityDebug
	verbosityTrace
)

func main() {
	// Program Argument Variables
	var startServer bool
	var runClient bool
	var configFilePath string
	var keyFile string
	var actionName string
	var sourceAddress string
	var sourcePort int
	var destinationAddress string
	var destinationPort int
	var usePassword bool
	var dryRun bool
	var wetRun bool
	var addCaps bool
	var genNewKey bool
	var installRequested bool
	var versionFlagExists bool
	var versionNumberFlagExists bool

	const usage = `
SecureKnock
  Send and receive encrypted UDP packets to perform actions on remote systems

Examples:
    secureknock --client -k <secret.key> -S 54321 -d example.com -D 1234 -a startwebserver
    secureknock --listen -c </etc/skd.json>

Options:
    -l, --listen                      Listen for knock packets via packet capture
    -C, --client                      Send knock packet to remote
    -c, --config </path/to/json>      Path to the configuration file [default: secureknockd.json]
    -k, --keyfile </path/to/keyfile>  Path to the encryption key file (Overrides key value in server config)
    -a, --action <action name>        Send knock packet with specified action name
    -s, --saddr <domain|IP>           Send knock packet with source address
    -S, --sport <port number>         Send knock packet with source port
    -d, --daddr <domain|IP>           Send knock packet to destination address
    -D, --dport <port number>         Send knock packet to destination port
    -p, --use-password                Send knock packet with password for sudo (required if server is not running as root)
        --disable-sudo                Disables running commands with sudo when server is running as non-root user
        --dry-run                     Test option and environment validity with doing anything
        --wet-run                     Test dry-run and PCAP validity for server
        --set-caps                    Add PCAP permissions to executable (for running server as non-root user)
        --generate-key                Generate encryption key for use with server or client (save to file with '--keyfile')
        --install-server              Install server and related components (systemd, apparmor, config)
    -v, --verbose <0...6>             Increase details of program execution (Higher=more verbose) [default: 1]
    -h, --help                        Show this help menu
    -V, --version                     Show version and packages
        --versionid                   Show only version number

Report bugs to: dev@evsec.net
SecureKnock home page: <https://github.com/EvSecDev/SecureKnock>
General help using GNU software: <https://www.gnu.org/gethelp/>
`
	// Read Program Arguments - allowing both short and long args
	flag.BoolVar(&startServer, "l", false, "")
	flag.BoolVar(&startServer, "listen", false, "")
	flag.BoolVar(&runClient, "C", false, "")
	flag.BoolVar(&runClient, "client", false, "")
	flag.StringVar(&configFilePath, "c", "secureknockd.json", "")
	flag.StringVar(&configFilePath, "config", "secureknockd.json", "")
	flag.StringVar(&keyFile, "k", "", "")
	flag.StringVar(&keyFile, "keyfile", "", "")
	flag.StringVar(&actionName, "a", "", "")
	flag.StringVar(&actionName, "action", "", "")
	flag.StringVar(&sourceAddress, "s", "", "")
	flag.StringVar(&sourceAddress, "saddr", "", "")
	flag.IntVar(&sourcePort, "S", 0, "")
	flag.IntVar(&sourcePort, "sport", 0, "")
	flag.StringVar(&destinationAddress, "d", "", "")
	flag.StringVar(&destinationAddress, "daddr", "", "")
	flag.IntVar(&destinationPort, "D", 0, "")
	flag.IntVar(&destinationPort, "dport", 0, "")
	flag.BoolVar(&usePassword, "p", false, "")
	flag.BoolVar(&usePassword, "use-password", false, "")
	flag.BoolVar(&disableSudo, "disable-sudo", false, "")
	flag.BoolVar(&dryRun, "t", false, "")
	flag.BoolVar(&dryRun, "dry-run", false, "")
	flag.BoolVar(&wetRun, "T", false, "")
	flag.BoolVar(&wetRun, "wet-run", false, "")
	flag.BoolVar(&addCaps, "set-caps", false, "")
	flag.BoolVar(&genNewKey, "generate-key", false, "")
	flag.BoolVar(&installRequested, "install-server", false, "")
	flag.BoolVar(&versionFlagExists, "V", false, "")
	flag.BoolVar(&versionFlagExists, "version", false, "")
	flag.BoolVar(&versionNumberFlagExists, "versionid", false, "")
	flag.IntVar(&globalVerbosityLevel, "v", 1, "")
	flag.IntVar(&globalVerbosityLevel, "verbosity", 1, "")

	// Custom help menu
	flag.Usage = func() { fmt.Printf("Usage: %s [OPTIONS]...%s", os.Args[0], usage) }
	flag.Parse()

	// Program Meta Args
	const progVersion string = "v1.1.0"
	if versionFlagExists {
		fmt.Printf("secureknock %s compiled using %s(%s) on %s architecture %s\n", progVersion, runtime.Version(), runtime.Compiler, runtime.GOOS, runtime.GOARCH)
		fmt.Print("Direct Package Imports: runtime github.com/syndtr/gocapability/capability encoding/hex strings golang.org/x/term strconv io bufio encoding/json flag fmt time crypto/rand math/big os/exec net github.com/google/gopacket os crypto/sha256 golang.org/x/crypto/chacha20poly1305 os/user crypto/cipher path/filepath github.com/google/gopacket/pcap encoding/binary\n")
	} else if versionNumberFlagExists {
		fmt.Println(progVersion)
	} else if installRequested {
		err := installServerComponents()
		logError("failed server installation", err, true, true)
	} else if startServer {
		log(verbosityProgress, "Reading config file '%s'\n", configFilePath)

		configFile, err := os.ReadFile(configFilePath)
		logError("failed to read config file", err, true, false)

		log(verbosityProgress, "Parsing config file JSON\n")

		var config Config
		err = json.Unmarshal(configFile, &config)
		logError("failed to parse JSON config", err, true, false)

		// Set file log path (doesn't matter if its empty)
		logFilePath = config.LogFile

		err = checkCapabilities()
		logError("failed PCAP permission check", err, true, true)

		err = checkConfigForEmpty(&config)
		logError("missing required config fields", err, true, true)

		err = validateActionCommands(config.Actions)
		logError("unable to find commands in config", err, true, true)

		if dryRun {
			log(verbosityStandard, "Dry-run requested, all configuration settings are valid. Exiting...\n")
			return
		}

		AEAD, TOTPSecret, err := prepareEncryption(config.EncryptionKey, keyFile)
		logError("failed to prepare encryption", err, true, true)

		captureAndProcess(config.CaptureFilter, config.Actions, AEAD, TOTPSecret, wetRun)
	} else if runClient {
		sourceSocket, _, err := validateIPandPort(sourceAddress, sourcePort, true)
		logError("invalid source", err, true, false)

		destinationSocket, l4Protocol, err := validateIPandPort(destinationAddress, destinationPort, false)
		logError("invalid destination", err, true, false)

		err = validateActionName(actionName)
		logError("invalid action name", err, true, false)

		AEAD, TOTPSecret, err := prepareEncryption("", keyFile)
		logError("failed encryption prep", err, true, false)

		payloadClearText, err := createPayloadText(actionName, usePassword)
		logError("failed to create text payload", err, true, false)

		if dryRun {
			log(verbosityStandard, "Dry-run requested, all settings are valid. Exiting...\n")
			return
		}

		err = sendPacket(payloadClearText, AEAD, TOTPSecret, sourceSocket, destinationSocket, l4Protocol)
		logError("failed to send packet", err, true, false)
	} else if addCaps {
		err := setCapabilities()
		logError("failed to set capabilities", err, true, true)
	} else if genNewKey {
		err := generateNewKey(keyFile)
		logError("failed to generate new encryption key", err, true, false)
	} else {
		log(verbosityStandard, "No arguments specified or incorrect argument combination. Use '-h' or '--help' to guide your way.\n")
	}
}
