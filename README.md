# SecureKnock

## Description

This program is designed to run a series of predetermined commands when a particular encrypted packet is received.
It is supposed to act as a replacement for a traditional port knocking program, except with more confidentiality and integrity.

For security, the program uses a time mutated IV(Nonce) and ChaCha20-Poly1305 encryption to ensure replay attack protection and confidentiality of the payload.
With these security features, there is:

- No need to run complex software exposed directly to the internet all the time, this program can toggle firewall rules or the larger program itself on and off by request of the client.
- No need for ANY reply traffic from the clients to exist, which means you can turn off any reply-to auto-rules that your firewall/router may apply to the connection.
- No need to worry about adversaries-in-the-middle. The server is able to authenticate the client and is protected against replay attacks.

Some examples of how this program can be deployed:

- Run on a VPN server and when a valid knock is received, start the VPN server service and add an allow firewall rule.
- Run on a Web server and when a valid knock is received, start the web server service and add an allow firewall rule.
- Run on a firewall and when a valid knock is seen, add a firewall rule.

This is a work-in-progress and may have unintended consequences as development is ongoing. Use at your own risk.

### Help Menu

```bash
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
```

Notes:

- `--action`: This argument is used to specify a single action (must be one of the `actions` from the server JSON configuration.
- `--use-password`: This argument will prompt you for the sudo password of the server's non-root user. This argument does not take the password directly, wait until prompted to enter the password.
- `--saddr|sport|daddr|dport`: All except `--sport`, `--saddr` are required arguments. Specifying nothing or 0 as `--sport` will use a random number.
- `--set-caps`: If installing or updating manually, be sure to run this argument as root to ensure executable file has required capability for packet captures as non-root user.
- `--generate-key`: For ease of use, this is available to create and print a new encryption key, you can always use openssl to generate the 28 byte key.
- `--install-server`: Easy setup for the daemon.
  - To force installation as root user export variable `runAsRoot` with any value.
  - To setup the unprivileged user password unattended, write the password to stdin (`echo 'mypassword' | secureknock --install-server`)
  - This can also be used to update the server components. This argument will not overwrite the configuration file, only the other components.

#### JSON Configuration File Example

```json
{
  "logFile": "$DaemonLogFile",
  "encryptionKey": "$encryptionKey",
  "pcapFilter":
  {
    "captureInterface": "lo",
    "inclusionBPF":"",
    "exclusionBPF":""
  },
  "actions":
  [
    {"action1": ["1cmd1", "1cmd2"]},
    {"action2": ["2cmd1", "2cmd2"]}
  ]
}
```

Notes:

- `logFile`: This will have all errors and messages from server in the same format as `/var/log/syslog`. Omit if you do not want to log to any file.
- `encryptionKey`: This 28 byte hexadecimal value (56 characters) is used to both encrypt and mutate payloads to ensure confidentiality and replay-attack protection.
- `inclusionBPF`: This is the primary filter that will capture the knock packet.
- `exclusionBPF`: This is an optional feature where you can specify what packets to not capture. Filter string is added to the inclusion filter with `and not`.
- `actions`: This has a list of 'actions' and their subsequent commands. The action name `action1` will be sent by the client to indicate which set of commands the server should run. The commands are run in linear order.
