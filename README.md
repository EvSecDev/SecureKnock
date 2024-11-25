# SecureKnock

## Description

This program is designed to run a series of predetermined commands when a particular encrypted packet is received.
It is supposed to act as a replacement for a traditional port knocking program, except with more confidentiality and integrity.

For security, the program uses a time mutated IV and AES256 GCM encryption to ensure replay attack protection.
With these security features, there is:
- No need to run complex software exposed directly to the internet all the time, this program can toggle firewall rules or the larger program itself on and off by request of the client.
- No need for ANY reply traffic from the clients to exist, which means you can turn off any reply-to auto-rules that your firewall/router may apply to the connection.
- No need to worry about adversaries-in-the-middle. The server is able to authenticate the client and is protected against replay attacks.

This is a work-in-progress and may have unintended consequences as development is ongoing. Use at your own risk.

### Server Help Menu

```
Usage: ./secureknockd [OPTIONS]...

Options:
    -s, --start-server              Start server
    -c, --config </path/to/json>    Path to the configuration file [default: secureknockd.json]
        --set-caps                  Add PCAP permissions to executable (for running as non-root user)
        --generate-key              Generate encryption key for use with server or client
    -h, --help                      Show this help menu
    -V, --version                   Show version and packages
    -v, --versionid                 Show only version number
```

### Client Help Menu

```
Usage: ./secureknock [OPTIONS]...

Options:
    -k, --keyfile </path/to/keyfile>  Path to the encryption key file [default: priv.key]
    -a, --action <action name>        Send knock packet with specified action name
    -p, --use-password                Send knock packet with password for sudo (required if server is not running as root)
    -s, --saddr <domain|IP>           Send knock packet with source address
    -S, --sport <port number>         Send knock packet with source port
    -d, --daddr <domain|IP>           Send knock packet to destination address
    -D, --dport <port number>         Send knock packet to destination port
    -h, --help                        Show this help menu
    -V, --version                     Show version and packages
    -v, --versionid                   Show only version number
```
