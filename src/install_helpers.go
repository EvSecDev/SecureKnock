// secureknockd
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/term"
)

func installExeFile(defaultExePath string) (err error) {
	currentExePath := os.Args[0]
	if currentExePath == defaultExePath {
		return
	}
	err = os.Rename(currentExePath, defaultExePath)
	if err != nil {
		err = fmt.Errorf("failed to move executable file to default path: %v", err)
		return
	}

	err = os.Chown(defaultExePath, 0, 0)
	if err != nil {
		err = fmt.Errorf("failed to set executable ownership to root: %v", err)
		return
	}

	err = os.Chmod(defaultExePath, 0755)
	if err != nil {
		err = fmt.Errorf("failed to set executable permissions: %v", err)
		return
	}

	log(verbosityStandard, "Successfully installed executable at '%s'\n", defaultExePath)
	return
}

func installUser(username string, interactiveTerminal bool) (runAsUID int, err error) {
	passwdFile, err := os.Open("/etc/passwd")
	if err != nil {
		return
	}
	defer passwdFile.Close()

	scanner := bufio.NewScanner(passwdFile)

	var userIsPresent bool
	for scanner.Scan() {
		line := scanner.Text()

		fields := strings.Split(line, ":")
		if len(fields) > 0 && fields[0] == username {
			userIsPresent = true
		}
	}

	if userIsPresent {
		var userObj *user.User
		userObj, err = user.Lookup(username)
		if err != nil {
			err = fmt.Errorf("failed to find UID for user %s: %v", username, err)
			return
		}
		runAsUID, err = strconv.Atoi(userObj.Uid)
		if err != nil {
			return
		}

		log(verbosityProgress, "  User %s already present, skipping user setup\n", username)
		return
	}

	cmd := exec.Command("useradd", "--system", "--user-group", "--no-create-home", "--shell", "/usr/sbin/nologin", username)
	output, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("useradd command error: %v: %s", err, string(output))
		return
	}

	var newPassword []byte
	if interactiveTerminal {
		fmt.Printf("Enter password for new user %s: ", username)
		newPassword, err = term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return
		}

		fmt.Println()
	} else {
		reader := bufio.NewReader(os.Stdin)
		newPassword, err = reader.ReadBytes('\n')
		if err != nil {
			return
		}
	}

	cmd = exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader(username + ":" + string(newPassword))

	output, err = cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("chpasswd command error: %v: %s", err, string(output))
		return
	}

	const sudoersPath string = "/etc/sudoers"

	_, err = os.Stat(sudoersPath)
	if err == nil {
		var sudoersContent []byte
		sudoersContent, err = os.ReadFile(sudoersPath)
		if err != nil {
			err = fmt.Errorf("failed reading sudoers file")
			return
		}

		if !strings.Contains(string(sudoersContent), username) {
			sudoersEntry := fmt.Sprintf("\n# User for SecureKnockd\n%s ALL=(root:root) ALL\n", username)

			var file *os.File
			file, err = os.OpenFile(sudoersPath, os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				err = fmt.Errorf("failed to open sudoers file for writing: %v", err)
				return
			}
			defer file.Close()

			_, err = file.WriteString(sudoersEntry)
			if err != nil {
				err = fmt.Errorf("failed to append sudoers entry: %v", err)
				return
			}
		}
	}
	err = nil

	var userObj *user.User
	userObj, err = user.Lookup(username)
	if err != nil {
		err = fmt.Errorf("failed to find UID for user %s: %v", username, err)
		return
	}
	runAsUID, err = strconv.Atoi(userObj.Uid)
	if err != nil {
		return
	}

	log(verbosityStandard, "Successfully setup user %s\n", username)

	return
}

func installConfig(configPath string, defaultLogPath string, runAsUserID int) (err error) {
	_, err = os.Stat(configPath)
	if err == nil {
		log(verbosityProgress, "  Configuration file (%s) is present, not installing template config\n", configPath)
		return
	}
	err = nil

	encKey, err := createKeyHex()
	if err != nil {
		err = fmt.Errorf("failed to generate new encryption key: %v", err)
		return
	}

	var config Config
	config.EncryptionKey = encKey
	config.LogFile = defaultLogPath
	config.CaptureFilter.CaptureInterface = "lo"
	config.CaptureFilter.IncludeFilter = "udp port 12345"
	config.Actions = []map[string][]string{
		{
			"start": {"touch /tmp/test", "touch /tmp/test2"},
			"stop":  {"rm /tmp/test", "rm /tmp/test2"},
		},
	}

	configJSON, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		err = fmt.Errorf("failed to create JSON config: %v", err)
		return
	}
	configJSON = append(configJSON, '\n')

	configFile, err := os.OpenFile(configPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0640)
	if err != nil {
		err = fmt.Errorf("failed to open config file: %v", err)
		return
	}
	defer configFile.Close()

	_, err = configFile.Write(configJSON)
	if err != nil {
		err = fmt.Errorf("failed to write config JSON to file: %v", err)
		return
	}

	err = os.Chown(configPath, 0, runAsUserID)
	if err != nil {
		err = fmt.Errorf("failed to set executable ownership to root: %v", err)
		return
	}

	err = os.Chmod(configPath, 0755)
	if err != nil {
		err = fmt.Errorf("failed to set executable permissions: %v", err)
		return
	}

	log(verbosityStandard, "Successfully installed template config to '%s'\n  Don't forget to change the default values\n", configPath)

	return
}

func installApparmorProfile(profileDir string, executablePath string, configPath string, logPath string) (err error) {
	_, err = os.Stat(profileDir)
	if os.IsNotExist(err) {
		log(verbosityProgress, "  Apparmor profile directory (%s) not present, not installing profile\n", profileDir)
		return
	} else if err != nil {
		err = fmt.Errorf("unable to access apparmor profile directory: %v", err)
		return
	}

	executablePath = strings.TrimPrefix(executablePath, "/")
	AAProfFile := strings.ReplaceAll(executablePath, "/", ".")
	profilePath := profileDir + AAProfFile

	aaProf := `### Apparmor Profile for the SecureKnock Daemon
## This is a very locked down profile made for Debian systems
## Variables
@{exelocation}=` + executablePath + `
@{configlocation}=` + configPath + `
@{logfilelocation}=` + logPath + `
@{pid}={[1-9],[1-9][0-9],[1-9][0-9][0-9],[1-9][0-9][0-9][0-9],[1-9][0-9][0-9][0-9][0-9],[1-9][0-9][0-9][0-9][0-9][0-9],[1-4][0-9][0-9][0-9][0-9][0-9][0-9]}

## Profile Begin
profile SecureKnockd @{exelocation} flags=(enforce) {
  # Receive signals
  signal receive set=(kill, term, exists, cont) peer=unconfined,
  signal receive set=(term, urg, exists, int) peer=SecureKnockd,
  # Send signals to self
  signal send set=(term, urg, exists, int) peer=SecureKnockd,

  # Capabilities
  capability net_raw,
  unix (send) type=stream,
  network netlink raw,
  network packet raw,
  # reject default unused behavior
  deny network inet dgram,
  deny network inet6 dgram,
  deny network unix raw,

  # Capability (self) access
  /dev/null rw,
  /usr/sbin/setcap rmix,

  # Startup Configurations needed
  @{configlocation} r,

  # Log accesses
  @{logfilelocation} rw,
  /usr/local/go/lib/time/zoneinfo.zip r,
  /usr/share/zoneinfo/** r,

  # Allow sudo execution for running action commands
  /usr/bin/sudo rmpx -> SecureKnockdSudo,

  # Misc accesses
  /proc/@{pid}/status r,
  /proc/@{pid}/maps r,
  /proc/sys/kernel/cap_last_cap r,
  /sys/kernel/mm/transparent_hugepage/hpage_pmd_size r,

  # Main Library access
  /etc/ld.so.cache r,
  /usr/lib/x86_64-linux-gnu/libpcap.so.* rm,
  /usr/lib/x86_64-linux-gnu/libcap.so.* rm,
  /usr/lib/x86_64-linux-gnu/libc.so.* rm,
  /usr/lib/x86_64-linux-gnu/libdbus-*.so.* rm,
  /usr/lib/x86_64-linux-gnu/libsystemd.so.* rm,
  /usr/lib/x86_64-linux-gnu/libgcrypt.so.* rm,
  /usr/lib/x86_64-linux-gnu/liblzma.so.* rm,
  /usr/lib/x86_64-linux-gnu/libzstd.so.* rm,
  /usr/lib/x86_64-linux-gnu/liblz4.so.* rm,
  /usr/lib/x86_64-linux-gnu/libgpg-error.so.* rm,
}
profile SecureKnockdSudo flags=(enforce) {
  # Read self
  /usr/bin/sudo r,
  / r,

  # Capabilities
  capability sys_resource,
  capability setuid,
  capability setgid,
  capability audit_write,
  capability chown,
  network netlink raw,
  network unix stream,
  network unix dgram,
  network inet dgram,
  network inet6 dgram,
  network packet raw,

  # User defined commands for actions (change as needed)
  # /usr/bin/nft rmpx -> SecureKnockdActions,
  /usr/bin/systemctl rmUx,
  /usr/sbin/nft rmUx,

  # /proc accesses
  /proc/stat r,
  /proc/filesystems r,
  /proc/sys/kernel/cap_last_cap r,
  /proc/sys/kernel/ngroups_max rw,
  /proc/sys/kernel/seccomp/actions_avail r,
  /proc/1/limits r,
  /proc/@{pid}/stat r,
  owner /proc/@{pid}/mounts r,
  owner /proc/@{pid}/status r,

  # /run accesses
  /run/ r,
  /run/sudo/ r,
  /run/sudo/ts/{,*} rwk,

  # /usr accesses
  /usr/share/zoneinfo/** r,
  /usr/lib/locale/locale-archive r,
  /usr/sbin/unix_chkpwd rmix,
  # Not necessary, additional attack surface
  deny /usr/sbin/sendmail rmx,

  # /etc accesses
  /etc/login.defs r,
  /etc/ld.so.cache r,
  /etc/locale.alias r,
  /etc/nsswitch.conf r,
  /etc/passwd r,
  /etc/shadow r,
  /etc/sudo.conf r,
  /etc/sudoers r,
  /etc/sudoers.d/{,*} r,
  /etc/pam.d/other r,
  /etc/pam.d/sudo r,
  /etc/pam.d/common-auth r,
  /etc/pam.d/common-account r,
  /etc/pam.d/common-session-noninteractive r,
  /etc/pam.d/common-session r,
  /etc/pam.d/common-password r,
  /etc/security/limits.conf r,
  /etc/security/limits.d/ r,
  /etc/group r,
  /etc/host.conf r,
  /etc/hosts r,
  /etc/resolv.conf r,
  /etc/gai.conf r,

  # /dev accesses
  /dev/tty rw,
  /dev/null rw,

  ## Libraries needed for sudo - lib versions are wildcarded
  /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.* r,
  /usr/lib/x86_64-linux-gnu/libaudit.so.* rm,
  /usr/lib/x86_64-linux-gnu/libselinux.so* rm,
  /usr/lib/x86_64-linux-gnu/libc.so* rm,
  /usr/lib/x86_64-linux-gnu/libcap-ng.so.* rm,
  /usr/lib/x86_64-linux-gnu/libpcre*.so.* rm,
  /usr/lib/x86_64-linux-gnu/libpam.so.* rm,
  /usr/lib/x86_64-linux-gnu/libz.so.* rm,
  /usr/lib/x86_64-linux-gnu/libm.so.* rm,
  /usr/libexec/sudo/libsudo_util.so.* rm,
  /usr/libexec/sudo/sudoers.so rm,
  /usr/lib/x86_64-linux-gnu/libnss_systemd.so.* rm,
  /usr/lib/x86_64-linux-gnu/libcap.so.* rm,
  /usr/lib/x86_64-linux-gnu/security/pam_limits.so rm,
  /usr/lib/x86_64-linux-gnu/security/pam_unix.so rm,
  /usr/lib/x86_64-linux-gnu/security/pam_deny.so rm,
  /usr/lib/x86_64-linux-gnu/security/pam_permit.so rm,
  /usr/lib/x86_64-linux-gnu/security/pam_systemd.so rm,
  /usr/lib/x86_64-linux-gnu/libcrypt.so.* rm,
  /usr/lib/x86_64-linux-gnu/libpam_misc.so.* rm,
  /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache r,
  /usr/lib/x86_64-linux-gnu/gconv/gconv-modules r,
  /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.d/ r,
}
# Dedicated profile if confining action commands is desired
#profile SecureKnockdActions flags=(enforce) {
# 
#}
`
	profileFile, err := os.OpenFile(profilePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0640)
	if err != nil {
		err = fmt.Errorf("failed to open apparmor profile file: %v", err)
		return
	}
	defer profileFile.Close()

	_, err = profileFile.Write([]byte(aaProf))
	if err != nil {
		err = fmt.Errorf("failed to write apparmor profile to file: %v", err)
		return
	}

	cmd := exec.Command("apparmor_parser", "--replace", profilePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("failed to enable apparmor profile: %v: %s", err, string(output))
		return
	}

	log(verbosityStandard, "Successfully installed Apparmor profile at '%s'\n  Don't forget to tweak it for your specific action commands\n", profilePath)
	return
}

func installSystemdService(executablePath string, configPath string, runAsUser string, serviceName string, serviceFilePath string) (err error) {
	serviceUnitDir := filepath.Dir(serviceFilePath)

	_, err = os.Stat(serviceUnitDir)
	if os.IsNotExist(err) {
		log(verbosityProgress, "  Systemd service unit file directory (%s) not present, not installing service\n", serviceFilePath)
		return
	} else if err != nil {
		err = fmt.Errorf("unable to access systemd unit file directory: %v", err)
		return
	}

	_, err = os.Stat(serviceFilePath)
	var serviceAlreadyExists bool
	if err == nil {
		cmd := exec.Command("systemctl", "stop", serviceName)
		err = cmd.Run()
		if err != nil {
			err = fmt.Errorf("failed to stop systemd service: %v", err)
			return
		}
		serviceAlreadyExists = true
	}
	err = nil

	serviceUnitFile := `[Unit]
Description=Secure Knock Daemon
After=network.target
StartLimitIntervalSec=1h
StartLimitBurst=6

[Service]
StandardOutput=journal
StandardError=journal
ExecStart=` + executablePath + ` --listen --config ` + configPath + `
User=` + runAsUser + `
Group=` + runAsUser + `
Type=simple
RestartSec=1min
Restart=always

[Install]
WantedBy=multi-user.target
`

	serviceFile, err := os.OpenFile(serviceFilePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		err = fmt.Errorf("failed to open service file: %v", err)
		return
	}
	defer serviceFile.Close()

	_, err = serviceFile.WriteString(serviceUnitFile)
	if err != nil {
		err = fmt.Errorf("failed to write to service file: %v", err)
		return
	}

	if serviceAlreadyExists {
		cmd := exec.Command("systemctl", "daemon-reload")
		err = cmd.Run()
		if err != nil {
			err = fmt.Errorf("failed to reload systemd unit files: %v", err)
			return
		}

		cmd = exec.Command("systemctl", "start", serviceName)
		err = cmd.Run()
		if err != nil {
			err = fmt.Errorf("failed to restart systemd service: %v", err)
			return
		}

		log(verbosityStandard, "Successfully installed Systemd service at '%s'\n", serviceFilePath)
	} else {

		cmd := exec.Command("systemctl", "enable", serviceName)
		err = cmd.Run()
		if err != nil {
			err = fmt.Errorf("failed to enable systemd service: %v", err)
			return
		}

		log(verbosityStandard, "Successfully installed and enabled Systemd service at '%s'\n  Leaving service stopped until daemon is configured\n", serviceFilePath)
	}
	return
}
