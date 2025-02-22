#!/bin/bash
# Ensure script is run only in bash, required for built-ins (read, conditionals)
if [ -z "$BASH_VERSION" ]
then
	echo "This script must be run in BASH."
	exit 1
fi

# Only run script if running as root (or with sudo)
if [ "$EUID" -ne 0 ]
then
	echo "This script must be run with root permissions"
	exit 1
fi

#### Pre Checks

# Check for commands
command -v echo
command -v tar
command -v sudo
command -v mkdir
command -v rm
command -v tail
command -v cat
command -v base64
command -v passwd
command -v systemctl

set -e

#### Installation
echo -e "\n========================================"
echo "         SecureKnockD Installer         "
echo "========================================"
read -p " Press enter to begin the installation"
echo -e "========================================"

# Default choices
executablePath="/usr/local/bin/secureknockd"
configFilePath="/etc/secureknockd.json"
RunAsUser="skduser"
DaemonLogFile="/tmp/secureknockd.log"
ApparmorProfilePath=/etc/apparmor.d/$(echo $executablePath | sed 's|^/||g' | sed 's|/|.|g')
ServiceDir="/etc/systemd/system"
Service="secureknockd.service"
ServiceFilePath="$ServiceDir/$Service"

# Setup User
# Check if user exists on this system (either as user or a group)
if [[ $(egrep $RunAsUser /etc/passwd 2>/dev/null) ]]
then
	:
elif [[ $(egrep $RunAsUser /etc/group 2>/dev/null) ]]
then
	:
else
	# Add the user
	useradd --system --shell /usr/sbin/nologin -U $RunAsUser 
	echo "[+] User $RunAsUser successfully created"
	# Change password for user
	echo "  [*] Please enter the password for the new user. This will be used for sudo escalation only, not for login."
	echo "  [*] This is needed for the client knock packet (so remember it, or copy it somewhere safe)."
	passwd $RunAsUser 
	echo "[+] Password for user $RunAsUser successfully changed"
fi

# Extract embedded
PAYLOAD_LINE=$(awk '/^__PAYLOAD_BEGINS__/ { print NR + 1; exit 0; }' $0)
executableDirs=$(dirname $executablePath 2>/dev/null)
mkdir -p $executableDirs 2>/dev/null
tail -n +${PAYLOAD_LINE} $0 | base64 -d | tar -zpvx -C $executableDirs
chown $RunAsUser:$RunAsUser $executablePath
chmod 755 $executablePath
echo "[+] Successfully extracted binary"

# Run binary to create new key
newKey=$("$executablePath" --generate-key)
encryptionKey=$(echo $newKey | cut -d" " -f4)

# Put config in etc - placeholder defaults for values
cat > "$configFilePath" <<EOF
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
    {"dothing1": ["echo firstcmd", "echo secondcmd"]},
    {"dothing2": ["echo firstcmd2", "echo secondcmd2"]}
  ]
}
EOF
chown root:$RunAsUser $configFilePath
chmod 640 $configFilePath
echo "[+] Successfully installed config to $configFilePath"

# Add Sudo Permissions
if ! [[ $(grep -q $RunAsUser /etc/sudoers) ]]
then
  cat > /etc/sudoers <<EOF

# User for SecureKnockd
$RunAsUser ALL=(root:root) ALL
EOF
  echo "[+] Sudo permissions added to user $RunAsUser"
fi

# If apparmor dir exists (assuming apparmor is installed)
if [[ -d "/etc/apparmor.d" ]]
then
	cat > "$ApparmorProfilePath" <<EOF
### Apparmor Profile for the SecureKnock Server
## This is a very locked down profile made for Debian systems
## Variables
@{exelocation}=$executablePath
@{configlocation}=$configFilePath
@{logfilelocation}=$DaemonLogFile
@{profilelocation}=/etc/apparmor.d/usr.local.bin.secureknockd
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
  owner @{logfilelocation} rw,
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
EOF
	#
	apparmor_parser -r $ApparmorProfilePath
	#
	echo "[+] Apparmor profile installed - don't forget to tweak it for your specific action commands"
fi

# If service already exists, stop to allow new install over existing
if [[ -f $ServiceFilePath ]]
then
	systemctl stop $Service
fi

# Setup Systemd Service
if [[ -d $ServiceDir ]]
then
  cat > "$ServiceFilePath" <<EOF
[Unit]
Description=Secure Knock Daemon
After=network.target
StartLimitIntervalSec=1h
StartLimitBurst=6

[Service]
StandardOutput=journal
StandardError=journal
ExecStart=$executablePath --start-server --config $configFilePath
User=$RunAsUser
Group=$RunAsUser
Type=simple
RestartSec=1min
Restart=always

[Install]
WantedBy=multi-user.target
EOF
  # reload units and enable
  systemctl daemon-reload
  systemctl enable $Service
  systemctl start $Service
  echo "[+] Systemd service installed, enabled and started"
fi

echo "==== Finished Installation ===="
echo "[+] Don't forget to tweak the capture filter in the config to meet your requirements"
echo ""
exit 0

# SecureKnockd Binary Embed #
__PAYLOAD_BEGINS__
