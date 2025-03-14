#!/bin/bash
# https://www.ssh-audit.com/hardening_guides.htm
# to add
    # PermitRootLogin no
    # AllowUsers user1 user2
    # Protocol 2 or check for existence of protocol 1
    #    ssh -1 user@remote_server
    # Fail2Ban
    # PasswordAuthentication no
    # "PubkeyAuthentication yes" "
    # "LogLevel VERBOSE" "$SSHD_CONFIG"
    # netstat -tuln
    # sshd -t
    # print out all auth keys


# Pretty Colors
BOLD="\e[1m"
RED="\e[31m"
GREEN="\e[32m"
RESET="\e[0m"

BOLD_RED="${BOLD}${RED}"
BOLD_GREEN="${BOLD}${GREEN}"

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${BOLD_RED}Root/Sudo required to run.${RESET}"
    exit 1
fi


# get_distro_info
#
# Output:
#   - Prints the distribution name and version in the format: "Distribution: <name> <version>"
# Returns:
#   - Returns the distribution name as DISTRO_NAME and the version as DISTRO_VERSION 
get_distro_info() {
    if command -v lsb_release &> /dev/null; then
        DISTRO_NAME=$(lsb_release -si)
        DISTRO_VERSION=$(lsb_release -sr)
    elif [ -f /etc/redhat-release ]; then
        DISTRO_NAME=$(awk '{print $1}' /etc/redhat-release)
        DISTRO_VERSION=$(awk '{print $4}' /etc/redhat-release)
    elif [ -f /etc/debian_version ]; then
        DISTRO_NAME="Debian"
        DISTRO_VERSION=$(cat /etc/debian_version)
    elif [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_NAME="$NAME"
        DISTRO_VERSION="$VERSION_ID"
    else
        echo "Unable to determine the distribution."
        exit 1
    fi

    echo "Distribution: $DISTRO_NAME $DISTRO_VERSION"
}

check_ubuntu() {
    if [[ "$DISTRO_NAME" != "Ubuntu" ]]; then
        echo "This system is NOT Ubuntu. Use appropriate script or suffer."
        exit 1
    fi
}

confirm_modification() {
    echo -e "${BOLD_RED}WARNING: This script will modify your SSH configuration!${RESET}"
    read -p "Do you want to continue? (y/n) " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Proceeding with the script..."
    else
        echo -e "${BOLD_RED}Script aborted by user.${RESET}"
        exit 1
    fi
}

check_for_existing_conf() {
    if [ -f "$HARDENING_CONF" ]; then
        echo -e "${BOLD_RED}Conflict: ssh-audit_hardening.conf already exists. Did someone run this already?${RESET}"
        exit 1
    fi
}

# Backup and generate new server host keys
backup_and_generate_keys() {
    mkdir /etc/ssh/backup
    mv -f /etc/ssh/ssh_host_* /etc/ssh/backup/
    cp "$SSHD_CONFIG" "$SSHD_CONFIG.bak"

    echo -e "${BOLD_GREEN}> Backed up server keys.${RESET}"

    # Remove existing SSH host keys
    rm -f /etc/ssh/ssh_host_

    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
    ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""

    echo -e "${BOLD_GREEN}> Created new server keys.${RESET}"
}

add_to_file() {
    local string="$1"
    local file="$2"

    # Escape special characters in the string
    local escaped_string=$(echo "$1" | sed 's/[\/&]/\\&/g')

    # Use sed to uncomment the line
    sed -i "s/^# *${escaped_string}$/${escaped_string}/g" "$file"

    if ! grep -q "^${string}" "$file"; then
        echo -e "${string}\n" >> "$file"
    fi
}

check_for_insecure_key_perms() {
    if grep -q "^HostKey /etc/ssh/ssh_host_dsa_key" "$SSHD_CONFIG"; then
        echo -e "${BOLD_RED}HostKey /etc/ssh/ssh_host_dsa_key present in config. Remove if possible.${RESET}"
    fi
    if grep -q "^HostKey /etc/ssh/ssh_host_ecdsa_key" "$SSHD_CONFIG"; then
        echo -e "${BOLD_RED}HostKey /etc/ssh/ssh_host_ecdsa_key present in config. Remove if possible.${RESET}"
    fi
}

update_moduli_file() {
    cp /etc/ssh/moduli /etc/ssh/moduli.bak
    awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
    mv /etc/ssh/moduli.safe /etc/ssh/moduli
    echo -e "${BOLD_GREEN}> Adjusted DH moduli.${RESET}"
}

print_next_steps() {
    echo -e "${BOLD_RED}> Attention! Next Steps: \n\tSet up firewall\n\tRestart ssh\n\tConfirm connections\n\tAudit Keys\n${RESET}"
}

retrieve_in_use_algos() {
    SEARCH_PATHS=("/home" "/root")
    KEY_TYPES=$(find "${SEARCH_PATHS[@]}" -name authorized_keys -type f -exec cat {} \; | grep -v '^$' | awk '{print $1}' | sort | uniq)

    declare -A KEY_TYPE_MAP=(
        ["ssh-rsa"]="rsa-sha2-512,rsa-sha2-256"
        ["ssh-ed25519"]="ssh-ed25519"
        ["ecdsa-sha2-nistp256"]="ecdsa-sha2-nistp256"
        ["ecdsa-sha2-nistp384"]="ecdsa-sha2-nistp384"
        ["ecdsa-sha2-nistp521"]="ecdsa-sha2-nistp521"
    )

}

configure_ssh_hardening() {
    if [[ "$DISTRO_VERSION" == "24.04" ]]; then ###################### Ubuntu 24.04
        HARDENING_CONFIG=$(cat <<EOF
KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,gss-group16-sha512-,diffie-hellman-group16-sha512

Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr

MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-

HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

EOF
)

        HOSTKEY_ALGORITHMS=$(cat <<EOF

HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

EOF
)

        PUBKEY_ALGORITHMS=$(cat <<EOF

PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

EOF
)
    ####################################################################
    elif [[ "$DISTRO_VERSION" == "22.04" ]]; then ###################### Ubuntu 22.04

        HARDENING_CONFIG=$(cat <<EOF
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr

MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com

CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-

HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256

EOF
)

        HOSTKEY_ALGORITHMS=$(cat <<EOF

HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

EOF
)

        PUBKEY_ALGORITHMS=$(cat <<EOF

PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256

EOF
)

    ####################################################################
    elif [[ "$DISTRO_VERSION" == "20.04" ]]; then ###################### Ubuntu 20.04

        HARDENING_CONFIG=$(cat <<EOF
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com

EOF
)

        HOSTKEY_ALGORITHMS=$(cat <<EOF

HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com

EOF
)

        PUBKEY_ALGORITHMS=""

    ####################################################################
    elif [[ "$DISTRO_VERSION" == "18.04" ]]; then ###################### Ubuntu 18.04

        HARDENING_CONFIG=$(cat <<EOF
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com
EOF
)

        HOSTKEY_ALGORITHMS=$(cat <<EOF

HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com

EOF
)

        PUBKEY_ALGORITHMS=""

    ####################################################################
    elif [[ "$DISTRO_VERSION" == "16.04" ]]; then ###################### Ubuntu 16.04

        HARDENING_CONFIG=$(cat <<EOF
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256

Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com

EOF
)

        HOSTKEY_ALGORITHMS=""

        PUBKEY_ALGORITHMS=""


    else
        echo "Unsupported distribution version. Look at Ubuntu hardening in guides."
        print_next_steps
        exit 1
    fi


}


add_algos_to_config() {
    for key_type in $KEY_TYPES; do
        ALGO="${KEY_TYPE_MAP[$key_type]}"

        if [[ -n $ALGO ]]; then

            # If algo isn't in config add it
            if ! echo "$HOSTKEY_ALGORITHMS" | grep "HostKeyAlgorithms" | grep -q -i "${ALGO}"; then
                echo -e "${BOLD_RED}Adding '${KEY_TYPE_MAP[$key_type]} to HostKeyAlgorithms. You should audit this.${RESET}"
                HOSTKEY_ALGORITHMS+="${ALGO},"
            fi

            # If algo isn't in config add it
            if ! echo "$PUBKEY_ALGORITHMS" | grep "PubkeyAcceptedAlgorithms" | grep -q -i "${ALGO}"; then
                echo -e "${BOLD_RED}Adding '${KEY_TYPE_MAP[$key_type]} to PubkeyAcceptedAlgorithms. You should audit this.${RESET}"
                PUBKEY_ALGORITHMS+="${ALGO},"
            fi

        fi

    done


    HOSTKEY_ALGORITHMS=${HOSTKEY_ALGORITHMS%,}
    PUBKEY_ALGORITHMS=${PUBKEY_ALGORITHMS%,}
}

### MAIN SCRIPT START
get_distro_info
check_ubuntu
confirm_modification

HARDENING_CONF="/etc/ssh/sshd_config.d/ssh-audit_hardening.conf"
SSHD_CONFIG="/etc/ssh/sshd_config"

check_for_existing_conf

echo -e "\n\n# Hardening Script Start\n" >> "$SSHD_CONFIG"
backup_and_generate_keys

add_to_file "HostKey /etc/ssh/ssh_host_ed25519_key" "$SSHD_CONFIG"
add_to_file "HostKey /etc/ssh/ssh_host_rsa_key" "$SSHD_CONFIG"

check_for_insecure_key_perms
update_moduli_file

# Harder daddy
retrieve_in_use_algos
configure_ssh_hardening

if [[ -z "$KEY_TYPES" ]]; then
    echo -e "${BOLD_GREEN}> No key types found in authorized_keys files.${RESET}"
else
    add_algos_to_config
fi


echo -e "$HARDENING_CONFIG\n$HOSTKEY_ALGORITHMS\n$PUBKEY_ALGORITHMS"  > test.conf

echo -e "${BOLD_GREEN}> Saved hardened config to: ${HARDENING_CONF}.${RESET}"

### Last echo
print_next_steps



