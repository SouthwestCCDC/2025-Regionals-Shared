#!/bin/sh
prompt_yn() {
    printf "%s [y/N]\n" "$1" >&2
    read -r promptmessage
    case "$promptmessage" in
        [yY]|[yY][eE][sS])
            printf "y"
            ;;
        *)
            printf "n"
            ;;
    esac
}

if [ "$(/usr/bin/id -u)" -ne 0 ]; then
    printf "Must run as root\n" >&2
    exit 1
fi

printf "What service do you want to sandbox?: "
read -r service

if command -v systemctl >/dev/null; then
    if systemctl list-unit-files "${service}.service" | grep "^0 unit files listed"; then
        printf "Systemd service not found\n"
        exit 1
    fi

    systemd_override_dir="/etc/systemd/system/${service}.service.d"
    systemd_override_conf="/etc/systemd/system/${service}.service.d/override.conf"

    if ! [ -e "$systemd_override_conf" ]; then
        mkdir -p "$systemd_override_dir"
        cp "profiles/generic-systemd.conf" "$systemd_override_conf"
    fi

else
    if ! [ -f "/etc/init.d/$service" ]; then
        printf "Init service not found\n"
        exit 1
    fi

    bwrap_script_dir="/usr/sbin"
    bwrap_script="/usr/sbin/${service}.bwrap"
    if ! [ -e "$bwrap_script" ]; then
        mkdir -p "$bwrap_script_dir"
        cp "profiles/generic-bwrap.sh" "$bwrap_script"
        chmod +s "$bwrap_script"
    fi
fi


while true; do
    if command -v systemctl >/dev/null; then
        systemctl edit "$service" || exit 1
    else
        vim "$bwrap_script" || exit 1
    fi

    restartservice=$(prompt_yn "Restart $service to test new sandbox config?")
    if [ "$restartservice" = "y" ]; then
        printf "Restarting service...\n"

        if command -v systemctl >/dev/null; then
            systemctl restart "$service" || { journalctl -eu "$service"; systemctl status "$service"; }
        else
            service "$service" restart
        fi

        if [ $? = 0 ]; then
            printf "%s successfully started (but could have failed after starting).\n" "$service"
            if command -v systemctl >/dev/null; then
                viewjournal=$(prompt_yn "View journalctl output?")
                if [ "$viewjournal" = "y" ]; then
                    journalctl -eu "$service"
                fi
            fi
        else
            printf "%s failed to start.\n" "$service"
        fi

        keepediting=$(prompt_yn "Keep editing the sandbox config?")
        if [ "$keepediting" = "y" ]; then
            continue
        else
            break
        fi
    else
        printf "Not restarting...\n"
        break
    fi
done

mkdir -p sandbox_configs

if [ -f "$systemd_override_conf" ]; then
    cp "$systemd_override_conf" "sandbox_configs/${service}.conf"
else
    cp "$bwrap_script" sandbox_configs/
fi
