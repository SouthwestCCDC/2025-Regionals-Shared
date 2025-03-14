#!/bin/sh
set -e

tmux_notify_channel="$1"
machine_nickname="$2"

trap "tmux wait-for -S \"$tmux_notify_channel\"" EXIT

script_sh="command -v sudo >/dev/null || { command -v doas >/dev/null && alias sudo=doas ; }
sudo sh -c '
COLOR_RED=\"\\033[0;91m\"
COLOR_NONE=\"\\033[0m\"

gtfobins_suid=\"aa-exec ab agetty alpine ar arj arp as ascii-xfr ash aspell atobm
awk base32 base64 basenc basez bash bc bridge busctl busybox bzip2 cabal capsh
cat chmod choom chown chroot clamscan cmp column comm cp cpio cpulimit csh csplit
csvtool cupsfilter curl cut dash date dd debugfs dialog diff dig distcc dmsetup
docker dosbox ed efax elvish emacs env eqn espeak expandexpect file find fish
flock fmt fold gawk gcore gdb genie genisoimage gimp grep gtester gzip hd head
hexdump highlight hping3 iconv install ionice ip ispell jjs join jq jrunscript
julia ksh ksshell kubectl ld.so less links logsave look lua make mawk minicom more
mosquitto msgattrib msgcat msgconv msgfilter msgmerge msguniq multitime mv nasm
nawk ncftp nft nice nl nm nmap node nohup ntpdate od openssl openvpn pandoc paste
perf perl pexec pg php pidstat pr ptx python rc readelf restic rev rlwrap rsync
rtorrent run-parts rview rvim sash scanmem sed setarch setfacl setlock shuf soelim
softlimit sort sqlite3 ss ssh-agent ssh-keygen ssh-keyscan sshpass
start-stop-daemon stdbuf strace strings sysctl systemctl tac tail taskset tbl
tclsh tee terraform tftp tic time timeout troff ul unexpand uniq unshare
unsquashfs unzip update-alternatives uudecode uuencode vagrant varnishncsa view
vigr vim vimdiff vipw w3m watch wc wget whiptail xargs xdotool xmodmap xmore xxd
xz yash zsh zsoelim\"

files_suid_sgid=\$(find / -type f -perm -2000 -o -perm -4000  2>/dev/null)

for bin in \$files_suid_sgid; do
    binname=\$(basename \"\$bin\")
    for gtfobin in \$gtfobins_suid; do
        if [ \"\$binname\" = \"\$gtfobin\" ]; then
            printf \"%b%s%b\n\" \"\$COLOR_RED\" \"\$(ls -l \"\$bin\")\" \"\$COLOR_NONE\"
            continue 2
        fi
    done
    printf \"%s\n\" \"\$(ls -l \"\$bin\")\"
done
'"

printf "Listing suid and sgid binaries\n"
printf "%s" "$script_sh" | ssh "$machine_nickname" /bin/sh -s
