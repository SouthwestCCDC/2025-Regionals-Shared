#!/bin/sh

# This script converts a GIF or video to an asciinema recording and creates
# a self-contained C header file that plays the video on repeat

set -e

help_text() {
    echo "Usage: $0 <video> <output_name> [<start_seconds> <end_seconds>]"
    exit
}

if [ -z "$1" ] || [ -z "$2" ] || ! [ -f "$1" ]; then
    help_text
fi
INFILE="$1"
OUTCAST="$2.cast"
OUTC="$2.h"

if ! command -v mpv && command -v asciinema; then
    echo "Missing dependencies"
    exit
fi

FLAGS="$INFILE --vo=tct --really-quiet"
if [ -n "$3" ]; then
    FLAGS="$FLAGS --start=$3"
fi
if [ -n "$4" ]; then
    FLAGS="$FLAGS --end=$4"
fi

stty rows 24 cols 80
asciinema rec "$OUTCAST" -c "mpv $FLAGS"

FNAME="$(echo "$2" | tr -c '[:alnum:]_' '_')"
echo "#include <stdio.h>\n#include <unistd.h>\n\nvoid ${FNAME}(void) {\nwhile(1) {" > "$OUTC"

asciinema cat "$OUTCAST" | sed 's/\(.*\)/printf\("%s", "\1"\);\nusleep\(100000\);/' | sed 's/.");/");/' >> "$OUTC"

echo "\n}\n}" >> "$OUTC"
