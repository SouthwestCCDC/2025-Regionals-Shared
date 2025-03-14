#!/bin/sh

# This script downloads multiple GIFs or videos and creates:
# - a static html page with javascript to fetch a random GIF
# - a standalone binary to play a random GIF in a terminal

set -e

curl -o coconut.gif 'https://c.tenor.com/ea9gIvewA2oAAAAM/coconut-coconut-malled.gif'
curl -o hackerman.gif 'https://media1.tenor.com/m/TbTe1Nc6j34AAAAd/hacker-hackerman.gif'
curl -o impossible.gif 'https://media.tenor.com/hxMGZ9vJQ-4AAAAC/mission-impossible.gif'
curl -o magic.gif 'https://media.tenor.com/Vyg73kR334sAAAAC/jurassic-park-ah.gif'
curl -o not_the_droids.gif 'https://i.makeagif.com/media/2-17-2017/r6MOA3.gif'
curl -o objection.gif 'https://gifdb.com/images/thumbnail/phoenix-wright-ace-attorney-objection-dotejtyisfqmel3b.gif'
curl -o rick_roll.gif 'https://media1.tenor.com/images/467d353f7e2d43563ce13fddbb213709/tenor.gif?itemid=12136175'
curl -o none_shall_pass.gif 'https://pa1.narvii.com/6261/0816e78b5fe4172d32420f0531c01e773998cd25_hq.gif'
curl -o shall_not_pass.gif 'https://media1.tenor.com/images/d23c20302e1d7d01bb8ec3b29c747583/tenor.gif?itemid=12019193'


# Convert to asciinema recording and C headers
./add_video.sh coconut.gif coconut
./add_video.sh hackerman.gif hackerman
./add_video.sh impossible.gif impossible
./add_video.sh magic.gif magic
./add_video.sh not_the_droids.gif not_the_droids
./add_video.sh objection.gif objection
./add_video.sh rick_roll.gif rick_roll
./add_video.sh none_shall_pass.gif none_shall_pass
./add_video.sh shall_not_pass.gif shall_not_pass

mkdir -p srv
cp *.gif srv/

cat <<EOF > srv/index.html
<!DOCTYPE html>
<html>
<style>body { background-color: #121314 }</style>
<body>
<img src="./shall_not_pass.gif" name="gif" style="width: 100%; height: 100%"></div>
<script>let gifs = ['/coconut.gif', 'hackerman.gif', 'impossible.gif', 'magic.gif', 'not_the_droids.gif', 'objection.gif', 'rick_roll.gif', 'none_shall_pass.gif', 'shall_not_pass.gif'];
let l = Math.floor(Math.random() * gifs.length);
document.gif.src = gifs[l];</script>
</body>
</html>
EOF


# Creates a binary that displays a random GIF or videas using terminal escape
# codes. Could be used as the login shell for a joke user :)
cat <<EOF > videos.c
#include <time.h>
#include <stdlib.h>

#include "coconut.h"
#include "hackerman.h"
#include "impossible.h"
#include "magic.h"
#include "not_the_droids.h"
#include "objection.h"
#include "rick_roll.h"
#include "none_shall_pass.h"
#include "shall_not_pass.h"

int main(void) {
    srand(time(NULL));
    switch (rand() % 9) {
        case 0:
            coconut_();
            break;
        case 1:
            hackerman_();
            break;
        case 2:
            impossible_();
            break;
        case 3:
            magic_();
            break;
        case 4:
            none_shall_pass_();
            break;
        case 5:
            not_the_droids_();
            break;
        case 6:
            objection_();
            break;
        case 7:
            rick_roll_();
            break;
        case 8:
        default:
            shall_not_pass_();
            break;
    }
    return 0;
}
EOF

gcc videos.c -o videos.bin
