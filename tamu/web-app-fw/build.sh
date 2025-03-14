#!/bin/sh
set -e

set -x
sudo apt-get update
sudo apt-get install -y curl gcc make g++ libevent-dev perl asciinema mpv
set +x

# Join long lines
mv haproxy_conf/haproxy.cfg haproxy_conf/haproxy.cfg.bak
perl -pe '$_.=<>,s/\n// while /JOINNEXTLINE$/' web-app-fw/haproxy_conf/haproxy.cfg.bak > haproxy_conf/haproxy.cfg

DOWNLOAD="curl -L"

CWD=$(pwd)

HAPROXY_MAJOR_VERSION="3.1"
HAPROXY_MINOR_VERSION="2"
PCRE2_VERSION="10.44"
OPENSSL_VERSION="3.4.0"
ZLIB_VERSION="1.3.1"
LUA_VERSION="5.4.7"
DARKHTTPD_VERSION="1.16"
MODSECURITY_VERSION="3.0.13"
CORERULESET_VERSION="4.10.0"


HAPROXY_VERSION="${HAPROXY_MAJOR_VERSION}.${HAPROXY_MINOR_VERSION}"
HAPROXY_FILE="haproxy-${HAPROXY_VERSION}.tar.gz"
HAPROXY_LINK="https://www.haproxy.org/download/${HAPROXY_MAJOR_VERSION}/src/${HAPROXY_FILE}"
HAPROXY_OUT="$CWD/build/haproxy"

PCRE2_FILE="pcre2-${PCRE2_VERSION}.tar.gz"
PCRE2_LINK="https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VERSION}/${PCRE2_FILE}"
PCRE2_OUT="$CWD/build/pcre"

OPENSSL_FILE="openssl-${OPENSSL_VERSION}.tar.gz"
OPENSSL_LINK="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/${OPENSSL_FILE}"
OPENSSL_OUT="$CWD/build/openssl"

ZLIB_FILE="zlib-${ZLIB_VERSION}.tar.gz"
ZLIB_LINK="https://github.com/madler/zlib/releases/download/v${ZLIB_VERSION}/${ZLIB_FILE}"
ZLIB_OUT="$CWD/build/zlib"

LUA_FILE="lua-${LUA_VERSION}.tar.gz"
LUA_LINK="https://www.lua.org/ftp/${LUA_FILE}"
LUA_OUT="$CWD/build/lua"

JA3N_FILE="ja3n.lua"
JA3N_LINK="https://raw.githubusercontent.com/O-X-L/haproxy-ja3n/refs/heads/latest/ja3n.lua"

JA4_FILE="ja4.zip"
JA4_LINK="https://github.com/O-X-L/haproxy-ja4/archive/refs/heads/latest.zip"
JA4DB_FILE="ja4db.json"
JA4DB_LINK="https://ja4db.com/api/read/"
JA4_OUT="$CWD/build/ja4"

DARKHTTPD_FILE="darkhttpd-v${VERSION}.tar.gz"
DARKHTTPD_LINK="https://github.com/emikulic/darkhttpd/archive/refs/tags/v1.16.tar.gz"
DARKHTTPD_OUT="$CWD/build/darkhttpd"

MODSECURITY_FILE="modsecurity-v${MODSECURITY_VERSION}.tar.gz"
MODSECURITY_LINK="https://github.com/owasp-modsecurity/ModSecurity/releases/download/v${MODSECURITY_VERSION}/${MODSECURITY_FILE}"
MODSECURITY_OUT="$CWD/build/modsecurity"

CORERULESET_FILE="coreruleset-${CORERULESET_VERSION}-minimal.tar.gz"
CORERULESET_LINK="https://github.com/coreruleset/coreruleset/releases/download/v${CORERULESET_VERSION}/${CORERULESET_FILE}"
CORERULESET_OUT="$CWD/build/coreruleset"

SPOA_FILE="spoa-modsecurity.zip"
SPOA_LINK="https://github.com/FireBurn/spoa-modsecurity/archive/refs/heads/master.zip"
SPOA_OUT="$CWD/build/spoa-modsecurity"

mkdir -p tarballs sources build

cd tarballs

printf "Downloading openssl\n"
if ! [ -f "$OPENSSL_FILE" ]; then
    $DOWNLOAD "$OPENSSL_LINK" -o "$OPENSSL_FILE"
fi
printf "Downloading pcre2\n"
if ! [ -f "$PCRE2_FILE" ]; then
    $DOWNLOAD "$PCRE2_LINK" -o "$PCRE2_FILE"
fi
printf "Downloading zlib\n"
if ! [ -f "$ZLIB_FILE" ]; then
    $DOWNLOAD "$ZLIB_LINK" -o "$ZLIB_FILE"
fi
printf "Downloading lua\n"
if ! [ -f "$LUA_FILE" ]; then
    $DOWNLOAD "$LUA_LINK" -o "$LUA_FILE"
fi
printf "Downloading haproxy\n"
if ! [ -f "$HAPROXY_FILE" ]; then
    $DOWNLOAD "$HAPROXY_LINK" -o "$HAPROXY_FILE"
fi
printf "Downloading haproxy-ja4\n"
if ! [ -f "$JA4_FILE" ]; then
    $DOWNLOAD "$JA4_LINK" -o "$JA4_FILE"
fi
printf "Downloading darkhttpd\n"
if ! [ -f "$DARKHTTPD_FILE" ]; then
    $DOWNLOAD "$DARKHTTPD_LINK" -o "$DARKHTTPD_FILE"
fi
printf "Downloading modsecurity\n"
if ! [ -f "$MODSECURITY_FILE" ]; then
    $DOWNLOAD "$MODSECURITY_LINK" -o "$MODSECURITY_FILE"
fi
printf "Downloading modsecurity coreruleset\n"
if ! [ -f "$CORERULESET_FILE" ]; then
    $DOWNLOAD "$CORERULESET_LINK" -o "$CORERULESET_FILE"
fi
printf "Downloading spoa-modsecurity\n"
if ! [ -f "$SPOA_FILE" ]; then
    $DOWNLOAD "$SPOA_LINK" -o "$SPOA_FILE"
fi

cd ..

cd sources

printf "Extracting openssl\n"
tar -xf "../tarballs/${OPENSSL_FILE}"
printf "Extracting pcre2\n"
tar -xf "../tarballs/${PCRE2_FILE}"
printf "Extracting zlib\n"
tar -xf "../tarballs/${ZLIB_FILE}"
printf "Extracting lua\n"
tar -xf "../tarballs/${LUA_FILE}"
printf "Extracting haproxy\n"
tar -xf "../tarballs/${HAPROXY_FILE}"
printf "Extracting darkhttpd\n"
tar -xf "../tarballs/${DARKHTTPD_FILE}"
printf "Extracting modsecurity\n"
tar -xf "../tarballs/${MODSECURITY_FILE}"
printf "Extracting modsecurity coreruleset\n"
tar -xf "../tarballs/${CORERULESET_FILE}"
printf "Extracting spoa-modsecurity\n"
unzip "../tarballs/${SPOA_FILE}"
printf "Extracting haproxy-ja4\n"
unzip "../tarballs/${JA4_FILE}"


NPROC=$(nproc)

# Build openssl
cd "openssl-${OPENSSL_VERSION}"
mkdir -p "$OPENSSL_OUT"
./config --prefix="$OPENSSL_OUT" no-shared no-tests
make -j "$NPROC"
make install_sw
cd ..

# Build pcre2
cd "pcre2-${PCRE2_VERSION}"
mkdir -p "$PCRE2_OUT"
CFLAGS='-O2' ./configure --prefix="$PCRE2_OUT" --disable-shared --enable-jit
make -j "$NPROC"
make install
cd ..

# Build zlib
cd "zlib-${ZLIB_VERSION}"
mkdir -p "$ZLIB_OUT"
./configure --static --prefix="$ZLIB_OUT"
make -j "$NPROC"
make install
cd ..

# Build lua
cd "lua-${LUA_VERSION}"
mkdir -p "$LUA_OUT"
make -j "$NPROC"
make all install INSTALL_TOP="$LUA_OUT"
cd ..

# Build darkhttpd
cd "darkhttpd-${DARKHTTPD_VERSION}"
mkdir -p "$DARKHTTPD_OUT"
make -j "$NPROC" darkhttpd-static
cp darkhttpd-static "${DARKHTTPD_OUT}/darkhttpd"
cd ..

# Build modsecurity
cd "modsecurity-v${MODSECURITY_VERSION}"
mkdir -p "$MODSECURITY_OUT"
./configure --prefix="$MODSECURITY_OUT" --without-lua --without-geoip --without-maxmind --with-pcre2="$PCRE2_OUT"
make -j "$NPROC" 
make install
cd ..

# Combine coreruleset to single file
cd "coreruleset-${CORERULESET_VERSION}"
mkdir -p "$CORERULESET_OUT"
cp "../modsecurity-v${MODSECURITY_VERSION}/modsecurity.conf-recommended" modsecurity.conf
cp "../modsecurity-v${MODSECURITY_VERSION}/unicode.mapping" unicode.mapping
cat crs-setup.conf.example >> modsecurity.conf
sed -i 's/SecRuleEngine .*/SecRuleEngine On/' modsecurity.conf
sed -i 's/\(SecDefaultAction "phase:[12]\),log,auditlog,pass"/\1,log,auditlog,deny,status:403/' modsecurity.conf
sed -i 's/^\(http:\/\/127.0.0.1\|http:\/\/localhost\)$/#\1/' rules/ssrf.data
find . -type f -name "*.conf" | grep -v -e "./modsecurity.conf" -e "./plugins" | sort | sed 's/^/Include /' >> modsecurity.conf
cp -r modsecurity.conf unicode.mapping rules "${CORERULESET_OUT}"
cd ..


# Build spoa-modsecurity
cd "spoa-modsecurity-master"
mkdir -p "${SPOA_OUT}/bin"
make -j "$NPROC" MODSEC_INC="${MODSECURITY_OUT}/include" MODSEC_LIB="${MODSECURITY_OUT}/lib"
make install PREFIX="$SPOA_OUT"
cd ..

# Build haproxy
cd "haproxy-${HAPROXY_VERSION}"
mkdir -p "$HAPROXY_OUT"
make -j "$NPROC" TARGET=linux-glibc-legacy \
	USE_TFO=1 USE_LINUX_TPROXY=1 USE_GETADDRINFO=1 \
	USE_OPENSSL=1 SSL_INC="${OPENSSL_OUT}/include" SSL_LIB="${OPENSSL_OUT}/lib64" \
	USE_STATIC_PCRE2=1 PCRE2_INC="${PCRE2_OUT}/include" PCRE2_LIB="${PCRE2_OUT}/lib" \
	USE_ZLIB=1 ZLIB_INC="${ZLIB_OUT}/include" ZLIB_LIB="${ZLIB_OUT}/lib" \
	USE_LUA=1 LUA_INC="${LUA_OUT}/include" LUA_LIB="${LUA_OUT}/lib"
make install DESTDIR="$HAPROXY_OUT" PREFIX=""
cd ..

# Update JA4 fingerprint map file
printf "Downloading updated JA4 fingerprints\n"
cd "haproxy-ja4-latest"
mkdir -p "$JA4_OUT"
if ! [ -f "$JA4DB_FILE" ]; then
    $DOWNLOAD "$JA4DB_LINK" -o "$JA4DB_FILE"
fi
python3 ja4db-dedupe.py
python3 ja4db-to-map.py
cp ja4.map "${JA4_OUT}/ja4_names.map"
cp ja4.lua "$JA4_OUT"
cd ..

cd ..

# Default page for a blocked request will show a random GIF or video
printf "Downloading videos\n"
mkdir -p build/videos
cp video_scripts/add_video.sh video_scripts/get_videos.sh build/videos
chmod u+x build/videos/*
cd build/videos
./get_videos.sh
cd ../..

printf "Creating distribution in ./dist\n"
mkdir -p dist/haproxy dist/darkhttpd dist/modsecurity
cp services/*.service dist/

cp "${HAPROXY_OUT}/sbin/haproxy" dist/haproxy
chmod 655 dist/haproxy/haproxy
cp "${JA4_OUT}/ja4.lua" "${JA4_OUT}/ja4_names.map" dist/haproxy
printf 'd00i000000_74c887e210ea_8e2f6cc4d42a not_encrypted\n' >> dist/haproxy/ja4_names.map
cp haproxy_conf/* dist/haproxy/
touch dist/haproxy/ja4_block.map dist/haproxy/ja4_allow.map dist/haproxy/ip_block.map dist/haproxy/ip_allow.map

cp "${DARKHTTPD_OUT}/darkhttpd" dist/darkhttpd/
chmod 655 dist/darkhttpd/darkhttpd
cp -r build/videos/srv dist/darkhttpd/

cp "${MODSECURITY_OUT}/lib/libmodsecurity.so" dist/modsecurity
cp "${SPOA_OUT}/bin/modsecurity" dist/modsecurity/modsecurity
chmod 655 dist/modsecurity/modsecurity
cp -r "${CORERULESET_OUT}/modsecurity.conf" "${CORERULESET_OUT}/unicode.mapping" "${CORERULESET_OUT}/rules" dist/modsecurity
touch dist/modsecurity/audit.log

cp build/videos/videos.bin dist/

chmod -R +r dist/

printf "Creating test certificate\n"
openssl req -x509 -newkey rsa:4096 -sha256 -nodes -subj "/CN=Some Name" -addext "subjectAltName = DNS:localhost,IP:127.0.0.1" -keyout server.key -out server.crt -days 30
cat server.key server.crt > dist/haproxy/server.pem
chmod 600 dist/haproxy/server.pem

cat <<-"EOF" > dist/install.sh
	#!/bin/sh
	if ! [ "$UID" != "0" ]; then
	    printf "Script must be run as root\n"
        exit
	fi
	set -x
	useradd waf_user || true
	chsh -s /bin/false waf_user
	mkdir -p /opt/waf_configs/
	cp -r * /opt/waf_configs/
	chown waf_user:root /opt/waf_configs/modsecurity/audit.log
	chown waf_user:root /opt/waf_configs/haproxy/server.pem
	ln -s /opt/waf_configs/*.service /etc/systemd/system/
	systemctl daemon-reload
	systemctl enable waf.service waf_haproxy.service waf_modsecurity.service waf_darkhttpd.service
	systemctl start waf.service
	set +x

	printf "\n"
	printf "Start the WAF with 'systemctl start waf.service'\n"
	printf "Get status with 'systemctl status waf*'\n"
	printf "Edit '/opt/waf_configs/haproxy.cfg' to change configuration settings for the proxy\n"
	printf "  and edit the sandbox service file at '/opt/waf_configs/waf_haproxy.service'\n"
	printf "Block JA4 hashes by appending to '/opt/waf_configs/haproxy/ja4_block.map', then\n"
	printf "  run 'systemctl reload waf_haproxy'.\n"
	printf "  The inode of the file **must not change**, so append with '>>' or configure\n"
	printf "  your editor to overwrite the file directly (e.g. ':set backupcopy=yes' in vim)\n"
	EOF
chmod +x dist/install.sh
tar -cf dist.tar dist

printf "Copy 'dist.tar' to machine, extract, then install with 'dist/install.sh'\n"
