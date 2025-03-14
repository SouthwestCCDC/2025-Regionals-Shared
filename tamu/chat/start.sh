#!/bin/sh
set -e

openssl req -x509 -newkey rsa:4096 -keyout ngircd.key -out ngircd.crt -sha256 -days 14 -nodes -subj "/CN=chat.local"
openssl req -x509 -newkey rsa:4096 -keyout nginx.key -out nginx.crt -sha256 -days 14 -nodes -subj "/CN=chat.local"
cat ngircd.key ngircd.crt > ngircd.pem
docker-compose up -d
docker exec --user node -it thelounge thelounge add admin
