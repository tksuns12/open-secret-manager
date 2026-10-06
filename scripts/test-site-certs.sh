#!/bin/sh
# Makes, once, the certificates of the phone tests' test site in a folder
# kept between runs: a certificate authority made for these tests only
# (ca.crt; its key is deleted once it has signed) and the site's
# certificate for login.osm.test and localhost (site.crt, site.key).
# Prints "made" when it made them, so the caller can say what to install.
#
#   scripts/test-site-certs.sh <folder>
set -eu
keep=$1
[ -f "$keep/ca.crt" ] && [ -f "$keep/site.crt" ] && exit 0
mkdir -p "$keep"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$keep/ca.key" -out "$keep/ca.crt" -days 365 \
    -subj "/CN=Open Secret Manager phone test CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$keep/site.key" -out "$keep/site.csr" \
    -subj "/CN=login.osm.test" 2>/dev/null
printf 'subjectAltName=DNS:login.osm.test,DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' >"$keep/site.ext"
openssl x509 -req -in "$keep/site.csr" -CA "$keep/ca.crt" -CAkey "$keep/ca.key" -CAcreateserial \
    -out "$keep/site.crt" -days 365 -extfile "$keep/site.ext" 2>/dev/null
rm -f "$keep/ca.key" "$keep/site.csr"
echo made
