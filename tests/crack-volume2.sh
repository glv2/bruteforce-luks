#!/bin/sh

set -e
BRUTEFORCE_LUKS=../bruteforce-luks

echo "Bruteforce LUKS2-PBKDF2 volume"
PASSWORD=$(${BRUTEFORCE_LUKS} -t 4 -f dict.txt volume2-header \
               | grep "Password found" \
               | cut -b 17-)

if [ "${PASSWORD}" = "Martin" ];
then
    echo "SUCCESS (Password: ${PASSWORD})"
    exit 0
else
    echo "FAILURE"
    exit 1
fi
