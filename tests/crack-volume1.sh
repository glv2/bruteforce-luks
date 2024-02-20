#!/bin/sh

set -e
BRUTEFORCE_LUKS=../bruteforce-luks

echo "Bruteforce LUKS1-PBKDF2 volume"
PASSWORD=$(${BRUTEFORCE_LUKS} -t 4 -l 5 -m 6 -b "Al" -e "ia" \
                              -s "abcdefghijklmnopqrstuvwxyz" volume1-header \
               | grep "Password found" \
               | cut -b 17-)

if [ "${PASSWORD}" = "Alexia" ];
then
    echo "SUCCESS (Password: ${PASSWORD})"
    exit 0
else
    echo "FAILURE"
    exit 1
fi
