#!/bin/sh

set -e
BRUTEFORCE_LUKS=../bruteforce-luks

echo "Bruteforce LUKS2-ARGON2 volume"
PASSWORD=$(${BRUTEFORCE_LUKS} -t 4 -l 4 -m 4 -b "Sa" \
                              -s "abcdefghijklmnopqrstuvwxyz" volume3-header \
               | grep "Password found" \
               | cut -b 17-)

if [ "${PASSWORD}" = "Sara" ];
then
    echo "SUCCESS (Password: ${PASSWORD})"
    exit 0
else
    echo "FAILURE"
    exit 1
fi
