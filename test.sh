#!/usr/bin/env bash

executable="./build/stun"

while IFS=: read -r addr port; do
    printf "%-20s ... " "$addr $port"
    err_out=$($executable $addr $port 2>&1 1>/dev/null)
    status=$?
    if [[ $status -eq 0 ]]; then
        printf "\033[42mpassed\033[0m\n"
    else
        printf "\033[41mfailed\033[0m\n"
        echo "--------------------------------"
        printf "    exit status: %d\n" $status
        if [[ -n "$err_out" ]]; then
            echo "$err_out" | sed 's/^/    /' >&2
        fi
        echo "--------------------------------"
    fi
done < "valid_ipv4s.txt"
