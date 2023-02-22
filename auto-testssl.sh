#!/bin/bash

# create host file in the format of host:port one per line
# Read the file line by line
while IFS= read -r line
do
    # Get the host and port
    host=$(echo $line | cut -d':' -f1)
    port=$(echo $line | cut -d':' -f2)

    # Run testssl.sh
    /<PATH_TO_TESTSSL>./testssl.sh -e -p -U -S -P -f --warnings=batch --quiet --append --logfile="$host.txt" $host:$port
done < "hosts.txt"
