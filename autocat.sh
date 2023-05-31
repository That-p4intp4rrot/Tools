#!/bin/bash

# Define the default values
NMAP_FILE=""
OUTPUT_FILE=""
LIVE_HOSTS_FILE="live_hosts.txt"

# Parse command-line arguments
while getopts ":n:o:h:" opt; do
  case $opt in
    n)
      NMAP_FILE=$OPTARG
      ;;
    o)
      OUTPUT_FILE=$OPTARG
      ;;
    h)
      LIVE_HOSTS_FILE=$OPTARG
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

# Check if the required options are provided
if [[ -z $NMAP_FILE || -z $OUTPUT_FILE ]]; then
    echo "Error: Missing required options." >&2
    echo "Usage: $0 -n <nmap results file> -o <output file> [-h <live hosts file>]" >&2
    exit 1
fi

# Check if the nmap scan results file exists
if [ ! -f "$NMAP_FILE" ]; then
    echo "Error: nmap scan results file not found!"
    exit 1
fi

# Check if the output file exists
if [ -f "$OUTPUT_FILE" ]; then
    echo "Error: output file already exists!"
    exit 1
fi

# Create the output file
touch "$OUTPUT_FILE"

# Extract the live hosts from the provided file or from the Nmap scan results
if [ -f "$LIVE_HOSTS_FILE" ]; then
    live_hosts=$(cat "$LIVE_HOSTS_FILE")
else
    live_hosts=$(grep -oP '(\d{1,3}\.){3}\d{1,3}' "$NMAP_FILE")
fi

# Loop through the live hosts
for host in $live_hosts; do
    # Extract the open ports for the current host
    open_ports=$(grep -E "^$host" "$NMAP_FILE" | awk '{print $1}')

    # Loop through the open ports
    for port in $open_ports; do
        # Connect to the host and port using netcat
        banner=$(nc -v -n -z -w 1 "$host" "$port")

        # Print the banner to the screen
        echo "Banner for $host:$port"
        echo "$banner"

        # Try some default commands
        default_commands=$(nc -v -n -z -w 1 "$host" "$port" <<< "help; exit")

        # Print the default commands to the screen
        echo "Default commands for $host:$port"
        echo "$default_commands"

        # Write the output to the output file
        echo "Banner for $host:$port" >> "$OUTPUT_FILE"
        echo "$banner" >> "$OUTPUT_FILE"
        echo "Default commands for $host:$port" >> "$OUTPUT_FILE"
        echo "$default_commands" >> "$OUTPUT_FILE"
    done
done

