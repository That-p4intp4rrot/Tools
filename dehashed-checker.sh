#!/bin/bash

## To run this script, save it to a file (e.g. dehashed_script.sh) and make it executable using chmod +x dehashed_script.sh. Then, you can pass the input file name as an argument when running the script, like so: ./dehashed_script.sh dom>
##Note that you'll need to have the jq command installed on your system for this script to work. You can install it using the following command:
##
## bash
## Copy code
## sudo apt install jq
## Also, you'll need to sign up for a DeHashed.com account and obtain an API key in order to use their API. Once you have an API key, you can enter it when prompted by the script.


# Check if input file exists
if [ ! -f "$1" ]; then
    echo "Usage: $0 <input_file>"
    exit 1
fi

# Define output file name
output_file="dehashed_results.txt"

# Remove output file if it already exists
if [ -f "$output_file" ]; then
    rm "$output_file"
fi

# Prompt user for DeHashed.com API credentials
echo -n "Enter DeHashed.com API key: "
read api_key

# Loop through each domain in the input file
while read -r domain; do
    # Look up breached credentials using DeHashed.com API
    result=$(curl -s "https://api.dehashed.com/search?query=domain:$domain" -H "Authorization: Basic $(echo -n "$api_key:" | base64)")
    
    # Check if any results were found
    if [ "$(echo "$result" | jq '.total')" -gt 0 ]; then
        echo "Results for $domain:" >> "$output_file"
        echo "$result" | jq '.entries[] | [.username, .password, .hash, .breaches] | @csv' >> "$output_file"
        echo "" >> "$output_file"
    fi
done < "$1"

echo "DeHashed.com lookup complete. Results written to $output_file."
