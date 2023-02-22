#!/bin/bash

#This script will connect to every open port from nmap scan results using netcat and grab the banner and try some default commands printing each to screen and output to a textfile

#Define the nmap scan results file
NMAP_FILE="nmap_scan_results.txt"

#Define the output file
OUTPUT_FILE="output.txt"

#Check if the nmap scan results file exists
if [ ! -f $NMAP_FILE ]; then
    echo "Error: nmap scan results file not found!"
    exit 1
fi

#Check if the output file exists
if [ -f $OUTPUT_FILE ]; then
    echo "Error: output file already exists!"
    exit 1
fi

#Create the output file
touch $OUTPUT_FILE

#Loop through the nmap scan results
while read line; do
    #Extract the port number
    PORT=$(echo $line | awk '{print $1}')

    #Connect to the port using netcat
    BANNER=$(nc -v -n -z -w 1 localhost $PORT)

    #Print the banner to the screen
    echo "Banner for port $PORT:"
    echo $BANNER

    #Try some default commands
    DEFAULT_COMMANDS=$(nc -v -n -z -w 1 localhost $PORT <<< "help; exit")

    #Print the default commands to the screen
    echo "Default commands for port $PORT:"
    echo $DEFAULT_COMMANDS

    #Write the output to the output file
    echo "Banner for port $PORT:" >> $OUTPUT_FILE
    echo $BANNER >> $OUTPUT_FILE
    echo "Default commands for port $PORT:" >> $OUTPUT_FILE
    echo $DEFAULT_COMMANDS >> $OUTPUT_FILE
done < $NMAP_FILE
