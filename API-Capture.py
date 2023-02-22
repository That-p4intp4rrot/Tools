import sys
import argparse
import datetime
from scapy.all import *

def capture_packets(iface, dest_ips, verbose, silent):
    api_call_count = 0
    start_time = datetime.datetime.now()
    filename = ""

    def process_packet(packet):
        nonlocal api_call_count, filename

        # check if packet has TCP layer
        if TCP in packet:
            # check if packet destination IP is in scope
            if packet[IP].dst in dest_ips:
                # check if packet contains HTTP layer
                if packet.haslayer(Raw) and "HTTP" in str(packet[TCP].payload):
                    # check if packet contains API call
                    if "API" in str(packet[Raw].load):
                        api_call_count += 1

                        # create new pcap file name
                        dest_ip = packet[IP].dst
                        curr_time = datetime.datetime.now().strftime("%H%M%S")
                        curr_date = datetime.datetime.now().strftime("%Y%m%d")
                        filename = f"{dest_ip}_{curr_time}_{curr_date}.pcap"

                        # save packets to pcap file
                        wrpcap(filename, packet, append=True)

                        # print message if not in silent mode
                        if not silent:
                            print(f"API call detected on {iface}. Saving as {filename} for later inspection")

    # start capturing packets on specified interface
    try:
        sniff(iface=iface, prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("Exiting program...")
    finally:
        end_time = datetime.datetime.now()
        elapsed_time = end_time - start_time
        print(f"Captured {api_call_count} API calls in {elapsed_time}.")
        if not silent and filename:
            print(f"Saved packets to {filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet capture program that saves TCP streams featuring API calls.")
    parser.add_argument("-I", "--interface", help="Network interface to capture packets from.", required=True)
    parser.add_argument("-S", "--silent", help="Run in silent mode (no print to screen).", action="store_true")
    parser.add_argument("-V", "--verbose", help="Run in verbose mode (print all packets).", action="store_true")
    parser.add_argument("-F", "--file", help="File containing destination IPs in scope.", required=True)

    args = parser.parse_args()

    # read in destination IPs from file
    with open(args.file) as f:
        dest_ips = [line.strip() for line in f.readlines()]

    # start packet capture
    capture_packets(args.interface, dest_ips, args.verbose, args.silent)
