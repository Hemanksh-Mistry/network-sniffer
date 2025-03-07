# Network Packet Analyzer
# Develop a packet sniffer tool that captures and analyzes network packets. Display relevant information such as source and destination IP addresses, protocols, and payload data. Ensure the ethical use of the tool for educational purposes.

# Install the required libraries
import os
os.system("pip install scapy")

# Importing the required libraries
from scapy.all import sniff, IP, TCP, UDP

# Function to process each packet
def process_packet(packet):
        if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                protocol = packet[IP].proto

                # Determine the protocol name
                if protocol == 6:
                        proto_name = "TCP"
                elif protocol == 17:
                        proto_name = "UDP"
                else:
                        proto_name = "Other"

                print(f"Source IP: {ip_src}")
                print(f"Destination IP: {ip_dst}")
                print(f"Protocol: {proto_name}")

                if TCP in packet:
                        print(f"Source Port: {packet[TCP].sport}")
                        print(f"Destination Port: {packet[TCP].dport}")
                        print(f"Payload: {bytes(packet[TCP].payload)}")

                elif UDP in packet:
                        print(f"Source Port: {packet[UDP].sport}")
                        print(f"Destination Port: {packet[UDP].dport}")
                        print(f"Payload: {bytes(packet[UDP].payload)}")

        print("-" * 50)

# Function to start the packet sniffer
def start_sniffer():
        print("Starting packet sniffer...")
        # Use conf.L3socket to sniff at the IP layer (Layer 3)
        sniff(prn=process_packet, store=0, filter="ip")

if __name__ == "__main__":
        start_sniffer()
