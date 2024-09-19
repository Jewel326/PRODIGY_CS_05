# network_sniffer.py

from scapy.all import sniff, IP, TCP, UDP

# Callback function to handle captured packets
def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = None

        # Check for protocol layer (TCP/UDP)
        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        else:
            proto = "Other"

        print(f"Source IP: {ip_src} | Destination IP: {ip_dst} | Protocol: {proto}")

# Main function to capture packets
def start_sniffing():
    print("Starting packet capture... Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=False)  # sniff indefinitely

if __name__ == "__main__":
    start_sniffing()
    


    


