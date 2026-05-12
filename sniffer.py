from scapy.all import sniff, IP

def process_packet(packet):
    if packet.haslayer(IP):
        print("Source IP:", packet[IP].src)
        print("Destination IP:", packet[IP].dst)
        print("Protocol:", packet[IP].proto)
        print("-" * 50)

sniff(count=10, prn=process_packet)
