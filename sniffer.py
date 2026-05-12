from scapy.all import sniff, IP, TCP, UDP, Raw

def process_packet(packet):
    print("=" * 60)

    # IP Layer
    if packet.haslayer(IP):
        print("[IP Layer]")
        print("Source IP:", packet[IP].src)
        print("Destination IP:", packet[IP].dst)
        print("Protocol:", packet[IP].proto)

    # TCP Layer
    if packet.haslayer(TCP):
        print("[TCP Layer]")
        print("Source Port:", packet[TCP].sport)
        print("Destination Port:", packet[TCP].dport)

    # UDP Layer
    elif packet.haslayer(UDP):
        print("[UDP Layer]")
        print("Source Port:", packet[UDP].sport)
        print("Destination Port:", packet[UDP].dport)

    # Payload (Data inside packet)
    if packet.haslayer(Raw):
        print("[Payload]")
        print(packet[Raw].load)

    # Packet Length
    print("Packet Length:", len(packet))

    print("=" * 60)

# Capture 15 packets
sniff(count=15, prn=process_packet)