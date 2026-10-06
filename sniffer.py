from scapy.all import sniff, IP, IPv6, TCP, UDP, Raw

print("======================================")
print("       SECURE PACKET ANALYZER")
print("======================================")
print("Capturing 20 packets...\n")


def analyze_packet(packet):
    try:
        print("Packet Structure:")

        # IP version
        if IP in packet:
            print("IP Version      : IPv4")
            print("Source IP       :", packet[IP].src)
            print("Destination IP  :", packet[IP].dst)

        elif IPv6 in packet:
            print("IP Version      : IPv6")
            print("Source IP       :", packet[IPv6].src)
            print("Destination IP  :", packet[IPv6].dst)

        # Protocol and ports
        if TCP in packet:
            print("Protocol        : TCP")
            print("Source Port     :", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

        elif UDP in packet:
            print("Protocol        : UDP")
            print("Source Port     :", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

        else:
            print("Protocol        : Other")

        # Packet size
        print("Packet Size     :", len(packet), "bytes")

        # Payload information
        # Actual payload content is NOT displayed
        if Raw in packet:
            payload_size = len(packet[Raw].load)
            print("Payload         : Present")
            print("Payload Size    :", payload_size, "bytes")
        else:
            print("Payload         : Not present")

        print("-" * 40)

    except Exception as error:
        print("Packet could not be analyzed safely.")
        print("Error:", error)


try:
    sniff(prn=analyze_packet, count=20)

except PermissionError:
    print("Permission error: packet capture requires proper authorization.")

except Exception as error:
    print("Packet capture could not be completed.")
    print("Error:", error)


print("\n======================================")
print("Packet analysis completed.")
print("======================================")