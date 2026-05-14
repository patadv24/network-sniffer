from scapy.all import *
from datetime import datetime

conf.use_pcap = True

# PROTOCOL DICTIONARY
protocols = {

    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF"

}

# SERVICE DICTIONARY
services = {

    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP Alternate"

}

# PACKET COUNTERS
total_packets = 0
tcp_packets = 0
udp_packets = 0
dns_queries = 0

# STARTUP BANNER
print("=" * 50)
print("        PYTHON NETWORK SNIFFER v1.0")
print("       Live Packet Monitoring Started")
print("=" * 50)

def packet_callback(packet):

    global total_packets
    global tcp_packets
    global udp_packets
    global dns_queries

    total_packets += 1

    # CURRENT TIME
    current_time = datetime.now().strftime("%H:%M:%S")

    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol_num = packet[IP].proto

        protocol_name = protocols.get(protocol_num, "Unknown Protocol")

        print("\n" + "=" * 50)
        print(f"Timestamp: {current_time}")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol_name}")

        # TCP PACKETS
        if packet.haslayer(TCP):

            tcp_packets += 1

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            service_name = services.get(dst_port, "Unknown Service")

            print(f"Source Port: {src_port}")
            print(f"Destination Port: {dst_port}")
            print(f"Service: {service_name}")
            print("Protocol Type: TCP")

        # UDP PACKETS
        elif packet.haslayer(UDP):

            udp_packets += 1

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            service_name = services.get(dst_port, "Unknown Service")

            print(f"Source Port: {src_port}")
            print(f"Destination Port: {dst_port}")
            print(f"Service: {service_name}")
            print("Protocol Type: UDP")

        # DNS DETECTION
        if packet.haslayer(DNSQR):

            dns_queries += 1

            dns_query = packet[DNSQR].qname.decode()

            print(f"DNS Query Detected: {dns_query}")

        # LIVE PACKET STATS
        print("\n" + "-" * 15 + " PACKET STATS " + "-" * 15)
        print(f"Total Packets Captured: {total_packets}")
        print(f"TCP Packets: {tcp_packets}")
        print(f"UDP Packets: {udp_packets}")
        print(f"DNS Queries: {dns_queries}")

# MAIN SNIFFING LOOP
try:

    sniff(
        iface="enp0s3",
        prn=packet_callback,
        store=False
    )

# HANDLE OTHER ERRORS
except Exception as e:

    print(f"\nError Occurred: {e}")

# ALWAYS EXECUTE ON EXIT
finally:

    print("\n\n" + "=" * 50)
    print("         NETWORK SNIFFER STOPPED")
    print("=" * 50)

    print("\nFINAL SESSION STATISTICS:\n")

    print(f"Total Packets Captured: {total_packets}")
    print(f"TCP Packets: {tcp_packets}")
    print(f"UDP Packets: {udp_packets}")
    print(f"DNS Queries: {dns_queries}")

    print("\nThank you for using Python Network Sniffer v1.0")
    print("=" * 50)