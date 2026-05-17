from scapy.all import *
from datetime import datetime
from colorama import *
import os
import threading
from queue import Queue

init(autoreset=True)

conf.use_pcap = True

# ================= STARTUP =================

print(Fore.LIGHTCYAN_EX + "="*50)
print(Fore.LIGHTGREEN_EX + "      PYTHON NETWORK SNIFFER v2.0")
print(Fore.LIGHTCYAN_EX + "="*50)

print("\nChoose Traffic Filter:")
print("1 → TCP Only")
print("2 → UDP Only")
print("3 → DNS Only")
print("4 → ALL Traffic")

filter_choice = input("\nEnter Choice: ")

# ================= LOG FILE =================

base_dir = os.path.dirname(
    os.path.abspath(__file__)
)

log_path = os.path.join(
    base_dir,
    "session_log.txt"
)

log_file = open(log_path, "a")

print(
    Fore.LIGHTGREEN_EX +
    "\nLogging packets to session_log.txt"
)

print(log_file.name)

# ================= PROTOCOLS =================

protocols = {

    1:"ICMP",
    2:"IGMP",
    6:"TCP",
    17:"UDP",
    41:"IPv6",
    47:"GRE",
    50:"ESP",
    51:"AH",
    89:"OSPF"

}

# ================= SERVICES =================

services = {

    20:"FTP Data",
    21:"FTP",
    22:"SSH",
    23:"Telnet",
    25:"SMTP",
    53:"DNS",
    67:"DHCP",
    68:"DHCP",
    80:"HTTP",
    110:"POP3",
    123:"NTP",
    143:"IMAP",
    161:"SNMP",
    443:"HTTPS",
    445:"SMB",
    3306:"MySQL",
    3389:"RDP",
    5432:"PostgreSQL",
    8080:"HTTP Alternate"

}

# ================= COUNTERS =================

total_packets = 0
tcp_packets = 0
udp_packets = 0
dns_queries = 0

# ================= THREAD QUEUE =================

packet_queue = Queue()

# ================= PACKET CAPTURE =================

def packet_callback(packet):

    packet_queue.put(packet)

# ================= PACKET WORKER =================

def process_packets():

    while True:

        packet = packet_queue.get()

        process_packet(packet)

# ================= PACKET ANALYSIS =================

def process_packet(packet):

    global total_packets
    global tcp_packets
    global udp_packets
    global dns_queries

    # FILTERS

    if filter_choice=="1" and not packet.haslayer(TCP):
        return

    elif filter_choice=="2" and not packet.haslayer(UDP):
        return

    elif filter_choice=="3" and not packet.haslayer(DNSQR):
        return

    total_packets += 1

    current_time = datetime.now().strftime(
        "%H:%M:%S"
    )

    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        protocol_num = packet[IP].proto

        protocol_name = protocols.get(
            protocol_num,
            "Unknown Protocol"
        )

        log_entry = (
            f"[{current_time}] "
            f"{src_ip}->{dst_ip}"
            f" | {protocol_name}"
        )

        print(
            "\n" +
            Fore.LIGHTCYAN_EX +
            "="*50
        )

        print(
            Fore.WHITE +
            f"Time: {current_time}"
        )

        print(
            Fore.WHITE +
            f"Source: {src_ip}"
        )

        print(
            Fore.WHITE +
            f"Destination: {dst_ip}"
        )

        # PROTOCOL COLORS

        if protocol_name=="TCP":

            print(
                Fore.LIGHTRED_EX +
                f"Protocol: {protocol_name}"
            )

        elif protocol_name=="UDP":

            print(
                Fore.LIGHTCYAN_EX +
                f"Protocol: {protocol_name}"
            )

        else:

            print(
                Fore.LIGHTYELLOW_EX +
                f"Protocol: {protocol_name}"
            )

        # TCP

        if packet.haslayer(TCP):

            tcp_packets += 1

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            service = services.get(
                dst_port,
                "Unknown Service"
            )

            print(
                f"Source Port: {src_port}"
            )

            print(
                f"Destination Port: {dst_port}"
            )

            print(
                Fore.LIGHTGREEN_EX +
                f"Service: {service}"
            )

            log_entry += (
                f" | "
                f"{src_port}->{dst_port}"
                f" ({service})"
            )

        # UDP

        elif packet.haslayer(UDP):

            udp_packets += 1

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            service = services.get(
                dst_port,
                "Unknown Service"
            )

            print(
                f"Source Port: {src_port}"
            )

            print(
                f"Destination Port: {dst_port}"
            )

            print(
                Fore.LIGHTGREEN_EX +
                f"Service: {service}"
            )

            log_entry += (
                f" | "
                f"{src_port}->{dst_port}"
                f" ({service})"
            )

        # DNS

        if packet.haslayer(DNSQR):

            dns_queries += 1

            dns_query = packet[
                DNSQR
            ].qname.decode()

            print(
                Fore.LIGHTMAGENTA_EX +
                f"DNS Query: {dns_query}"
            )

            log_entry += (
                f" | DNS:{dns_query}"
            )

        # SAVE LOG

        log_file.write(
            log_entry
        )

        log_file.write(
            "\n"
        )

        log_file.flush()

        # DASHBOARD

        print(
            Fore.LIGHTGREEN_EX +
            "\n"+"="*35
        )

        print(
            Fore.LIGHTYELLOW_EX +
            "      LIVE NETWORK STATS"
        )

        print(
            Fore.LIGHTGREEN_EX +
            "="*35
        )

        print(
            Fore.WHITE +
            f"Total Packets : {total_packets}"
        )

        print(
            Fore.LIGHTRED_EX +
            f"TCP Packets   : {tcp_packets}"
        )

        print(
            Fore.LIGHTCYAN_EX +
            f"UDP Packets   : {udp_packets}"
        )

        print(
            Fore.LIGHTMAGENTA_EX +
            f"DNS Queries   : {dns_queries}"
        )

        print(
            Fore.LIGHTGREEN_EX +
            "="*35
        )

# ================= START THREAD =================

worker = threading.Thread(
    target=process_packets
)

worker.daemon = True

worker.start()

# ================= SNIFFER =================

try:

    sniff(
        iface="enp0s3",
        prn=packet_callback,
        store=False
    )

finally:

    log_file.close()

    print(
        "\n"+
        Fore.LIGHTRED_EX+
        "="*50
    )

    print(
        Fore.LIGHTYELLOW_EX+
        "NETWORK SNIFFER STOPPED"
    )

    print(
        Fore.LIGHTRED_EX+
        "="*50
    )

    print(
        Fore.WHITE+
        f"Total Packets: {total_packets}"
    )

    print(
        Fore.LIGHTRED_EX+
        f"TCP Packets: {tcp_packets}"
    )

    print(
        Fore.LIGHTCYAN_EX+
        f"UDP Packets: {udp_packets}"
    )

    print(
        Fore.LIGHTMAGENTA_EX+
        f"DNS Queries: {dns_queries}"
    )

    print(
        Fore.LIGHTGREEN_EX+
        "\nLogs saved to session_log.txt"
    )
