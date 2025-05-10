from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime

# Log file to store captured packet data
LOG_FILE = "packet_log.txt"

def process_packet(packet):
    log_data = f"\n--- Packet Captured at {datetime.now()} ---\n"

    if IP in packet:
        ip_layer = packet[IP]
        log_data += f"From: {ip_layer.src} --> To: {ip_layer.dst}\n"
        log_data += f"Protocol: {ip_layer.proto}\n"

        if TCP in packet:
            tcp_layer = packet[TCP]
            log_data += f"TCP Segment: Src Port: {tcp_layer.sport} --> Dst Port: {tcp_layer.dport}\n"
        elif UDP in packet:
            udp_layer = packet[UDP]
            log_data += f"UDP Datagram: Src Port: {udp_layer.sport} --> Dst Port: {udp_layer.dport}\n"
        elif ICMP in packet:
            log_data += f"ICMP Packet Type: {packet[ICMP].type}\n"
    else:
        log_data += "Non-IP Packet\n"

    
    print(log_data)

  
    with open(LOG_FILE, "a") as f:
        f.write(log_data)

# Start packet sniffing
  def start_sniffing():
    print("Starting packet capture... Press Ctrl+C to stop.\n")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffing()
