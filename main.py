import threading
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import psutil

sniffing = False
packet_count = 0
sniff_thread = None  

def label_packet(packet): #위험성 있는 네트워크 포트 점검
    if TCP in packet or UDP in packet:
        port = packet[TCP].dport if TCP in packet else packet[UDP].dport
        if port == 22:
            return '*'
        elif port == 80:
            return '**'
        elif port == 23:
            return '***'
    return ''  # 아무런 문제 없음을 표시

def packet_callback(packet):
    global packet_count
    packet_count += 1
    packet_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    label = label_packet(packet)
    packet_size = len(packet)
    
    if IP in packet:
        ip_source = packet[IP].src
        ip_destination = packet[IP].dst

        if TCP in packet:
            output = (f"{packet_count}. {packet_time} {label} - TCP Packet: {ip_source} -> {ip_destination} | "
                      f"Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}, Packet Size: {packet_size} 바이트")
        elif UDP in packet:
            output = (f"{packet_count}. {packet_time} {label} - UDP Packet: {ip_source} -> {ip_destination} | "
                      f"Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}, Packet Size: {packet_size} 바이트")
        else:
            output = (f"{packet_count}. {packet_time} {label} - Other IP Packet: {ip_source} -> {ip_destination} | "
                      f"Packet Size: {packet_size} 바이트")
        
        print(output)

def get_network_stats():
    stats = psutil.net_io_counters()
    return stats.packets_sent, stats.packets_recv

def start_sniffing():
    global sniffing
    sniffing = True
    print("패킷 점검 시작...")
    sniff(prn=packet_callback, filter="ip", store=0, stop_filter=lambda x: not sniffing)
    print("패킷 점검 마치기...")

def manage_sniffing():
    global sniffing, sniff_thread
    while True:
        user_input = input("네트워크 점검 시작하고 싶으면 'start' 멈추고 싶으면 'stop': ").strip().lower()
        if user_input == 'start' and not sniffing:
            sniff_thread = threading.Thread(target=start_sniffing)
            sniff_thread.start()
        elif user_input == 'stop' and sniffing:
            sniffing = False
            sniff_thread.join()
            sniff_thread = None  # 스레드 값을 리셋하기
            packets_sent, packets_received = get_network_stats()
            print(f"보낸 패킷 갯수: {packets_sent} 개, 받은 패킷 갯수: {packets_received} 개")

manage_sniffing()
