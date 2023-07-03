from scapy.all import sniff, IP
import time, os

os.system("cls")
print("""   ____
  (.   \\
    \  |  
     \ |___(\--/)
   __/    (  . . )
  "'._.    '-.O.'
       '-.  \ "|\\
          '.,,/'.,,
             PacketCat                              
""")

THRESHOLD_PACKETS = 1000
THRESHOLD_INTERVAL = 1

packet_count = {}
start_time = time.time()
total_packets = 0

def process_packet(packet):
    global packet_count
    if IP in packet:
        src_ip = packet[IP].src
        packet_count[src_ip] = packet_count.get(src_ip, 0) + 1

while True:
    sniff(filter="ip", prn=lambda packet: process_packet(packet), store=False, timeout=THRESHOLD_INTERVAL)
    capture_duration = time.time() - start_time
    for src_ip, count in packet_count.items():
        if count / capture_duration > THRESHOLD_PACKETS:
            print(f"\x1b[31m[{src_ip.ljust(15)}] Packets: {count}\x1b[37m")
        else:
            print(f"[{src_ip.ljust(15)}] Packets: {count}")
        total_packets += count
    packets_per_second = total_packets / capture_duration
    os.system(f"title P/S: {int(packets_per_second)}")
    packet_count = {}
    start_time = time.time()
    total_packets = 0
