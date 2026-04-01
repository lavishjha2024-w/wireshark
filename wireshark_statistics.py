from scapy.all import *
from collections import defaultdict
# Load the captured file
pcap = rdpcap("capture.pcapng")
# -------- Protocol Statistics --------
total_packets = len(pcap)
total_size = sum(len(pkt) for pkt in pcap)
header_size = 0
for pkt in pcap:
header_size += len(pkt) - len(pkt.payload)
print("===== Protocol Statistics =====")
print("Total Packets:", total_packets)print("Total Data Size:", total_size, "bytes")
print("Total Header Size:", header_size, "bytes")
# -------- Conversation Analysis --------
conversations = defaultdict(lambda: {"bytes": 0, "packets": 0})
previous_time = None
time_differences = []
for pkt in pcap:
if IP in pkt:
src = pkt[IP].src
dst = pkt[IP].dst
pair = (src, dst)
conversations[pair]["bytes"] += len(pkt)
conversations[pair]["packets"] += 1
if previous_time is not None:
time_differences.append(pkt.time - previous_time)
previous_time = pkt.time
print("\n===== Conversation Statistics =====")
# Pair with maximum bytes
max_pair = max(conversations, key=lambda x: conversations[x]["bytes"])
print("Pair with Maximum Data Transfer:", max_pair)
print("Maximum Bytes:", conversations[max_pair]["bytes"])
print("\nPackets transferred between each pair:")
for pair, data in conversations.items():
print(pair, "-> Packets:", data["packets"])
# Average inter-packet time
if len(time_differences) > 0:
avg_time = sum(time_differences) / len(time_differences)
print("\nAverage Inter-Packet Time:", avg_time)
else:
print("\nNot enough packets to calculate inter-packet time.")
