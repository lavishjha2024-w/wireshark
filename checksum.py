from scapy.all import *
pcap_file = "exp3.pcapng" packets = rdpcap(pcap_file)
# your file
def verify_packet(pkt):
results = {}
# ---------------- Ethernet ----------------
if Ether in pkt:
results["Ethernet"] = "FCS not present in pcap (Not Applicable)"
# ---------------- IP ----------------
if IP in pkt:
ip_original = pkt[IP].chksum
del pkt[IP].chksum
new_pkt = IP(bytes(pkt[IP]))
results["IP"] = (ip_original, new_pkt.chksum)
# ---------------- TCP ----------------
if IP in pkt and TCP in pkt:
tcp_original = pkt[TCP].chksum
del pkt[TCP].chksum
new_pkt = IP(bytes(pkt[IP]))
results["TCP"] = (tcp_original, new_pkt[TCP].chksum)
# TLS runs over TCP (no checksum)
if pkt[TCP].sport == 443 or pkt[TCP].dport == 443:
results["TLS"] = "No checksum field (Integrity via MAC/AEAD)"
# ---------------- UDP ----------------
if IP in pkt and UDP in pkt:
udp_original = pkt[UDP].chksum
del pkt[UDP].chksum
new_pkt = IP(bytes(pkt[IP]))
results["UDP"] = (udp_original, new_pkt[UDP].chksum)
# ---------------- ICMP ----------------
if IP in pkt and ICMP in pkt:
icmp_original = pkt[ICMP].chksum
del pkt[ICMP].chksum
new_pkt = IP(bytes(pkt[IP]))
results["ICMP"] = (icmp_original, new_pkt[ICMP].chksum)
return results
print("=== SCAPY CHECKSUM & INTEGRITY VERIFICATION (PCAP) ===")
for i, pkt in enumerate(packets[:20], 1): print(f"\nPacket #{i}")
results = verify_packet(pkt)
# first 20 packets
if not results:print("No verifiable checksum fields in this packet")
for proto, value in results.items():
if isinstance(value, tuple):
orig, calc = value
print(f"{proto:9} | Original: {hex(orig)} Calculated: {hex(calc)} Match: {orig == calc}")
else:
print(f"{proto:9} | {value}”)
