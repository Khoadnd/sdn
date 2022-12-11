from config import *
from scapy.all import *
network = Network()


# handles ttl inside different packets
def handle_ttl(pkt):
    src_mac = pkt[0][Ether].src
    src_ip = pkt[0][IP].src
    dst_mac = pkt[0][Ether].dst
    dst_ip = pkt[0][IP].dst
    ttl = pkt[0][IP].ttl
    src_subnet = get_subnet_number(src_ip)
    dst_subnet = get_subnet_number(dst_ip)
    if ttl <= abs(src_subnet - dst_subnet) + 1:  # time exceeded
        if src_subnet > dst_subnet:
            router = network.routers[src_subnet - ttl + 1]
        else:
            router = network.routers[src_subnet + ttl - 1]
            ether = Ether(src=router.mac, dst=src_mac)
            ip = IP(src=router.ip, dst=src_ip)
            icmp = ICMP(type=11, code=0)
            response = ether/ip/icmp/IPerror(str(pkt[0][IP]))
            sendp(response, inter=0.001, verbose=0)
    else:  # destination unreachable
        ether = Ether(src=dst_mac, dst=src_mac)
        ip = IP(src=dst_ip, dst=src_ip)
        icmp = ICMP(type=3, code=3)
        response = ether/ip/icmp/IPerror(str(pkt[0][IP]))
        sendp(response, inter=0.001, verbose=0)


# handles ARP REQUEST packets and sends ARP RESPONSE packet
def handle_arp(pkt):
    if pkt[0].op == 1:  # request
        response = eval(pkt[0].command())
        dst_ip = pkt[0].pdst
        dst_node = network.get_node_by_ip(dst_ip)
        if dst_node == None:
            warning("deceiver: unknown destination for ARP at " + str(dst_ip))
            return
        related_mac = dst_node.mac
        response[Ether].src = related_mac
        response[ARP].hwsrc = related_mac
        response[ARP].psrc = pkt[0].pdst
        response[Ether].dst = pkt[0].hwsrc
        response[ARP].hwdst = pkt[0].hwsrc
        response[ARP].pdst = pkt[0].psrc
        response[ARP].op = 2
        sendp(response, inter=0.001, verbose=0)


# handles ICMP packets and sends appropriate packet
def handle_icmp(pkt):


if pkt[0][ICMP].type == 8:  # echo request
dst_ip = pkt[0][IP].dst
dst_node = network.get_node_by_ip(dst_ip)
if dst_node == None:
warning("deceiver: unknown destination for ICMP at " + str(dst_ip))
return
reply = eval(pkt[0].command())
reply[Ether].src = pkt[0][Ether].dst
reply[IP].src = pkt[0][IP].dst
reply[Ether].dst = pkt[0][Ether].src
reply[IP].dst = pkt[0][IP].src
reply[ICMP].type = 0
reply[ICMP].code = 0
sendp(reply, inter=0.001, verbose=0)
# handles all incoming packets according to different packet types
def handle_packets(pkt):


if pkt.haslayer(ARP):
handle_arp(pkt)
if pkt[0].haslayer(IP):
if pkt[0][IP].ttl < TTL:
handle_ttl(pkt)
elif pkt.haslayer(ICMP):
handle_icmp(pkt)
sniff(prn=handle_packets)
