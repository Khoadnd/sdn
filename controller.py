from pox.core import core
import pox.openflow.nicira as nx
from pox.openflow.of_json import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from config import *


class MyController(object):
    def __init__(self) -> None:
        core.openflow.addListeners(self)
        self.relations = Relations()
        self.attackers = []
        self.scanners = []
        self.blocked_scanners = []
        self.network = Network()
        log("Controller initialized")

    def _handle_ConnectionUp(self, event):

        # Rule to send SUSSCANNER packets to controller
        alert_rule = nx.nx_flow_mod()
        alert_rule.match.of_eth_type = ethernet.IP_TYPE
        alert_rule.match.of_ip_proto = ipv4.UDP_PROTOCOL
        alert_rule.match.udp_src = SUSSCANNERPORT
        alert_rule.priority = 10
        alert_rule.actions.append(
            of.ofp_action_output(port=of.OFPP_CONTROLLER))
        event.connection.send(alert_rule)

        # Rule to send all SUSATTACKER packets to controller
        alert_rule = nx.nx_flow_mod()
        alert_rule.match.of_eth_type = ethernet.IP_TYPE
        alert_rule.match.of_ip_proto = ipv4.UDP_PROTOCOL
        alert_rule.match.udp_src = SUSATTACKERPORT
        alert_rule.priority = 10
        alert_rule.actions.append(
            of.ofp_action_output(port=of.OFPP_CONTROLLER))
        event.connection.send(alert_rule)

        # Rule to send all SUSRELATION packets to controller
        alert_rule = nx.nx_flow_mod()
        alert_rule.match.of_eth_type = ethernet.IP_TYPE
        alert_rule.match.of_ip_proto = ipv4.UDP_PROTOCOL
        alert_rule.match.udp_src = SUSRELATIONPORT
        alert_rule.priority = 10
        alert_rule.actions.append(
            of.ofp_action_output(port=of.OFPP_CONTROLLER))
        event.connection.send(alert_rule)

        # Rule to send all ARP REQUEST to deceiver
        arp_rule = nx.nx_flow_mod()
        arp_rule.match.of_eth_type = ethernet.ARP_TYPE
        arp_rule.match.of_ip_proto = arp.REQUEST
        arp_rule.priority = 7
        arp_rule.actions.append(
            of.ofp_action_output(port=self.network.deceiver_port))
        event.connection.send(arp_rule)

        # Rules to send all IP packets with specific TTLs to deceiver
        for t in range(TTL):
            ttl_rule = nx.nx_flow_mod()
            ttl_rule.match.NXM_OF_ETH_TYPE = ethernet.IP_TYPE
            ttl_rule.match.NXM_NX_IP_TTL = t
            ttl_rule.priority = 7
            ttl_rule.actions.append(of.ofp_action_output(
                port=self.network.deceiver_port))
            event.connection.send(ttl_rule)

        # Rule to send all DHCP DISCOVER and DHCP REQUEST to DHCP server
        dhcp_rule = nx.nx_flow_mod()
        dhcp_rule.match.of_eth_type = ethernet.IP_TYPE
        dhcp_rule.match.of_ip_proto = ipv4.UDP_PROTOCOL
        dhcp_rule.match.udp_src = 68
        dhcp_rule.match.udp_dst = 67
        dhcp_rule.priority = 7
        dhcp_rule.actions.append(of.ofp_action_output(
            port=self.network.dhcp_server.port))
        event.connection.send(dhcp_rule)

        # Rule to send all DNS QUERY to DNS server
        dns_rule = nx.nx_flow_mod()
        dns_rule.match.of_eth_type = ethernet.IP_TYPE
        dns_rule.match.of_ip_proto = ipv4.UDP_PROTOCOL
        dns_rule.match.udp_dst = 53
        dns_rule.priority = 7
        dns_rule.actions.append(of.ofp_action_output(
            port=self.network.dns_server.port))
        event.connection.send(dns_rule)

        # Rule to send all ICMP REQUEST to deceiver
        icmp_rule = nx.nx_flow_mod()
        icmp_rule.match.of_eth_type = ethernet.IP_TYPE
        icmp_rule.match.of_ip_proto = ipv4.ICMP_PROTOCOL
        icmp_rule.match.of_icmp_type = 8
        icmp_rule.priority = 6  # lower than TTL rule
        icmp_rule.actions.append(of.ofp_action_output(
            port=self.network.deceiver.port))
        event.connection.send(icmp_rule)

        # Rules to send IP packets to related targets
        for dst_target in self.network.targets:
            dst_ip = dst_target.ip
            dst_mac = dst_target.mac
            ip_rule = nx.nx_flow_mod()
            ip_rule.match.of_eth_type = ethernet.IP_TYPE
            ip_rule.match.ip_dst = IPAddr(dst_ip)
            ip_rule.priority = 4
            ip_rule.actions.append(of.ofp_action_output(port=dst_target.port))
            ip_rule.actions.append(of.ofp_action_output(
                port=of.OFPP_CONTROLLER))  # necessary
            event.connection.send(ip_rule)

        # Rules to send non IP or non TTL packets to related targets
        for dst_target in self.network.targets:
            dst_ip = dst_target.ip
            dst_mac = dst_target.mac
            rule = nx.nx_flow_mod()
            rule.match.eth_dst = EthAddr(dst_mac)
            rule.priority = 3
            rule.actions.append(of.ofp_action_output(port=dst_target.port))
            rule.actions.append(of.ofp_action_output(
                port=of.OFPP_CONTROLLER))  # necessary
            event.connection.send(rule)

        # Rules to send IP packets to related hosts and targets
        for src_node in self.network.hosts + self.network.targets:
            src_ip = src_node.ip
            src_mac = src_node.mac
            for dst_host in self.network.hosts:
                dst_ip = dst_host.ip
                dst_mac = dst_host.mac
                ip_rule = nx.nx_flow_mod()
                ip_rule.match.of_eth_type = ethernet.IP_TYPE
                ip_rule.match.ip_src = IPAddr(src_ip)
                ip_rule.match.ip_dst = IPAddr(dst_ip)
                ip_rule.priority = 4
                src_subnet = src_node.subnet_number
                dst_subnet = dst_host.subnet_number
                for k in range(abs(src_subnet - dst_subnet)):
                    ip_rule.actions.append(nx.nx_action_dec_ttl())
                ip_rule.actions.append(
                    of.ofp_action_output(port=dst_host.port))
                event.connection.send(ip_rule)

        # Rules to send non IP or non TTL packets to related hosts
        for dst_host in self.network.hosts:
            dst_ip = dst_host.ip
            dst_mac = dst_host.mac
            rule = nx.nx_flow_mod()
            rule.match.eth_dst = EthAddr(dst_mac)
            rule.priority = 3
            rule.actions.append(of.ofp_action_output(port=dst_host.port))
            event.connection.send(rule)

        # rules to send packets to related servers
        for server in self.network.servers:
            dst_ip = server.ip
            dst_mac = server.mac
            rule = nx.nx_flow_mod()
            rule.match.of_eth_type = ethernet.IP_TYPE
            rule.match.ip_dst = IPAddr(dst_ip)
            rule.priority = 3
            rule.actions.append(of.ofp_action_output(port=server.port))
            event.connection.send(rule)

        # rules to send IP packets of routers to deceiver
        for router in self.network.routers:
            dst_ip = router.ip
            dst_mac = router.mac
            rule = nx.nx_flow_mod()
            rule.match.of_eth_type = ethernet.IP_TYPE
            rule.match.ip_dst = IPAddr(dst_ip)
            rule.priority = 3
            rule.actions.append(of.ofp_action_output(
                port=self.network.deceiver.port))
            event.connection.send(rule)

        # rules to send all other packets to honeypot
        for subnet in range(SUBNETS):
            honeypot_rule = nx.nx_flow_mod()
            honeypot_rule.match.of_eth_type = ethernet.IP_TYPE
            honeypot_rule.match.ip_dst = (
                IPAddr(get_ip_in_subnet(subnet, 0)), SUBNETMASK)
            honeypot_rule.priority = 2
            honeypot_rule.actions.append(
                of.ofp_action_output(port=self.network.honeypot.port))
            event.connection.send(honeypot_rule)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if packet.type == ethernet.IP_TYPE:
            ip = packet.payload
            src_ip = ip.srcip
            dst_ip = ip.dstip
            if ip.protocol == ipv4.UDP_PROTOCOL and ip.payload.srcport == SUSSCANNERPORT and dst_ip not in self.scanners:
                self.scanners.append(dst_ip)
                info = str(dst_ip) + " suspicious scanner"
                debug(info, CONTROLLERINFOFILENAME)
            if ip.protocol == ipv4.UDP_PROTOCOL and ip.payload.srcport == SUSATTACKERPORT and dst_ip not in self.attackers:
                self.attackers.append(dst_ip)
                info = str(dst_ip) + " suspicious attacker"
                debug(info, CONTROLLERINFOFILENAME)
                # blocking rule
                for dst_host in (self.network.hosts + self.network.targets):
                    if dst_host.ip == self.network.hosts[0].ip:
                        continue
                    block_rule = nx.nx_flow_mod()
                    block_rule.match.of_eth_type = ethernet.IP_TYPE
                    block_rule.match.ip_src = IPAddr(dst_ip)
                    block_rule.match.ip_dst = IPAddr(dst_host.ip)
                    block_rule.priority = 5
                    block_rule.actions.append(of.ofp_action_output(
                        port=self.network.honeypot.port))
                    event.connection.send(block_rule)
        if ip.protocol == ipv4.UDP_PROTOCOL and ip.payload.srcport == SUSRELATIONPORT:
            self.relations.add_relation(src_ip, dst_ip)
            info = "relation between " + str(src_ip) + " and " + str(dst_ip)
            debug(info, CONTROLLERINFOFILENAME)


def launch():
    core.registerNew(MyController)
