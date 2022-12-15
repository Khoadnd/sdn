from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import info, setLogLevel
from mininet.cli import CLI

SUSSCANNERPORT = 1
SUSATTACKERPORT = 2
SUSRELATIONPORT = 3
TTL = 5
SUBNETS = 4
SUBNETMASK = 10
CONTROLLERINFOFILENAME = "ControllerInfo.txt"


def debug(str, filename):
    with open(filename, "a") as f:
        f.write(str + "\r\n")


def get_ip_in_subnet(subnet, host):
    pass


def Network():
    net = Mininet(topo=None, build=False, controller=RemoteController)
    info('*** Adding controller\n')
    poxController = net.addController(
        'controller', controller=RemoteController, ip='192.168.1.218', port=6633)

    info('*** Add switches\n')
    switch1 = net.addSwitch('s1')
    switch2 = net.addSwitch('s2')
    switch3 = net.addSwitch('s3')

    info('*** Links switches\n')
    net.addLink(switch1, switch2)
    net.addLink(switch2, switch3)

    info('*** Add hosts\n')

    host1_1 = net.addHost('DNSSer', ip='10.10.0.5')
    host2_1 = net.addHost('h2_1', ip='10.10.0.6')
    host3_1 = net.addHost('h3_1', ip='10.10.0.7')
    host4_1 = net.addHost('h4_1', ip='10.10.0.8')
    host5_1 = net.addHost('h5_1', ip='10.10.0.9')
    host6_1 = net.addHost('h6_1', ip='10.10.0.10')
    host7_1 = net.addHost('h7_1', ip='10.10.0.11')
    host8_1 = net.addHost('h8_1', ip='10.10.0.12')
    host9_1 = net.addHost('h9_1', ip='10.10.0.13')
    host10_1 = net.addHost('TopoDec', ip='10.10.0.14')

    host1_2 = net.addHost('DHCPSer', ip='10.10.0.15')
    host2_2 = net.addHost('h2_2', ip='10.10.0.16')
    host3_2 = net.addHost('h3_2', ip='10.10.0.17')
    host4_2 = net.addHost('h4_2', ip='10.10.0.18')
    host5_2 = net.addHost('h5_2', ip='10.10.0.19')
    host6_2 = net.addHost('h6_2', ip='10.10.0.20')
    host7_2 = net.addHost('h7_2', ip='10.10.0.21')
    host8_2 = net.addHost('h8_2', ip='10.10.0.22')
    host9_2 = net.addHost('h9_2', ip='10.10.0.23')
    host10_2 = net.addHost('h10_2', ip='10.10.0.24')

    host1_3 = net.addHost('DecoyMgr', ip='10.10.0.25')
    host2_3 = net.addHost('HoneyPot', ip='10.10.0.26')
    host3_3 = net.addHost('h3_3', ip='10.10.0.27')
    host4_3 = net.addHost('h4_3', ip='10.10.0.28')
    host5_3 = net.addHost('h5_3', ip='10.10.0.29')
    host6_3 = net.addHost('h6_3', ip='10.10.0.30')
    host7_3 = net.addHost('h7_3', ip='10.10.0.31')
    host8_3 = net.addHost('h8_3', ip='10.10.0.32')
    host9_3 = net.addHost('h9_3', ip='10.10.0.33')

    info('*** Links hosts\n')

    net.addLink(host1_1, switch1)
    net.addLink(host2_1, switch1)
    net.addLink(host3_1, switch1)
    net.addLink(host4_1, switch1)
    net.addLink(host5_1, switch1)
    net.addLink(host6_1, switch1)
    net.addLink(host7_1, switch1)
    net.addLink(host8_1, switch1)
    net.addLink(host9_1, switch1)
    net.addLink(host10_1, switch1)

    net.addLink(host1_2, switch2)
    net.addLink(host2_2, switch2)
    net.addLink(host3_2, switch2)
    net.addLink(host4_2, switch2)
    net.addLink(host5_2, switch2)
    net.addLink(host6_2, switch2)
    net.addLink(host7_2, switch2)
    net.addLink(host8_2, switch2)
    net.addLink(host9_2, switch2)
    net.addLink(host10_2, switch2)

    net.addLink(host1_3, switch3)
    net.addLink(host2_3, switch3)
    net.addLink(host3_3, switch3)
    net.addLink(host4_3, switch3)
    net.addLink(host5_3, switch3)
    net.addLink(host6_3, switch3)
    net.addLink(host7_3, switch3)
    net.addLink(host8_3, switch3)
    net.addLink(host9_3, switch3)

    info('*** Starting network\n')
    net.start()

    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network')
    net.stop()

    pass


def Relations():
    pass


def log(str):
    print(str)


def get_subnet_number(ip):
    pass


if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    Network()
