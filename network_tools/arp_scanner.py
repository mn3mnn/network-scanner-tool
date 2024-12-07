import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp


class ARPScanner:
    """Handles ARP scanning to discover active devices in a network."""
    def __init__(self):
        pass

    @staticmethod
    def scan(subnet: str, gui_callback: callable):
        """
        :param subnet:
        :return: A dictionary of IP addresses and corresponding MAC addresses.
        """
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)

        ans, unans = srp(request, timeout=2, retry=1)
        result = {}

        for sent, received in ans:
            result[str(received.psrc)] = str(received.hwsrc)

        if gui_callback:
            gui_callback(str(result))

        return result


if __name__ == '__main__':
    scanner = ARPScanner()
    result = scanner.scan("192.168.1.0/24")
    print(result)

