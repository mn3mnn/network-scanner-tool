import threading

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
import time


class _Logger:
    """Logs messages to a file."""
    def __init__(self, log_file):
        self.log_file = log_file

    def log(self, message):
        """Log the message to the file."""
        with open(self.log_file, "a") as log:
            log.write(f"{time.time()} - {message}\n")


class PacketSniffer:
    """Captures network packets based on filters. protocol_filter can be 'TCP', 'UDP', 'ICMP' etc."""

    def __init__(self, ip_filter=None, protocol_filter=None, log_file: str = None, gui_callback=None):
        self.ip_filter = ip_filter
        self.protocol_filter = protocol_filter

        self.packets_logger = _Logger(log_file) if log_file else None

        self.gui_callback = gui_callback

        self._stop_sniffing = False

    def stop_sniffing(self):
        """Stop capturing packets."""
        self._stop_sniffing = True

    def _stop_sniffing_filter(self, packet):
        return self._stop_sniffing

    def start_sniffing(self):
        """Start capturing packets."""
        self._stop_sniffing = False

        scapy.sniff(prn=self.packet_callback, store=False, stop_filter=self._stop_sniffing_filter)

    def start_logging(self, log_file_name: str):
        self.packets_logger = _Logger(log_file_name)

    def stop_logging(self):
        self.packets_logger = None

    def packet_callback(self, packet):
        if self._is_matching_packet(packet):
            # print(packet.summary())

            if self.packets_logger:
                self.packets_logger.log(str(packet.summary()))

            if self.gui_callback:
                threading.Thread(target=self.gui_callback, args=(str(packet.summary()),)).start()

    def _is_matching_packet(self, packet):
        """Check if the packet matches the filters."""

        if self.ip_filter and packet.haslayer(IP) and self.ip_filter not in [packet[IP].src, packet[IP].dst]:
            return False
        if self.protocol_filter and not packet.haslayer(self.protocol_filter):
            return False
        return True


class PacketSender:
    """Sends custom packets to a target IP."""

    @staticmethod
    def send(target_ip: str, protocol: str) -> None:
        """Send a custom packet based on the specified protocol.
        :param target_ip: The target IP address.
        :param protocol: The protocol to use ("ICMP", "TCP", "UDP").
        """

        #todo: check it

        protocols = {
            "ICMP": IP(dst=target_ip) / ICMP(),
            "TCP": IP(dst=target_ip) / TCP(dport=80, flags="S"),
            "UDP": IP(dst=target_ip) / UDP(dport=53),
        }
        packet = protocols.get(protocol, None)
        if packet:
            scapy.send(packet, verbose=False)
            print(f"Packet sent to {target_ip} using {protocol}.")
        else:
            print("Invalid protocol specified.")


class NetworkPerformanceCalculator:
    """Calculates network performance metrics."""

    def __init__(self, net_interface=str, gui_callback=None):
        self.net_interface = net_interface
        self.gui_callback = gui_callback

    def calculate(self):
        """Calculate performance metrics and log results."""

        #todo: implement it

        pass

    def log_measures(self, log_file_name: str):
        """Log the performance statistics to a file."""

        #todo: implement it

        pass

