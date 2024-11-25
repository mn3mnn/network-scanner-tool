from tkinter import Tk, Button, Label, Entry, Text, Scrollbar, END
import threading
import time

from network_tools.arp_scanner import ARPScanner
from network_tools.packets import PacketSniffer, PacketSender, NetworkPerformanceCalculator


class NetworkToolGUI:
    """Manages the GUI interface for the network tool."""

    def __init__(self):
        self.root = Tk()
        self.root.title("Network Tool")
        self.output_text = None
        self.create_gui()

    def create_gui(self):
        """Build the GUI layout."""
        # ARP Scan Section
        Label(self.root, text="ARP Scan (Subnet):").grid(row=0, column=0)
        subnet_entry = Entry(self.root)
        subnet_entry.grid(row=0, column=1)
        Button(self.root, text="Scan", command=lambda: self.arp_scan(subnet_entry.get())).grid(row=0, column=2)

        # Packet Sniffer Section
        Label(self.root, text="Packet Sniffer (IP, Protocol):").grid(row=1, column=0)
        ip_entry = Entry(self.root)
        ip_entry.grid(row=1, column=1)
        protocol_entry = Entry(self.root)
        protocol_entry.grid(row=1, column=2)
        Button(self.root, text="Start", command=lambda: self.packet_sniffer(ip_entry.get(), protocol_entry.get())).grid(row=1, column=3)

        # Custom Packet Sender Section
        Label(self.root, text="Send Custom Packet (IP, Protocol):").grid(row=2, column=0)
        target_ip_entry = Entry(self.root)
        target_ip_entry.grid(row=2, column=1)
        target_protocol_entry = Entry(self.root)
        target_protocol_entry.grid(row=2, column=2)
        Button(self.root, text="Send", command=lambda: self.custom_packet_sender(target_ip_entry.get(), target_protocol_entry.get())).grid(row=2, column=3)

        # Network Performance Section
        Label(self.root, text="Measure Performance:").grid(row=3, column=0)
        Button(self.root, text="Start", command=lambda: self.network_performance()).grid(row=3, column=1)

        # Output Section
        self.output_text = Text(self.root, height=20, width=80)
        self.output_text.grid(row=4, column=0, columnspan=4)
        scroll = Scrollbar(self.root, command=self.output_text.yview)
        self.output_text.configure(yscrollcommand=scroll.set)
        scroll.grid(row=4, column=4, sticky="ns")

    def display_results_in_new_window(self, results: str):
        """ Display the results in a new window that does not block the main GUI."""
        result_window = Tk()
        result_window.title("Results")
        result_label = Label(result_window, text=results)
        result_label.pack()
        result_window.mainloop()

    def arp_scan(self, subnet: str):
        """Scan the specified subnet for active devices."""
        results = ARPScanner.scan(subnet)
        # convert the results to a string
        results = "\n".join([f"{ip} - {mac}" for ip, mac in results.items()])
        self.display_results_in_new_window(results)

    def packet_sniffer(self, ip: str, protocol: str):
        """Start sniffing packets based on the specified IP and protocol."""
        # todo: validate the IP and protocol
        # todo: handle the logging

        # todo: fix the callback gui

        sniffer = PacketSniffer(ip_filter=ip, protocol_filter=protocol, gui_callback=self.display_results_in_new_window)
        sniffer.start_sniffing()

    def custom_packet_sender(self, target_ip: str, protocol: str):
        """Send a custom packet to the specified IP using the specified protocol."""
        # todo: validate the IP and protocol

        if PacketSender.send(target_ip, protocol):
            self.display_results_in_new_window(f"Packet sent to {target_ip} using {protocol}.")
        else:
            self.display_results_in_new_window("Could not send the packet.")

    def network_performance(self):
        """Calculate network performance metrics."""

        #todo: check the results
        results = NetworkPerformanceCalculator().calculate()

        self.display_results_in_new_window(results)

    def run(self):
        """Run the GUI event loop."""
        self.root.mainloop()


if __name__ == "__main__":
    gui = NetworkToolGUI()
    gui.run()
