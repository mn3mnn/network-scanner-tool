from tkinter import Tk, Button, Label, Entry, Text, Scrollbar, END, messagebox, IntVar, Checkbutton
from tkinter import ttk
import threading
import time

from network_tools.arp_scanner import ARPScanner
from network_tools.packets import PacketSniffer, PacketSender, NetworkPerformanceCalculator


class NetworkToolGUI:
    """Manages the GUI interface for the network tool."""

    def __init__(self):
        self.sniffer = None

        self.root = Tk()
        self.root.geometry("800x400")
        self.root.title("Network Tool")
        self.captured_packets_window = None
        self.captured_packets_output_text = None
        self.create_gui()

    def create_gui(self):
        """Build the GUI layout."""
        # ARP Scan Section
        Label(self.root, text="ARP Scan (Subnet):").grid(row=0, column=0, pady=20)
        subnet_entry = Entry(self.root)
        subnet_entry.grid(row=0, column=1)
        ttk.Button(self.root, text="Scan", command=lambda: self.arp_scan(subnet_entry.get())).grid(row=0, column=2)

        # Packet Sniffer Section
        Label(self.root, text="Packet Sniffer (IP, Protocol):").grid(row=1, column=0, pady=20)
        ip_entry = Entry(self.root)
        ip_entry.grid(row=1, column=1, padx=10)
        protocol_entry = Entry(self.root)
        protocol_entry.grid(row=1, column=2)
        # add logging checkbox
        logging_var = IntVar(value=True)
        ttk.Checkbutton(self.root, text="Enable Logging", variable=logging_var).grid(row=1, column=3, padx=10)
        ttk.Button(self.root, text="Start", command=lambda: self.packet_sniffer(ip_entry.get(), protocol_entry.get(), logging_var.get() == 1)).grid(row=1, column=4)
        ttk.Button(self.root, text="Stop", command=lambda: self.stop_sniffing()).grid(row=1, column=5)

        # Custom Packet Sender Section
        Label(self.root, text="Send Custom Packet (IP, Protocol):").grid(row=2, column=0, pady=20)
        target_ip_entry = Entry(self.root)
        target_ip_entry.grid(row=2, column=1, padx=10)
        target_protocol_entry = Entry(self.root)
        target_protocol_entry.grid(row=2, column=2)
        ttk.Button(self.root, text="Send", command=lambda: self.custom_packet_sender(target_ip_entry.get(), target_protocol_entry.get())).grid(row=2, column=3)

        # Network Performance Section
        Label(self.root, text="Measure Performance:").grid(row=3, column=0, pady=20)
        ttk.Button(self.root, text="Start", command=lambda: self.network_performance()).grid(row=3, column=1)

        # # Output Section
        # self.output_text = Text(self.root, height=20, width=80)
        # self.output_text.grid(row=4, column=0, columnspan=4)
        # scroll = Scrollbar(self.root, command=self.output_text.yview)
        # self.output_text.configure(yscrollcommand=scroll.set)
        # scroll.grid(row=4, column=4, sticky="ns")

    def display_results_in_new_window(self, results: str):
        """ Display the results in a new window that does not block the main GUI."""
        result_window = Tk()
        result_window.geometry("600x400")
        result_window.title("Results")
        result_label = Label(result_window, text=results)
        result_label.pack()
        result_window.mainloop()

    def display_captured_packet(self, packet: str):
        def on_closing_captured_packets_window():
            self.sniffer.stop_sniffing()
            self.captured_packets_window.destroy()
            self.captured_packets_window = None
            self.captured_packets_output_text = None

        if not self.captured_packets_window:
            self.captured_packets_window = Tk()
            self.captured_packets_window.geometry("600x400")
            self.captured_packets_window.title("Captured Packets")
            self.captured_packets_window.protocol("WM_DELETE_WINDOW", on_closing_captured_packets_window)
            self.captured_packets_output_text = Text(self.captured_packets_window, height=20, width=80)
            self.captured_packets_output_text.pack()
            scroll = Scrollbar(self.captured_packets_window, command=self.captured_packets_output_text.yview)
            self.captured_packets_output_text.configure(yscrollcommand=scroll.set)
            scroll.pack()

            self.captured_packets_window.mainloop()

        if self.captured_packets_output_text:
            self.captured_packets_output_text.insert(END, f"{packet}\n")
            self.captured_packets_output_text.see(END)

    def arp_scan(self, subnet: str):
        """Scan the specified subnet for active devices."""

        # validate the subnet str
        if not subnet or not (subnet.count(".") == 3 or subnet.count("/") == 1 or [x.isdigit() or x == '/' for x in subnet.split(".")]):
            messagebox.showerror("Invalid Subnet", "Please enter a valid subnet format, i.e., 192.168.1.0/24")
            return

        thread = threading.Thread(target=ARPScanner.scan, args=(subnet, self.display_results_in_new_window,))
        thread.start()

        messagebox.showinfo("ARP Scan", "ARP scan started. Results will be displayed shortly.")

    def packet_sniffer(self, ip: str, protocol: str, logging: bool):
        global packets_log_file

        """Start sniffing packets based on the specified IP and protocol."""
        if ip and not (ip.count(".") == 3 or [x.isdigit() for x in ip.split(".")]):
            messagebox.showerror("Invalid IP", "Please enter a valid IP address.")
            return

        if protocol and protocol not in ["TCP", "UDP", "ICMP"]:
            messagebox.showerror("Invalid Protocol", "Please enter a valid protocol (TCP, UDP, ICMP).")
            return

        self.sniffer = PacketSniffer(ip_filter=ip, protocol_filter=protocol, log_file=packets_log_file if logging else None,
                                gui_callback=self.display_captured_packet)

        thread = threading.Thread(target=self.sniffer.start_sniffing)
        thread.start()

    def stop_sniffing(self):
        """Stop sniffing packets."""
        if self.sniffer:
            self.sniffer.stop_sniffing()

    def custom_packet_sender(self, target_ip: str, protocol: str):
        """Send a custom packet to the specified IP using the specified protocol."""
        # todo: validate the IP and protocol

        if PacketSender.send(target_ip, protocol):
            self.display_results_in_new_window(f"Packet sent to {target_ip} using {protocol}.")
        else:
            self.display_results_in_new_window("Could not send the packet.")

    def network_performance(self):
        global performance_log_file
        """Calculate network performance metrics."""

        #todo: check the results
        results = NetworkPerformanceCalculator().calculate()

        self.display_results_in_new_window(results)

    def run(self):
        """Run the GUI event loop."""
        self.root.mainloop()


if __name__ == "__main__":
    packets_log_file = "packets.txt"
    performance_log_file = "performance.txt"

    gui = NetworkToolGUI()
    gui.run()
