import sys
import os
import threading
import queue
import time
import platform
import re
from typing import Optional, Dict, Any, List
from datetime import datetime

try:
    from scapy.all import (
        sniff, wrpcap, rdpcap, Ether, IP, IPv6, TCP, UDP, ICMP, DNS, Raw,
        conf as scapy_conf, get_if_list
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext

# Constants for protocols and colors
PROTO_COLORS = {
    "TCP": "#1E90FF",  # DodgerBlue
    "UDP": "#800080",  # Purple
    "ICMP": "#228B22",  # ForestGreen
    "DNS": "#FF8C00",  # DarkOrange
    "HTTP": "#008080",  # Teal
    "TLS": "#708090",  # SlateGray
    "OTHER": "#A9A9A9",  # DarkGray
}

ETHICS_TEXT = (
    "This tool is for educational and authorized testing only.\n"
    "Capture traffic only on networks you own or have explicit permission to monitor.\n"
    "Unauthorized packet capture may be illegal and unethical."
)

def is_admin() -> bool:
    """Check if the program is running with admin/root privileges."""
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0

def hex_dump(data: bytes, length: int = 16) -> str:
    """Return a hex dump string of the given bytes."""
    lines = []
    for i in range(0, len(data), length):
        chunk = data[i:i + length]
        hex_bytes = ' '.join(f"{b:02X}" for b in chunk)
        ascii_bytes = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{i:08X}  {hex_bytes:<{length*3}}  {ascii_bytes}")
    return '\n'.join(lines)

def build_bpf(filters: Dict[str, bool], custom_filter: str) -> str:
    """Construct BPF filter string from checkbox filters and custom filter."""
    parts = []
    if filters.get("ipv4", False) and not filters.get("ipv6", False):
        parts.append("ip")
    elif filters.get("ipv6", False) and not filters.get("ipv4", False):
        parts.append("ip6")
    
    proto_parts = []
    if filters.get("tcp", False):
        proto_parts.append("tcp")
    if filters.get("udp", False):
        proto_parts.append("udp")
    if filters.get("icmp", False):
        proto_parts.append("icmp or icmp6")
    if filters.get("dns", False):
        proto_parts.append("port 53")
    if filters.get("http", False):
        proto_parts.append("tcp port 80 or tcp port 8080")
    if filters.get("tls", False):
        proto_parts.append("tcp port 443")
    
    if proto_parts:
        parts.append('(' + ' or '.join(proto_parts) + ')')
    if custom_filter.strip():
        parts.append(f"({custom_filter.strip()})")
    return ' and '.join(parts) if parts else ''

def format_interface_name(iface_name: str) -> str:
    """Convert technical interface names to user-friendly names."""
    # Windows NPF interface names
    if iface_name.startswith(r'\Device\NPF_'):
        # Extract the GUID part
        guid_match = re.search(r'\{([0-9A-Fa-f-]+)\}', iface_name)
        if guid_match:
            return f"Network Adapter ({guid_match.group(1)[:8]}...)"
        else:
            return "Network Adapter"
    
    # Common interface names with friendly labels
    friendly_names = {
        "eth0": "Ethernet",
        "eth1": "Ethernet 2",
        "wlan0": "Wi-Fi",
        "wlan1": "Wi-Fi 2",
        "lo": "Loopback",
        "en0": "Ethernet (macOS)",
        "en1": "Ethernet 2 (macOS)",
        "awdl0": "AirDrop (macOS)",
        "utun0": "VPN Tunnel (macOS)",
        "ppp0": "PPP Connection"
    }
    
    return friendly_names.get(iface_name, iface_name)

class CaptureWorker(threading.Thread):
    """Background thread for packet capture."""
    def __init__(self, iface: str, bpf_filter: str, stop_event: threading.Event,
                 packet_queue: queue.Queue, packet_limit: int, timeout: Optional[int]):
        super().__init__(daemon=True)
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.stop_event = stop_event
        self.packet_queue = packet_queue
        self.packet_limit = packet_limit
        self.timeout = timeout
        self.captured_count = 0
        self.start_time = time.time()

    def run(self):
        def pkt_callback(pkt):
            if self.stop_event.is_set():
                return False
            parsed = self.parse_packet(pkt)
            if parsed:
                self.packet_queue.put(parsed)
                self.captured_count += 1
                if self.packet_limit and self.captured_count >= self.packet_limit:
                    self.stop_event.set()
                    return False
            return True

        try:
            sniff(iface=self.iface, filter=self.bpf_filter, prn=pkt_callback,
                  store=False, stop_filter=lambda x: self.stop_event.is_set(),
                  timeout=self.timeout)
        except Exception as e:
            self.packet_queue.put({"error": str(e)})

    def parse_packet(self, pkt) -> Optional[Dict[str, Any]]:
        """Parse scapy packet into dict for GUI."""
        try:
            layers = []
            proto = "OTHER"
            info = ""
            src = dst = ""
            length = len(pkt)
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

            # Process layers
            if pkt.haslayer(Ether):
                eth = pkt[Ether]
                layers.append(("Ethernet", {"src": eth.src, "dst": eth.dst}))

            ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip_layer:
                src = ip_layer.src
                dst = ip_layer.dst
                proto_num = ip_layer.proto if hasattr(ip_layer, 'proto') else (ip_layer.nh if hasattr(ip_layer, 'nh') else 0)
                
                if proto_num == 6:
                    proto = "TCP"
                elif proto_num == 17:
                    proto = "UDP"
                elif proto_num in [1, 58]:
                    proto = "ICMP"

            # Protocol-specific processing
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                info = f"{tcp.sport} → {tcp.dport} [TCP]"
                if tcp.flags == 2:  # SYN
                    info += " SYN"
                elif tcp.flags == 18:  # SYN-ACK
                    info += " SYN-ACK"
                elif tcp.flags == 16:  # ACK
                    info += " ACK"
                elif tcp.flags == 17:  # FIN-ACK
                    info += " FIN-ACK"
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                info = f"{udp.sport} → {udp.dport} [UDP]"
                if pkt.haslayer(DNS):
                    proto = "DNS"
                    dns = pkt[DNS]
                    if dns.qr == 0:
                        info = f"DNS Query for {dns.qd.qname.decode() if dns.qd else 'Unknown'}"
                    else:
                        info = f"DNS Response ({len(dns.an)} answers)"
            elif pkt.haslayer(ICMP):
                icmp = pkt[ICMP]
                info = f"ICMP Type: {icmp.type} Code: {icmp.code}"

            # HTTP/TLS detection
            if pkt.haslayer(Raw):
                raw = pkt[Raw]
                try:
                    payload = raw.load.decode('utf-8', errors='ignore')
                    if "HTTP" in payload or "GET" in payload or "POST" in payload:
                        proto = "HTTP"
                        if "GET" in payload:
                            info = "HTTP GET Request"
                        elif "POST" in payload:
                            info = "HTTP POST Request"
                        elif "HTTP/1." in payload:
                            info = "HTTP Response"
                    elif b"\x16\x03" in raw.load[:5]:  # TLS handshake
                        proto = "TLS"
                        info = "TLS Handshake"
                except:
                    pass

            return {
                "timestamp": timestamp,
                "src": src,
                "dst": dst,
                "proto": proto,
                "length": length,
                "info": info,
                "raw": bytes(pkt),
                "layers": layers
            }
        except Exception as e:
            print(f"Parse error: {e}")
            return None

class PacketSnifferApp(tk.Tk):
    """Main application class."""
    def __init__(self):
        super().__init__()
        self.title("Network Packet Analyzer")
        self.geometry("800x650")
        
        # Center the window on screen
        self.center_window()
        
        self.protocol("WM_DELETE_WINDOW", self.on_exit)

        # Variables
        self.ethics_agreed = tk.BooleanVar(value=False)
        self.is_capturing = False
        self.capture_thread = None
        self.stop_event = threading.Event()
        self.packet_queue = queue.Queue()
        self.packets = []
        self.selected_iface = tk.StringVar()
        self.bpf_filter = tk.StringVar()
        self.packet_limit = tk.IntVar(value=1000)
        self.timeout = tk.IntVar(value=0)
        self.filter_vars = {k: tk.BooleanVar(value=v) for k, v in {
            "ipv4": True, "ipv6": False, "tcp": True, "udp": True,
            "icmp": True, "dns": True, "http": True, "tls": True
        }.items()}
        self.redact = tk.BooleanVar(value=False)
        self.auto_scroll = tk.BooleanVar(value=True)
        self.packets_per_second = tk.StringVar(value="0")
        self.total_packets = tk.StringVar(value="0")

        self.setup_ui()
        self.check_permissions()
        self.after(100, self.process_queue)
        
    def center_window(self):
        """Center the window on the screen."""
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def setup_ui(self):
        """Setup the user interface."""
        # Configure grid weights for responsive layout
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Main frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.grid_rowconfigure(7, weight=1)
        main_frame.grid_rowconfigure(8, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)

        # Ethics banner - CENTERED
        banner = ttk.Label(main_frame, text=ETHICS_TEXT, foreground="red", 
                          font=("Arial", 10, "bold"), justify="center", wraplength=700)
        banner.grid(row=0, column=0, columnspan=5, pady=5, sticky="nsew")

        # Ethics agreement - CENTERED
        ethics_btn = ttk.Checkbutton(main_frame, text="I agree to ethical use", 
                                   variable=self.ethics_agreed, command=self.on_ethics_agreed)
        ethics_btn.grid(row=1, column=0, columnspan=5, pady=5)

        # Interface selection
        ttk.Label(main_frame, text="Interface:").grid(row=2, column=0, sticky="w")
        self.iface_combo = ttk.Combobox(main_frame, textvariable=self.selected_iface, width=40)
        self.iface_combo.grid(row=2, column=1, padx=5, sticky="w")
        ttk.Button(main_frame, text="Refresh", command=self.refresh_interfaces).grid(row=2, column=2, padx=5)
        
        # Packet limit
        ttk.Label(main_frame, text="Packet Limit:").grid(row=2, column=3, sticky="w", padx=(20, 5))
        ttk.Spinbox(main_frame, from_=0, to=10000, textvariable=self.packet_limit, width=10).grid(row=2, column=4, sticky="w")

        # Filter section
        ttk.Label(main_frame, text="BPF Filter:").grid(row=3, column=0, sticky="w")
        ttk.Entry(main_frame, textvariable=self.bpf_filter, width=50).grid(row=3, column=1, padx=5, sticky="w", columnspan=2)

        # Protocol filters frame
        proto_frame = ttk.LabelFrame(main_frame, text="Protocol Filters")
        proto_frame.grid(row=4, column=0, columnspan=5, sticky="ew", pady=5)
        for i, (proto, var) in enumerate(self.filter_vars.items()):
            ttk.Checkbutton(proto_frame, text=proto.upper(), variable=var).grid(row=0, column=i, padx=5)

        # Controls
        ctrl_frame = ttk.Frame(main_frame)
        ctrl_frame.grid(row=5, column=0, columnspan=5, pady=10, sticky="ew")
        self.start_btn = ttk.Button(ctrl_frame, text="Start Capture", command=self.start_capture, state="disabled")
        self.start_btn.grid(row=0, column=0, padx=5)
        self.stop_btn = ttk.Button(ctrl_frame, text="Stop Capture", command=self.stop_capture, state="disabled")
        self.stop_btn.grid(row=0, column=1, padx=5)
        ttk.Button(ctrl_frame, text="Clear", command=self.clear_packets).grid(row=0, column=2, padx=5)
        ttk.Button(ctrl_frame, text="Save PCAP", command=self.save_pcap).grid(row=0, column=3, padx=5)
        ttk.Button(ctrl_frame, text="Load PCAP", command=self.load_pcap).grid(row=0, column=4, padx=5)
        ttk.Checkbutton(ctrl_frame, text="Auto Scroll", variable=self.auto_scroll).grid(row=0, column=5, padx=5)
        ttk.Checkbutton(ctrl_frame, text="Redact IPs", variable=self.redact).grid(row=0, column=6, padx=5)

        # Stats frame
        stats_frame = ttk.Frame(main_frame)
        stats_frame.grid(row=6, column=0, columnspan=5, sticky="ew", pady=5)
        ttk.Label(stats_frame, text="Packets/s:").grid(row=0, column=0, sticky="w")
        ttk.Label(stats_frame, textvariable=self.packets_per_second).grid(row=0, column=1, sticky="w", padx=(0, 20))
        ttk.Label(stats_frame, text="Total Packets:").grid(row=0, column=2, sticky="w")
        ttk.Label(stats_frame, textvariable=self.total_packets).grid(row=0, column=3, sticky="w")
        
        # Packet table with scrollbar
        table_frame = ttk.Frame(main_frame)
        table_frame.grid(row=7, column=0, columnspan=5, sticky="nsew", pady=5)
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        
        columns = ("#", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)
        
        # Set column widths
        self.tree.column("#", width=50, minwidth=50)
        self.tree.column("Time", width=120, minwidth=120)
        self.tree.column("Source", width=150, minwidth=150)
        self.tree.column("Destination", width=150, minwidth=150)
        self.tree.column("Protocol", width=80, minwidth=80)
        self.tree.column("Length", width=80, minwidth=80)
        self.tree.column("Info", width=300, minwidth=200)
        
        # Set column headings
        for col in columns:
            self.tree.heading(col, text=col)
        
        # Add scrollbar to treeview
        tree_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        
        # Grid treeview and scrollbar
        self.tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll.grid(row=0, column=1, sticky="ns")
        
        self.tree.bind("<Double-1>", self.show_packet_details)

        # Details frame
        detail_frame = ttk.LabelFrame(main_frame, text="Packet Details")
        detail_frame.grid(row=8, column=0, columnspan=5, sticky="nsew", pady=5)
        detail_frame.grid_rowconfigure(0, weight=1)
        detail_frame.grid_columnconfigure(0, weight=1)
        
        self.detail_text = scrolledtext.ScrolledText(detail_frame, height=12, font=("Consolas", 10))
        self.detail_text.grid(row=0, column=0, sticky="nsew")

        # Status bar
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=9, column=0, columnspan=5, sticky="ew", pady=5)
        self.status = ttk.Label(status_frame, text="Ready", relief="sunken")
        self.status.pack(side="left", fill="x", expand=True)

        self.refresh_interfaces()
        
        # Initialize packet counters
        self.last_packet_count = 0
        self.last_update_time = time.time()

    def check_permissions(self):
        """Check if running with admin privileges."""
        if not is_admin():
            messagebox.showwarning(
                "Permissions Required",
                "Packet capture requires administrator/root privileges.\n\n"
                "On Windows: Run as Administrator\n"
                "On Linux/macOS: Use sudo"
            )

    def refresh_interfaces(self):
        """Refresh available network interfaces."""
        if SCAPY_AVAILABLE:
            try:
                interfaces = get_if_list()
                friendly_interfaces = [format_interface_name(iface) for iface in interfaces]
                self.iface_combo['values'] = friendly_interfaces
                
                # Create mapping between friendly names and real names
                self.interface_mapping = dict(zip(friendly_interfaces, interfaces))
                
                if friendly_interfaces:
                    self.selected_iface.set(friendly_interfaces[0])
            except Exception as e:
                messagebox.showerror("Error", f"Failed to get interfaces: {str(e)}")
                self.iface_combo['values'] = ["Ethernet", "Wi-Fi", "Loopback"]
                self.selected_iface.set("Ethernet")
        else:
            self.iface_combo['values'] = ["Ethernet", "Wi-Fi", "Loopback"]
            self.selected_iface.set("Ethernet")

    def get_real_interface_name(self):
        """Get the real interface name from the friendly name."""
        friendly_name = self.selected_iface.get()
        if hasattr(self, 'interface_mapping') and friendly_name in self.interface_mapping:
            return self.interface_mapping[friendly_name]
        return friendly_name

    def on_ethics_agreed(self):
        """Enable/disable controls based on ethics agreement."""
        enabled = self.ethics_agreed.get()
        self.start_btn.config(state="normal" if enabled else "disabled")

    def start_capture(self):
        """Start packet capture."""
        if not self.selected_iface.get():
            messagebox.showerror("Error", "Please select a network interface")
            return

        self.is_capturing = True
        self.stop_event.clear()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status.config(text="Capturing...")
        self.last_packet_count = 0
        self.last_update_time = time.time()

        # Build BPF filter
        bpf_filter = build_bpf(
            {k: v.get() for k, v in self.filter_vars.items()},
            self.bpf_filter.get()
        )

        # Get the real interface name
        real_iface = self.get_real_interface_name()

        self.capture_thread = CaptureWorker(
            real_iface,
            bpf_filter,
            self.stop_event,
            self.packet_queue,
            self.packet_limit.get(),
            self.timeout.get() if self.timeout.get() > 0 else None
        )
        self.capture_thread.start()

    def stop_capture(self):
        """Stop packet capture."""
        self.stop_event.set()
        self.is_capturing = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status.config(text="Stopped")

    def process_queue(self):
        """Process packets from the capture queue."""
        try:
            processed_count = 0
            while True:
                packet = self.packet_queue.get_nowait()
                if "error" in packet:
                    messagebox.showerror("Capture Error", packet["error"])
                    self.stop_capture()
                else:
                    self.add_packet(packet)
                    processed_count += 1
                    
                if processed_count > 50:  # Process max 50 packets per cycle
                    break
                    
        except queue.Empty:
            pass
        finally:
            # Update packets per second
            current_time = time.time()
            if current_time - self.last_update_time >= 1.0:
                pps = len(self.packets) - self.last_packet_count
                self.packets_per_second.set(str(pps))
                self.last_packet_count = len(self.packets)
                self.last_update_time = current_time
                
            self.total_packets.set(str(len(self.packets)))
            self.after(100, self.process_queue)

    def add_packet(self, packet):
        """Add packet to the table."""
        packet_id = len(self.packets) + 1
        self.packets.append(packet)
        
        # Redact IP addresses if enabled
        src = packet["src"] or "N/A"
        dst = packet["dst"] or "N/A"
        
        if self.redact.get() and src != "N/A":
            src_parts = src.split('.')
            if len(src_parts) == 4:
                src = f"{src_parts[0]}.{src_parts[1]}.***.***"
                
        if self.redact.get() and dst != "N/A":
            dst_parts = dst.split('.')
            if len(dst_parts) == 4:
                dst = f"{dst_parts[0]}.{dst_parts[1]}.***.***"
        
        values = (
            packet_id,
            packet["timestamp"],
            src,
            dst,
            packet["proto"],
            packet["length"],
            packet["info"]
        )
        
        item = self.tree.insert("", "end", values=values)
        # Color coding
        if packet["proto"] in PROTO_COLORS:
            self.tree.item(item, tags=(packet["proto"],))
            self.tree.tag_configure(packet["proto"], foreground=PROTO_COLORS[packet["proto"]])
            
        # Auto-scroll to bottom if enabled
        if self.auto_scroll.get():
            self.tree.see(item)

    def show_packet_details(self, event):
        """Show detailed packet information."""
        selection = self.tree.selection()
        if selection:
            item = selection[0]
            index = int(self.tree.item(item, "values")[0]) - 1
            packet = self.packets[index]
            
            # Redact IP addresses if enabled
            src = packet["src"] or "N/A"
            dst = packet["dst"] or "N/A"
            
            if self.redact.get() and src != "N/A":
                src_parts = src.split('.')
                if len(src_parts) == 4:
                    src = f"{src_parts[0]}.{src_parts[1]}.***.***"
                    
            if self.redact.get() and dst != "N/A":
                dst_parts = dst.split('.')
                if len(dst_parts) == 4:
                    dst = f"{dst_parts[0]}.{dst_parts[1]}.***.***"
            
            details = f"Packet #{index + 1}\n"
            details += f"Time: {packet['timestamp']}\n"
            details += f"Source: {src}\n"
            details += f"Destination: {dst}\n"
            details += f"Protocol: {packet['proto']}\n"
            details += f"Length: {packet['length']} bytes\n"
            details += f"Info: {packet['info']}\n\n"
            
            # Show layer information if available
            if "layers" in packet and packet["layers"]:
                details += "Layers:\n"
                for layer_name, layer_data in packet["layers"]:
                    details += f"  {layer_name}: {layer_data}\n"
                details += "\n"
            
            details += "Hex Dump:\n" + hex_dump(packet['raw'][:512])  # First 512 bytes only
            
            self.detail_text.delete(1.0, tk.END)
            self.detail_text.insert(1.0, details)

    def clear_packets(self):
        """Clear all packets."""
        self.tree.delete(*self.tree.get_children())
        self.packets.clear()
        self.detail_text.delete(1.0, tk.END)
        self.status.config(text="Cleared")
        self.packets_per_second.set("0")
        self.total_packets.set("0")

    def save_pcap(self):
        """Save packets to PCAP file."""
        if not self.packets:
            messagebox.showinfo("Info", "No packets to save")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        if filename:
            try:
                # For simplicity, we'll just save the raw bytes
                with open(filename, "wb") as f:
                    for packet in self.packets:
                        f.write(packet["raw"])
                self.status.config(text=f"Saved {len(self.packets)} packets to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save: {str(e)}")

    def load_pcap(self):
        """Load packets from PCAP file."""
        filename = filedialog.askopenfilename(
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        if filename:
            try:
                packets = rdpcap(filename)
                self.clear_packets()
                
                for pkt in packets:
                    parsed = CaptureWorker.parse_packet(self, pkt)
                    if parsed:
                        self.add_packet(parsed)
                        
                self.status.config(text=f"Loaded {len(packets)} packets from {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load: {str(e)}")

    def on_exit(self):
        """Handle application exit."""
        if self.is_capturing:
            self.stop_capture()
        if messagebox.askokcancel("Exit", "Are you sure you want to exit?"):
            self.destroy()

def main():
    """Main entry point."""
    if not SCAPY_AVAILABLE:
        messagebox.showerror(
            "Dependencies Missing",
            "Please install required packages:\n\n"
            "pip install scapy"
        )
        return
    
    app = PacketSnifferApp()
    app.mainloop()

if __name__ == "__main__":
    main()