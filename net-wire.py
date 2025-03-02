import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from scapy.all import *
import threading
import os
from datetime import datetime
import netifaces
import mimetypes
import hashlib
import platform

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Net-wire Sniffer ")
        
        system = platform.system()
        if system == "Windows":
            self.root.state('zoomed')
        elif system == "Linux":
            try:
                self.root.attributes('-zoomed', True)
            except:
                screen_width = self.root.winfo_screenwidth()
                screen_height = self.root.winfo_screenheight()
                self.root.geometry(f"{screen_width}x{screen_height}+0+0")
        elif system == "Darwin":
            self.root.attributes('-fullscreen', True)
            self.root.geometry("1200x800")
        
        self.captured_packets = []
        self.filtered_packets = []
        self.streams = {}
        self.hosts = {}
        self.pending_data_ports = {}
        
        self.style = ttk.Style()
        self.style.configure("Treeview", rowheight=25)
        self.style.configure("Treeview.Heading", font=('Arial', 10, 'bold'))
        
        self.packet_tree = None
        self.root.after(100, self.configure_colors)
        
        self.menu_bar = tk.Menu(root)
        root.config(menu=self.menu_bar)
        
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Open PCAP", command=self.load_pcap)
        self.file_menu.add_command(label="Save PCAP", command=self.save_pcap)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=root.quit)
        
        self.view_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="View", menu=self.view_menu)
        self.view_menu.add_command(label="Extracted Files", command=self.show_extracted_files)
        self.view_menu.add_command(label="Hosts", command=self.show_hosts)
        self.view_menu.add_command(label="Packet Capture", command=self.show_packet_capture)
        
        control_frame = ttk.Frame(root)
        control_frame.pack(pady=5, fill='x')
        
        self.start_button = ttk.Button(control_frame, text="Start Capture", command=self.start_sniffing)
        self.start_button.pack(side='left', padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop Capture", command=self.stop_sniffing, state='disabled')
        self.stop_button.pack(side='left', padx=5)
        
        self.follow_button = ttk.Button(control_frame, text="Follow Stream", command=self.follow_stream)
        self.follow_button.pack(side='left', padx=5)
        
        self.interface_label = ttk.Label(control_frame, text="Interface:")
        self.interface_label.pack(side='left', padx=5)
        
        self.interfaces = self.get_interfaces()
        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(control_frame, textvariable=self.interface_var, values=self.interfaces)
        self.interface_dropdown.pack(side='left', padx=5)
        if self.interfaces:
            self.interface_dropdown.set(self.interfaces[0])
        else:
            self.interface_dropdown.set("No interfaces found")
        
        filter_frame = ttk.LabelFrame(control_frame, text="Filters")
        filter_frame.pack(side='left', padx=5, fill='x', expand=True)
        
        ttk.Label(filter_frame, text="Protocol:").pack(side='left', padx=2)
        self.protocol_filter = ttk.Entry(filter_frame, width=10)
        self.protocol_filter.pack(side='left', padx=2)
        
        ttk.Label(filter_frame, text="Src IP:").pack(side='left', padx=2)
        self.src_ip_filter = ttk.Entry(filter_frame, width=15)
        self.src_ip_filter.pack(side='left', padx=2)
        
        ttk.Label(filter_frame, text="Dest IP:").pack(side='left', padx=2)
        self.dest_ip_filter = ttk.Entry(filter_frame, width=15)
        self.dest_ip_filter.pack(side='left', padx=2)
        
        ttk.Label(filter_frame, text="Any IP:").pack(side='left', padx=2)
        self.any_ip_filter = ttk.Entry(filter_frame, width=15)
        self.any_ip_filter.pack(side='left', padx=2)
        
        self.apply_filter_button = ttk.Button(filter_frame, text="Apply Filter", command=self.apply_filter)
        self.apply_filter_button.pack(side='left', padx=5)
        
        self.clear_filter_button = ttk.Button(filter_frame, text="Clear Filter", command=self.clear_filter)
        self.clear_filter_button.pack(side='left', padx=5)
        
        self.main_notebook = ttk.Notebook(root)
        self.main_notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.packet_frame = ttk.Frame(self.main_notebook)
        self.main_notebook.add(self.packet_frame, text="Packet Capture")
        
        self.packet_pane = ttk.PanedWindow(self.packet_frame, orient='vertical')
        self.packet_pane.pack(fill='both', expand=True)
        
        self.packet_list_frame = ttk.LabelFrame(self.packet_pane, text="Captured Packets")
        self.packet_pane.add(self.packet_list_frame, weight=2)
        
        self.packet_tree = ttk.Treeview(self.packet_list_frame, 
                                      columns=("No", "Time", "Source", "Destination", "Protocol", "Length"),
                                      show='headings')
        self.packet_tree.heading("No", text="No.")
        self.packet_tree.heading("Time", text="Time")
        self.packet_tree.heading("Source", text="Source")
        self.packet_tree.heading("Destination", text="Destination")
        self.packet_tree.heading("Protocol", text="Protocol")
        self.packet_tree.heading("Length", text="Length")
        
        self.packet_tree.column("No", width=50)
        self.packet_tree.column("Time", width=150)
        self.packet_tree.column("Source", width=150)
        self.packet_tree.column("Destination", width=150)
        self.packet_tree.column("Protocol", width=100)
        self.packet_tree.column("Length", width=50)
        
        self.packet_tree.pack(fill='both', expand=True)
        self.packet_tree.bind('<<TreeviewSelect>>', self.show_packet_details)
        
        self.details_pane = ttk.PanedWindow(self.packet_frame, orient='horizontal')
        self.packet_pane.add(self.details_pane, weight=1)
        
        self.details_frame = ttk.LabelFrame(self.details_pane, text="Packet Details")
        self.details_pane.add(self.details_frame)
        
        self.details_tree = ttk.Treeview(self.details_frame, show='tree')
        self.details_tree.pack(fill='both', expand=True)
        
        self.bytes_frame = ttk.LabelFrame(self.details_pane, text="Packet Bytes")
        self.details_pane.add(self.bytes_frame)
        
        self.bytes_text = scrolledtext.ScrolledText(self.bytes_frame, height=10, width=40)
        self.bytes_text.pack(fill='both', expand=True)
        
        self.files_frame = ttk.Frame(self.main_notebook)
        self.main_notebook.add(self.files_frame, text="Extracted Files")
        
        self.files_pane = ttk.PanedWindow(self.files_frame, orient='vertical')
        self.files_pane.pack(fill='both', expand=True)
        
        self.files_list_frame = ttk.LabelFrame(self.files_pane, text="Extracted Files")
        self.files_pane.add(self.files_list_frame, weight=2)
        
        self.files_tree = ttk.Treeview(self.files_list_frame, 
                                     columns=("FrameNr", "Filename", "Extension", "Size", "SourceHost", "SPort", 
                                              "DestHost", "DPort", "Protocol", "Details", "Timestamp"),
                                     show='headings')
        self.files_tree.heading("FrameNr", text="Frame Nr")
        self.files_tree.heading("Filename", text="Filename")
        self.files_tree.heading("Extension", text="Extension")
        self.files_tree.heading("Size", text="Size")
        self.files_tree.heading("SourceHost", text="Source Host")
        self.files_tree.heading("SPort", text="S.Port")
        self.files_tree.heading("DestHost", text="Dest Host")
        self.files_tree.heading("DPort", text="Dest.Port")
        self.files_tree.heading("Protocol", text="Protocol")
        self.files_tree.heading("Details", text="Details")
        self.files_tree.heading("Timestamp", text="Timestamp")
        
        self.files_tree.column("FrameNr", width=60)
        self.files_tree.column("Filename", width=150)
        self.files_tree.column("Extension", width=80)
        self.files_tree.column("Size", width=80)
        self.files_tree.column("SourceHost", width=120)
        self.files_tree.column("SPort", width=60)
        self.files_tree.column("DestHost", width=120)
        self.files_tree.column("DPort", width=60)
        self.files_tree.column("Protocol", width=80)
        self.files_tree.column("Details", width=150)
        self.files_tree.column("Timestamp", width=150)
        
        self.files_tree.pack(fill='both', expand=True)
        self.files_tree.bind('<<TreeviewSelect>>', self.show_file_details)
        
        self.file_details_frame = ttk.LabelFrame(self.files_pane, text="File Details")
        self.files_pane.add(self.file_details_frame, weight=1)
        
        self.file_details_tree = ttk.Treeview(self.file_details_frame, show='tree')
        self.file_details_tree.pack(fill='both', expand=True)
        
        self.context_menu = tk.Menu(self.file_details_tree, tearoff=0)
        self.context_menu.add_command(label="Copy Hash", command=self.copy_hash)
        self.file_details_tree.bind("<Button-3>", self.show_context_menu)
        
        self.hosts_frame = ttk.Frame(self.main_notebook)
        self.main_notebook.add(self.hosts_frame, text="Hosts")
        
        self.hosts_tree = ttk.Treeview(self.hosts_frame, 
                                     columns=("IP", "OS", "MAC"),
                                     show='headings')
        self.hosts_tree.heading("IP", text="IP Address")
        self.hosts_tree.heading("OS", text="Operating System")
        self.hosts_tree.heading("MAC", text="MAC Address")
        
        self.hosts_tree.column("IP", width=150)
        self.hosts_tree.column("OS", width=150)
        self.hosts_tree.column("MAC", width=200)
        
        self.hosts_tree.pack(fill='both', expand=True)
        
        self.sniffing = False
        self.packet_count = 0
        self.extracted_files = {}
        self.ftp_data_ports = {}

    def configure_colors(self):
        if self.packet_tree:
            self.packet_tree.tag_configure("TCP", background="#ADD8E6")
            self.packet_tree.tag_configure("UDP", background="#90EE90")
            self.packet_tree.tag_configure("ICMP", background="#FFFFE0")
            self.packet_tree.tag_configure("HTTP", background="#87CEFA")
            self.packet_tree.tag_configure("HTTPS", background="#4682B4")
            self.packet_tree.tag_configure("DNS", background="#98FB98")
            self.packet_tree.tag_configure("ARP", background="#FFDAB9")
            self.packet_tree.tag_configure("FTP", background="#FFA07A")
            self.packet_tree.tag_configure("SMTP", background="#DDA0DD")
            self.packet_tree.tag_configure("TLS", background="#B0C4DE")
            self.packet_tree.tag_configure("IPv6", background="#E6E6FA")
            self.packet_tree.tag_configure("Other", background="#D3D3D3")
            print("Colors configured")

    def get_interfaces(self):
        try:
            interfaces = netifaces.interfaces()
            if not interfaces:
                return ["No interfaces found"]
            valid_interfaces = [iface for iface in interfaces if iface != 'lo' and not iface.startswith('v')]
            return valid_interfaces if valid_interfaces else ["No valid interfaces"]
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            return ["No interfaces found"]

    def start_sniffing(self):
        if not self.interface_var.get() or self.interface_var.get() == "No interfaces found":
            messagebox.showerror("Error", "Please select a valid interface")
            return
        self.sniffing = True
        self.start_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.files_tree.delete(*self.files_tree.get_children())
        self.hosts_tree.delete(*self.hosts_tree.get_children())
        self.details_tree.delete(*self.details_tree.get_children())
        self.file_details_tree.delete(*self.file_details_tree.get_children())
        self.captured_packets = []
        self.filtered_packets = []
        self.streams.clear()
        self.ftp_data_ports.clear()
        self.hosts.clear()
        self.pending_data_ports.clear()
        self.packet_count = 0
        
        interface = self.interface_var.get()
        self.sniff_thread = threading.Thread(target=self.sniff_packets, args=(interface,))
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
        print(f"Started sniffing on interface: {interface}")

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.extract_pending_streams()
        self.update_hosts_display()
        print("Sniffing stopped")

    def sniff_packets(self, interface):
        try:
            sniff(iface=interface, prn=self.process_packet, stop_filter=lambda x: not self.sniffing)
        except Exception as e:
            print(f"Error sniffing: {e}")
            messagebox.showerror("Error", f"Sniffing failed: {e}")

    def process_packet(self, packet, from_pcap=False):
        self.packet_count += 1
        if not from_pcap:
            self.captured_packets.append(packet)
            self.filtered_packets.append(packet)
        
        try:
            if from_pcap and hasattr(packet, 'time'):
                timestamp = datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            else:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        except Exception as e:
            print(f"Timestamp error: {e}")
            timestamp = "N/A"
        
        src = packet[IP].src if IP in packet else (packet[IPv6].src if IPv6 in packet else packet.src if ARP in packet else "N/A")
        dst = packet[IP].dst if IP in packet else (packet[IPv6].dst if IPv6 in packet else packet.dst if ARP in packet else "N/A")
        length = len(packet)
        
        if TCP in packet:
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                protocol = "HTTP"
                color_tag = "HTTP"
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                protocol = "HTTPS"
                color_tag = "HTTPS"
                if packet.haslayer(TLS):
                    protocol = "TLS"
                    color_tag = "TLS"
            elif packet[TCP].dport == 53 or packet[TCP].sport == 53:
                protocol = "DNS"
                color_tag = "DNS"
            elif packet[TCP].dport == 21 or packet[TCP].sport == 21:
                protocol = "FTP"
                color_tag = "FTP"
            elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                protocol = "SSH"
                color_tag = "SSH"
            elif packet[TCP].dport == 25 or packet[TCP].sport == 25:
                protocol = "SMTP"
                color_tag = "SMTP"
            else:
                protocol = "TCP"
                color_tag = "TCP"
        elif UDP in packet:
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                protocol = "DNS"
                color_tag = "DNS"
            else:
                protocol = "UDP"
                color_tag = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
            color_tag = "ICMP"
        elif ARP in packet:
            protocol = "ARP"
            color_tag = "ARP"
        elif IPv6 in packet:
            protocol = "IPv6"
            color_tag = "IPv6"
        else:
            protocol = "Other"
            color_tag = "Other"
        
        self.packet_tree.insert("", "end", 
                              values=(self.packet_count, timestamp, src, dst, protocol, length),
                              tags=(str(self.packet_count), color_tag))
        
        self.process_file_extraction(packet, protocol)
        self.update_hosts(packet)

    def show_packet_details(self, event):
        self.details_tree.delete(*self.details_tree.get_children())
        self.bytes_text.delete(1.0, tk.END)
        selection = self.packet_tree.selection()
        if selection:
            packet_num = int(self.packet_tree.item(selection[0])['tags'][0]) - 1
            if 0 <= packet_num < len(self.captured_packets):
                packet = self.captured_packets[packet_num]
                self.display_packet_tree(packet)
                hexdump_str = hexdump(packet, dump=True)
                self.bytes_text.insert(tk.END, hexdump_str)
                print(f"Showing details for packet {packet_num + 1}")

    def display_packet_tree(self, packet):
        def add_layer(parent, layer, layer_name):
            layer_node = self.details_tree.insert(parent, "end", text=layer_name)
            for field_name in layer.fields:
                value = layer.fields[field_name]
                self.details_tree.insert(layer_node, "end", text=f"{field_name}: {value}")

        current_layer = packet
        while current_layer:
            layer_name = current_layer.__class__.__name__
            add_layer("", current_layer, layer_name)
            current_layer = current_layer.payload

    def show_file_details(self, event):
        self.file_details_tree.delete(*self.file_details_tree.get_children())
        selection = self.files_tree.selection()
        if selection:
            item = self.files_tree.item(selection[0])['values']
            frame_nr, filename, extension, size, src_host, src_port, dst_host, dst_port, protocol, details, timestamp = item
            
            try:
                with open(filename, "rb") as f:
                    file_content = f.read()
                    md5_hash = hashlib.md5(file_content).hexdigest()
                    sha1_hash = hashlib.sha1(file_content).hexdigest()
                    sha256_hash = hashlib.sha256(file_content).hexdigest()
            except Exception as e:
                md5_hash = sha1_hash = sha256_hash = f"Error: {e}"
            
            file_node = self.file_details_tree.insert("", "end", text="File Details")
            self.file_details_tree.insert(file_node, "end", text=f"File Path: {os.path.abspath(filename)}")
            self.file_details_tree.insert(file_node, "end", text=f"Name: {filename}", values=(filename,))
            self.file_details_tree.insert(file_node, "end", text=f"MD5: {md5_hash}", values=(md5_hash,))
            self.file_details_tree.insert(file_node, "end", text=f"SHA1: {sha1_hash}", values=(sha1_hash,))
            self.file_details_tree.insert(file_node, "end", text=f"SHA256: {sha256_hash}", values=(sha256_hash,))
            self.file_details_tree.insert(file_node, "end", text=f"Source: {src_host}:{src_port}")
            self.file_details_tree.insert(file_node, "end", text=f"Destination: {dst_host}:{dst_port}")
            print(f"Showing file details for {filename}")

    def show_context_menu(self, event):
        item = self.file_details_tree.identify('item', event.x, event.y)
        if item:
            text = self.file_details_tree.item(item, "text")
            if any(h in text for h in ["MD5:", "SHA1:", "SHA256:"]):
                self.selected_hash = self.file_details_tree.item(item, "values")[0]
                self.context_menu.post(event.x_root, event.y_root)

    def copy_hash(self):
        if hasattr(self, 'selected_hash'):
            self.root.clipboard_clear()
            self.root.clipboard_append(self.selected_hash)
            self.root.update()
            print(f"Copied hash to clipboard: {self.selected_hash}")

    def follow_stream(self):
        print("Entering follow_stream")
        selection = self.packet_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a packet to follow!")
            print("No packet selected")
            return
        
        packet_num = int(self.packet_tree.item(selection[0])['tags'][0]) - 1
        print(f"Selected packet number: {packet_num + 1}")
        if 0 <= packet_num < len(self.captured_packets):
            selected_packet = self.captured_packets[packet_num]
            if TCP not in selected_packet:
                messagebox.showwarning("Warning", "Selected packet is not TCP!")
                print("Selected packet is not TCP")
                return
            
            src_ip = selected_packet[IP].src if IP in selected_packet else None
            dst_ip = selected_packet[IP].dst if IP in selected_packet else None
            src_port = selected_packet[TCP].sport
            dst_port = selected_packet[TCP].dport
            print(f"Stream endpoints: {src_ip}:{src_port} <-> {dst_ip}:{dst_port}")
            
            # Filter stream packets
            self.stream_packets = [
                pkt for pkt in self.captured_packets
                if (TCP in pkt and IP in pkt and 
                    ((pkt[IP].src == src_ip and pkt[IP].dst == dst_ip and 
                      pkt[TCP].sport == src_port and pkt[TCP].dport == dst_port) or
                     (pkt[IP].src == dst_ip and pkt[IP].dst == src_ip and 
                      pkt[TCP].sport == dst_port and pkt[TCP].dport == src_port)))
            ]
            
            if not self.stream_packets:
                messagebox.showwarning("Warning", "No stream packets found!")
                print("No stream packets found")
                return
            
            print(f"Found {len(self.stream_packets)} packets in the stream")
            self.stream_packets.sort(key=lambda pkt: pkt[TCP].seq if TCP in pkt else 0)
            self.filtered_packets = self.stream_packets[:]
            self.update_packet_list()
            
            # Reconstruct full stream content with direction indication
            full_stream_content = ""
            for pkt in self.stream_packets:
                if Raw in pkt:
                    direction = "Client -> Server" if pkt[IP].src == src_ip and pkt[TCP].sport == src_port else "Server -> Client"
                    try:
                        decoded_data = pkt[Raw].load.decode('utf-8', errors='ignore')
                        full_stream_content += f"{direction}: {decoded_data}\n"
                        print(f"Packet {self.captured_packets.index(pkt) + 1} ({direction}): {decoded_data[:50]}...")
                    except:
                        full_stream_content += f"{direction}: [Binary Data ({len(pkt[Raw].load)} bytes)]\n"
                        print(f"Packet {self.captured_packets.index(pkt) + 1} ({direction}): [Binary Data, {len(pkt[Raw].load)} bytes]")
            
            print(f"Full stream content length: {len(full_stream_content)} characters")
            print(f"Sample content: {full_stream_content[:100]}...")
            
            # Create stream window
            try:
                self.stream_window = tk.Toplevel(self.root)
                self.stream_window.title(f"TCP Stream: {src_ip}:{src_port} <-> {dst_ip}:{dst_port}")
                self.stream_window.geometry("800x600")
                self.stream_window.protocol("WM_DELETE_WINDOW", self.close_stream_window)
                print("Stream window created")
                
                self.stream_text = scrolledtext.ScrolledText(self.stream_window, wrap=tk.WORD, height=30, width=100)
                self.stream_text.pack(fill='both', expand=True)
                self.stream_text.insert(tk.END, full_stream_content)
                self.stream_text.config(state='disabled')
            except Exception as e:
                print(f"Error creating stream window: {e}")
                messagebox.showerror("Error", f"Failed to create stream window: {e}")

    def close_stream_window(self):
        if hasattr(self, 'stream_window'):
            self.stream_window.destroy()
            delattr(self, 'stream_window')
            delattr(self, 'stream_packets')
            delattr(self, 'stream_text')
            self.filtered_packets = self.captured_packets[:]
            self.update_packet_list()
            print("Stream window closed, main list reset")

    def apply_filter(self):
        protocol = self.protocol_filter.get().strip().upper()
        src_ip = self.src_ip_filter.get().strip()
        dest_ip = self.dest_ip_filter.get().strip()
        any_ip = self.any_ip_filter.get().strip()
        
        print(f"Applying filter - Protocol: {protocol}, Src IP: {src_ip}, Dest IP: {dest_ip}, Any IP: {any_ip}")
        self.filtered_packets = self.captured_packets[:]
        
        if protocol:
            self.filtered_packets = [pkt for pkt in self.filtered_packets if self.get_packet_protocol(pkt) == protocol]
            print(f"After protocol filter: {len(self.filtered_packets)} packets")
        if src_ip:
            self.filtered_packets = [pkt for pkt in self.filtered_packets if 
                                   (IP in pkt and pkt[IP].src == src_ip) or 
                                   (IPv6 in pkt and pkt[IPv6].src == src_ip) or 
                                   (ARP in pkt and pkt.src == src_ip)]
            print(f"After src_ip filter: {len(self.filtered_packets)} packets")
        if dest_ip:
            self.filtered_packets = [pkt for pkt in self.filtered_packets if 
                                   (IP in pkt and pkt[IP].dst == dest_ip) or 
                                   (IPv6 in pkt and pkt[IPv6].dst == dest_ip) or 
                                   (ARP in pkt and pkt.dst == dest_ip)]
            print(f"After dest_ip filter: {len(self.filtered_packets)} packets")
        if any_ip:
            self.filtered_packets = [pkt for pkt in self.filtered_packets if 
                                   ((IP in pkt and (pkt[IP].src == any_ip or pkt[IP].dst == any_ip)) or 
                                    (IPv6 in pkt and (pkt[IPv6].src == any_ip or pkt[IPv6].dst == any_ip)) or 
                                    (ARP in pkt and (pkt.src == any_ip or pkt.dst == any_ip)))]
            print(f"After any_ip filter: {len(self.filtered_packets)} packets")
        
        self.update_packet_list()
        print("Filter applied and packet list updated")

    def clear_filter(self):
        self.protocol_filter.delete(0, tk.END)
        self.src_ip_filter.delete(0, tk.END)
        self.dest_ip_filter.delete(0, tk.END)
        self.any_ip_filter.delete(0, tk.END)
        self.filtered_packets = self.captured_packets[:]
        self.update_packet_list()
        print("Filters cleared, showing all packets")

    def get_packet_protocol(self, packet):
        if TCP in packet:
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                return "HTTP"
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                return "HTTPS" if not packet.haslayer(TLS) else "TLS"
            elif packet[TCP].dport == 53 or packet[TCP].sport == 53:
                return "DNS"
            elif packet[TCP].dport == 21 or packet[TCP].sport == 21:
                return "FTP"
            elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                return "SSH"
            elif packet[TCP].dport == 25 or packet[TCP].sport == 25:
                return "SMTP"
            return "TCP"
        elif UDP in packet:
            return "DNS" if (packet[UDP].dport == 53 or packet[UDP].sport == 53) else "UDP"
        elif ICMP in packet:
            return "ICMP"
        elif ARP in packet:
            return "ARP"
        elif IPv6 in packet:
            return "IPv6"
        return "Other"

    def update_packet_list(self):
        self.packet_tree.delete(*self.packet_tree.get_children())
        for i, packet in enumerate(self.filtered_packets, 1):
            try:
                timestamp = (datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                            if hasattr(packet, 'time') else datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3])
            except:
                timestamp = "N/A"
            
            src = packet[IP].src if IP in packet else (packet[IPv6].src if IPv6 in packet else packet.src if ARP in packet else "N/A")
            dst = packet[IP].dst if IP in packet else (packet[IPv6].dst if IPv6 in packet else packet.dst if ARP in packet else "N/A")
            length = len(packet)
            protocol = self.get_packet_protocol(packet)
            color_tag = protocol
            
            self.packet_tree.insert("", "end", 
                                  values=(i, timestamp, src, dst, protocol, length),
                                  tags=(str(self.captured_packets.index(packet) + 1), color_tag))
        print(f"Updated packet list with {len(self.filtered_packets)} packets")

    def update_hosts(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ttl = packet[IP].ttl if IP in packet else None
            mac = packet[Ether].src if Ether in packet else "N/A"
            
            os_guess = "Unknown"
            if ttl:
                if ttl <= 64:
                    os_guess = "Linux/Unix"
                elif ttl <= 128:
                    os_guess = "Windows"
                elif ttl <= 255:
                    os_guess = "Solaris/AIX"
            
            if src_ip not in self.hosts:
                self.hosts[src_ip] = {'os': os_guess, 'mac': mac}
            else:
                if self.hosts[src_ip]['mac'] == "N/A" and mac != "N/A":
                    self.hosts[src_ip]['mac'] = mac
                if self.hosts[src_ip]['os'] == "Unknown" and os_guess != "Unknown":
                    self.hosts[src_ip]['os'] = os_guess
            
            if dst_ip not in self.hosts:
                self.hosts[dst_ip] = {'os': os_guess, 'mac': "N/A" if Ether not in packet else packet[Ether].dst}
        
        elif ARP in packet:
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            src_mac = packet[ARP].hwsrc
            dst_mac = packet[ARP].hwdst if packet[ARP].op == 2 else "N/A"
            
            if src_ip not in self.hosts:
                self.hosts[src_ip] = {'os': "Unknown", 'mac': src_mac}
            else:
                self.hosts[src_ip]['mac'] = src_mac
            
            if dst_ip not in self.hosts:
                self.hosts[dst_ip] = {'os': "Unknown", 'mac': dst_mac}
            else:
                if self.hosts[dst_ip]['mac'] == "N/A":
                    self.hosts[dst_ip]['mac'] = dst_mac
        
        self.update_hosts_display()

    def update_hosts_display(self):
        self.hosts_tree.delete(*self.hosts_tree.get_children())
        for ip, info in self.hosts.items():
            self.hosts_tree.insert("", "end", values=(ip, info['os'], info['mac']))
        print(f"Updated hosts list with {len(self.hosts)} entries")

    def process_file_extraction(self, packet, protocol):
        if TCP in packet and Raw in packet and IP in packet:
            payload = bytes(packet[Raw])
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            stream_key = (src_ip, src_port, dst_ip, dst_port)
            reverse_key = (dst_ip, dst_port, src_ip, src_port)
            frame_nr = self.packet_count
            
            if protocol == "FTP" and (dst_port == 21 or src_port == 21):
                if b"RETR" in payload or b"STOR" in payload:
                    print(f"Packet {frame_nr}: FTP {b'RETR' if b'RETR' in payload else b'STOR'} detected")
                    try:
                        if b"RETR" in payload:
                            fname = payload.split(b"RETR")[1].strip().split(b"\r\n")[0].decode('utf-8', errors='ignore').strip()
                            details = f"RETR {fname}"
                        elif b"STOR" in payload:
                            fname = payload.split(b"STOR")[1].strip().split(b"\r\n")[0].decode('utf-8', errors='ignore').strip()
                            details = f"STOR {fname}"
                        if fname:
                            self.ftp_data_ports[(dst_ip, 20)] = (fname, frame_nr, src_ip, src_port, dst_ip, dst_port, protocol, details)
                            print(f"Packet {frame_nr}: Expecting data for {fname} from {dst_ip}:20")
                    except Exception as e:
                        print(f"Packet {frame_nr}: FTP command parsing error: {e}")
                elif b"PORT" in payload:
                    try:
                        port_data = payload.split(b"PORT")[1].strip().split(b"\r\n")[0].decode('utf-8').split(',')
                        if len(port_data) >= 6:
                            data_port = int(port_data[4]) * 256 + int(port_data[5])
                            self.pending_data_ports[(src_ip, data_port)] = frame_nr
                            print(f"Packet {frame_nr}: FTP PORT command detected, data port: {data_port}")
                        else:
                            print(f"Packet {frame_nr}: PORT parsing error: insufficient data")
                    except Exception as e:
                        print(f"Packet {frame_nr}: PORT parsing error: {e}")
            
            elif (src_ip, src_port) in self.ftp_data_ports or (dst_ip, dst_port) in self.ftp_data_ports:
                print(f"Packet {frame_nr}: FTP data packet detected ({len(payload)} bytes)")
                stream_key = (src_ip, src_port, dst_ip, dst_port) if (src_ip, src_port) in self.ftp_data_ports else reverse_key
                if stream_key not in self.streams:
                    fname, orig_frame, orig_src_ip, orig_src_port, orig_dst_ip, orig_dst_port, orig_protocol, details = (
                        self.ftp_data_ports.get((src_ip, src_port)) or self.ftp_data_ports.get((dst_ip, dst_port))
                    )
                    self.streams[stream_key] = {
                        'payload': b'', 
                        'filename': fname, 
                        'is_data': True, 
                        'frame_nr': orig_frame, 
                        'src_ip': orig_src_ip, 
                        'src_port': orig_src_port, 
                        'dst_ip': orig_dst_ip, 
                        'dst_port': orig_dst_port, 
                        'protocol': orig_protocol,
                        'details': details
                    }
                self.streams[stream_key]['payload'] += payload
                print(f"Packet {frame_nr}: Added to FTP data stream {stream_key}, Total size: {len(self.streams[stream_key]['payload'])} bytes")
                if packet[TCP].flags & 0x01:  # FIN flag
                    print(f"Packet {frame_nr}: FTP data stream {stream_key} ended (FIN)")
                    self.extract_from_stream(stream_key)
            
            elif protocol == "HTTP" and b"POST" in payload[:8]:
                print(f"Packet {frame_nr}: HTTP POST detected")
                if stream_key not in self.streams:
                    filename = f"http_post_{frame_nr}"
                    details = f"POST {filename}"
                    if b"Content-Disposition" in payload:
                        try:
                            disp = payload.split(b"Content-Disposition:")[1].split(b"\r\n")[0]
                            if b"filename=" in disp:
                                filename = disp.split(b"filename=")[1].strip(b'"\r').decode('utf-8', errors='ignore')
                                details = f"POST {filename}"
                                print(f"Packet {frame_nr}: Filename from disposition: {filename}")
                        except Exception as e:
                            print(f"Packet {frame_nr}: Content-Disposition error: {e}")
                    if b"Content-Type" in payload:
                        try:
                            content_type = payload.split(b"Content-Type:")[1].split(b"\n")[0].strip().decode('utf-8')
                            extension = mimetypes.guess_extension(content_type.split(';')[0]) or ""
                            if extension and not filename.endswith(extension):
                                filename += extension
                            print(f"Packet {frame_nr}: Content-Type: {content_type}, Extension: {extension}")
                        except Exception as e:
                            print(f"Packet {frame_nr}: Content-Type error: {e}")
                    self.streams[stream_key] = {
                        'payload': b'', 
                        'filename': filename, 
                        'is_data': True, 
                        'frame_nr': frame_nr, 
                        'src_ip': src_ip, 
                        'src_port': src_port, 
                        'dst_ip': dst_ip, 
                        'dst_port': dst_port, 
                        'protocol': protocol,
                        'details': details
                    }
                if b"\r\n\r\n" in payload:
                    body = payload[payload.index(b"\r\n\r\n") + 4:]
                    self.streams[stream_key]['payload'] += body
                else:
                    self.streams[stream_key]['payload'] += payload
                print(f"Packet {frame_nr}: Added to HTTP POST stream, Total size: {len(self.streams[stream_key]['payload'])} bytes")
                if packet[TCP].flags & 0x01:  # FIN flag
                    print(f"Packet {frame_nr}: HTTP POST stream {stream_key} ended (FIN)")
                    self.extract_from_stream(stream_key)

    def extract_from_stream(self, stream_key):
        if stream_key not in self.streams:
            return
        
        stream_data = self.streams[stream_key]
        payload = stream_data['payload']
        filename = stream_data['filename']
        frame_nr = stream_data['frame_nr']
        src_ip = stream_data['src_ip']
        src_port = stream_data['src_port']
        dst_ip = stream_data['dst_ip']
        dst_port = stream_data['dst_port']
        protocol = stream_data['protocol']
        details = stream_data.get('details', '')
        
        if not filename or not payload:
            print(f"Stream {stream_key}: No filename or payload to extract")
            del self.streams[stream_key]
            return
        
        try:
            filename = os.path.basename(filename)
            filepath = os.path.join(os.getcwd(), filename)
            extension = os.path.splitext(filename)[1] if '.' in filename else ""
            print(f"Stream {stream_key}: Extracting {filename}, Size: {len(payload)} bytes")
            with open(filepath, "wb") as f:
                f.write(payload)
            size = os.path.getsize(filepath)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.files_tree.insert("", "end", 
                                 values=(frame_nr, filename, extension, f"{size} bytes", src_ip, src_port, 
                                         dst_ip, dst_port, protocol, details, timestamp))
            if stream_key in self.ftp_data_ports:
                del self.ftp_data_ports[(stream_key[0], stream_key[1])]
            del self.streams[stream_key]
            print(f"Extracted file: {filename}")
        except Exception as e:
            print(f"Stream {stream_key}: Extraction error: {e}")

    def extract_pending_streams(self):
        for stream_key in list(self.streams.keys()):
            self.extract_from_stream(stream_key)

    def load_pcap(self):
        filetypes = [
            ("PCAP files", "*.pcap *.PCAP *.pcapng *.PCAPNG *.cap *.CAP"),
            ("All files", "*.*")
        ]
        file_path = filedialog.askopenfilename(title="Open PCAP File", filetypes=filetypes)
        if not file_path:
            print("No file selected")
            return
        
        file_path = os.path.normpath(file_path)
        print(f"Attempting to load PCAP file: {file_path}")
        
        try:
            if not os.path.isfile(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            if not os.access(file_path, os.R_OK):
                raise PermissionError(f"No read permission for file: {file_path}")
            
            packets = rdpcap(file_path)
            if not packets:
                print("Warning: No packets found in the PCAP file")
                messagebox.showwarning("Warning", f"No packets found in {file_path}")
                return
            
            self.captured_packets = list(packets)
            self.filtered_packets = list(packets)
            self.packet_tree.delete(*self.packet_tree.get_children())
            self.files_tree.delete(*self.files_tree.get_children())
            self.hosts_tree.delete(*self.hosts_tree.get_children())
            self.details_tree.delete(*self.details_tree.get_children())
            self.file_details_tree.delete(*self.file_details_tree.get_children())
            self.packet_count = 0
            self.streams.clear()
            self.ftp_data_ports.clear()
            self.hosts.clear()
            self.pending_data_ports.clear()
            
            for packet in packets:
                self.process_packet(packet, from_pcap=True)
            self.extract_pending_streams()
            self.update_hosts_display()
            messagebox.showinfo("Success", f"Loaded {len(packets)} packets from {file_path}")
            print(f"Successfully loaded {len(packets)} packets from {file_path}")
            
        except FileNotFoundError as e:
            print(f"Load PCAP error: {e}")
            messagebox.showerror("Error", str(e))
        except PermissionError as e:
            print(f"Load PCAP error: {e}")
            messagebox.showerror("Error", str(e))
        except Exception as e:
            print(f"Load PCAP error: {e}")
            messagebox.showerror("Error", f"Failed to load PCAP: {e}")

    def save_pcap(self):
        if not self.captured_packets:
            messagebox.showwarning("Warning", "No packets to save!")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".pcap",
                                               filetypes=[("PCAP files", "*.pcap *.cap")])
        if file_path:
            try:
                wrpcap(file_path, self.captured_packets)
                messagebox.showinfo("Success", f"Saved {len(self.captured_packets)} packets to {file_path}")
                print(f"Saved {len(self.captured_packets)} packets to {file_path}")
            except Exception as e:
                print(f"Failed to save PCAP: {e}")
                messagebox.showerror("Error", f"Failed to save PCAP: {e}")

    def show_extracted_files(self):
        self.main_notebook.select(self.files_frame)
        print("Switched to Extracted Files tab")

    def show_hosts(self):
        self.main_notebook.select(self.hosts_frame)
        print("Switched to Hosts tab")

    def show_packet_capture(self):
        self.main_notebook.select(self.packet_frame)
        print("Switched to Packet Capture tab")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()