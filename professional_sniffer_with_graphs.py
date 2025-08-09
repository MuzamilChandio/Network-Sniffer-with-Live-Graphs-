"""
professional_sniffer_with_graphs.py

Professional "hacker-style" GUI sniffer with:
 - Target IP/domain input and protocol filter
 - Start / Stop sniffing
 - Built-in simple port scanner (ports 1-1024)
 - Live textual log
 - Live graphs: protocol counts (bar) and packets-per-second (line)

Requirements:
  pip install scapy matplotlib

Run as Administrator on Windows for capture.
"""
import socket
import struct
import textwrap
import threading
import time
import queue
from collections import Counter, deque
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import sys

# Try scapy imports
USE_SCAPY = True
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, conf
except Exception as e:
    USE_SCAPY = False
    print("Scapy import failed:", e)
    print("Install Scapy: pip install scapy")
    # We'll still allow listing and port-scan but sniffing won't work

# Matplotlib for embedding graphs
try:
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
except Exception as e:
    print("Matplotlib import failed:", e)
    print("Install Matplotlib: pip install matplotlib")
    raise

# ----------------------------
# Globals & state
# ----------------------------
sniff_thread = None
stop_event = None
log_queue = queue.Queue()
protocol_counts = Counter()
pps_history = deque(maxlen=60)   # last 60 seconds
pps_timestamps = deque(maxlen=60)
pkt_count_this_second = 0
last_second_tick = int(time.time())
pkt_lock = threading.Lock()

# supported protocol keys for graphing
PROT_KEYS = ["TCP", "UDP", "ICMP", "ARP", "DNS", "OTHER"]

# ----------------------------
# Utilities
# ----------------------------
def resolve_target(value):
    try:
        return socket.gethostbyname(value)
    except Exception:
        return None

def enqueue_log(s):
    log_queue.put(s)

def process_packet_stats(proto_name):
    global pkt_count_this_second, last_second_tick
    with pkt_lock:
        protocol_counts[proto_name] += 1
        now = int(time.time())
        if now == last_second_tick:
            pkt_count_this_second += 1
        else:
            # push previous second count, shift time
            pps_history.append(pkt_count_this_second)
            pps_timestamps.append(last_second_tick)
            # reset
            pkt_count_this_second = 1
            last_second_tick = now

# ----------------------------
# Packet processing callback
# ----------------------------
def packet_processor(pkt, target_ip=None, protocol_filter=None):
    """
    Called for each packet by the sniff thread.
    We filter by target_ip (if set) and protocol_filter (if set),
    update counters and push human-readable log lines to UI queue.
    """
    try:
        # Basic IP/ARP checks
        proto = "OTHER"
        summary = None
        if ARP in pkt:
            proto = "ARP"
            summary = pkt.summary()
        elif IP in pkt:
            ip = pkt[IP]
            src = ip.src
            dst = ip.dst
            # target filter
            if target_ip and src != target_ip and dst != target_ip:
                return
            if TCP in pkt:
                proto = "TCP"
            elif UDP in pkt:
                proto = "UDP"
            elif ICMP in pkt:
                proto = "ICMP"
            # DNS detection (over UDP typically) - check layers
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                proto = "DNS"
            summary = pkt.summary()
        else:
            # not IP/ARP; optionally ignore
            if target_ip:
                # if user set target IP, skip non-IP packets
                return
            summary = pkt.summary()

        # protocol filter if provided
        if protocol_filter:
            pf = protocol_filter.strip().upper()
            if pf and pf not in summary.upper() and pf not in proto:
                return

        # update stats and queue log
        process_packet_stats(proto)
        enqueue_log(f"[{time.strftime('%H:%M:%S')}] {summary}")

    except Exception as e:
        enqueue_log(f"[ERROR] packet processing: {e}")

# ----------------------------
# Sniffing Thread
# ----------------------------
def sniffing_thread_func(iface, target_ip, protocol_filter, user_stop_event):
    """
    Runs in background: calls scapy.sniff and uses a prn callback.
    stop governed by user_stop_event; uses stop_filter to stop.
    """
    if not USE_SCAPY:
        enqueue_log("[ERROR] Scapy not available — sniffing disabled.")
        return

    # prefer pcap backend on Windows when available
    if sys.platform.startswith("win"):
        try:
            conf.use_pcap = True
        except Exception:
            pass

    # prn wrapper to call our packet_processor and allow stop
    def prn(pkt):
        if user_stop_event.is_set():
            # return something that stop_filter can use; scapy sniff will still rely on stop_filter
            return
        packet_processor(pkt, target_ip=target_ip, protocol_filter=protocol_filter)

    # stop_filter uses user_stop_event
    try:
        enqueue_log("[INFO] Sniffing started...")
        sniff(iface=iface if iface else None,
              prn=prn,
              store=False,
              stop_filter=lambda x: user_stop_event.is_set())
    except Exception as e:
        enqueue_log(f"[ERROR] Sniffing failed: {e}")

    enqueue_log("[INFO] Sniffing stopped.")

# ----------------------------
# Port scanning (simple, 1-1024)
# ----------------------------
def simple_port_scan(target, output_widget):
    try:
        ip = resolve_target(target) if not all(ch.isdigit() or ch=='.' for ch in target) else target
        if not ip:
            output_widget.insert(tk.END, f"[SCAN] Could not resolve target: {target}\n")
            return
    except Exception:
        output_widget.insert(tk.END, f"[SCAN] Invalid target: {target}\n")
        return

    output_widget.insert(tk.END, f"[SCAN] Starting port scan on {ip} (1-1024)...\n")
    output_widget.see(tk.END)
    for port in range(1, 1025):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            res = sock.connect_ex((ip, port))
            if res == 0:
                output_widget.insert(tk.END, f"[OPEN] Port {port}\n")
                output_widget.see(tk.END)
            sock.close()
        except Exception:
            pass
    output_widget.insert(tk.END, "[SCAN] Complete.\n")
    output_widget.see(tk.END)

# ----------------------------
# GUI & Graphing
# ----------------------------
class SnifferGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Professional Network Sniffer")
        self.geometry("1100x700")
        self.configure(bg="black")

        # top controls
        top = tk.Frame(self, bg="black")
        top.pack(fill="x", padx=8, pady=6)

        tk.Label(top, text="Target IP/Domain:", fg="cyan", bg="black", font=("Consolas", 10)).pack(side="left")
        self.target_entry = tk.Entry(top, width=28, bg="black", fg="lime", insertbackground="lime", font=("Consolas", 10))
        self.target_entry.pack(side="left", padx=6)

        tk.Label(top, text="Protocol Filter:", fg="cyan", bg="black", font=("Consolas", 10)).pack(side="left", padx=(12,0))
        self.protocol_combo = ttk.Combobox(top, values=["", "TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP"], width=8)
        self.protocol_combo.pack(side="left", padx=6)

        tk.Label(top, text="Interface (optional):", fg="cyan", bg="black", font=("Consolas", 10)).pack(side="left", padx=(12,0))
        self.iface_entry = tk.Entry(top, width=18, bg="black", fg="lime", font=("Consolas", 10))
        self.iface_entry.pack(side="left", padx=6)

        self.start_btn = tk.Button(top, text="Start Sniffing", bg="lime", fg="black", command=self.start_sniff)
        self.start_btn.pack(side="left", padx=6)
        self.stop_btn = tk.Button(top, text="Stop Sniffing", bg="red", fg="white", command=self.stop_sniff, state="disabled")
        self.stop_btn.pack(side="left", padx=6)

        self.scan_btn = tk.Button(top, text="Port Scan (1-1024)", bg="orange", fg="black", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=6)

        self.save_btn = tk.Button(top, text="Save Log", bg="yellow", fg="black", command=self.save_log)
        self.save_btn.pack(side="left", padx=6)

        # layout middle: left = text log, right = graphs
        mid = tk.Frame(self, bg="black")
        mid.pack(fill="both", expand=True, padx=8, pady=6)

        # log widget
        left = tk.Frame(mid, bg="black")
        left.pack(side="left", fill="both", expand=True)

        tk.Label(left, text="Packet Log", bg="black", fg="lime", font=("Consolas", 12)).pack(anchor="w")
        self.log = scrolledtext.ScrolledText(left, bg="black", fg="lime", insertbackground="lime", font=("Consolas", 10))
        self.log.pack(fill="both", expand=True, padx=4, pady=4)

        # right: graphs frame
        right = tk.Frame(mid, bg="black")
        right.pack(side="right", fill="y", padx=4)

        tk.Label(right, text="Live Protocol Counts", bg="black", fg="lime", font=("Consolas", 12)).pack()
        self.fig1 = Figure(figsize=(4,2.5), dpi=100)
        self.ax1 = self.fig1.add_subplot(111)
        self.ax1.set_facecolor("#0d0d0d")
        self.canvas1 = FigureCanvasTkAgg(self.fig1, master=right)
        self.canvas1.get_tk_widget().pack(padx=6, pady=6)

        tk.Label(right, text="Packets Per Second (last 60s)", bg="black", fg="lime", font=("Consolas", 12)).pack()
        self.fig2 = Figure(figsize=(4,2.5), dpi=100)
        self.ax2 = self.fig2.add_subplot(111)
        self.ax2.set_facecolor("#0d0d0d")
        self.canvas2 = FigureCanvasTkAgg(self.fig2, master=right)
        self.canvas2.get_tk_widget().pack(padx=6, pady=6)

        # status bar
        self.status = tk.Label(self, text="Status: Idle", bg="black", fg="cyan", anchor="w", font=("Consolas", 10))
        self.status.pack(fill="x", side="bottom")

        # schedule UI updates
        self.after(300, self.process_log_queue)
        self.after(1000, self.update_graphs)

    # Start sniffing: spawn thread
    def start_sniff(self):
        global sniff_thread, stop_event, protocol_counts, pps_history, pkt_count_this_second, pps_timestamps
        if not USE_SCAPY:
            messagebox.showerror("Error", "Scapy not installed. Install scapy to sniff packets.")
            return

        if sniff_thread and sniff_thread.is_alive():
            messagebox.showinfo("Info", "Sniffer already running.")
            return

        # reset counters
        protocol_counts.clear()
        pps_history.clear()
        while pps_timestamps:
            pps_timestamps.popleft()
        with pkt_lock:
            global pkt_count_this_second, last_second_tick
            pkt_count_this_second = 0
            last_second_tick = int(time.time())

        target = self.target_entry.get().strip()
        if target:
            t_ip = resolve_target(target) or target
        else:
            t_ip = None

        proto_filter = self.protocol_combo.get().strip() or None
        iface = self.iface_entry.get().strip() or None

        # create stop event
        stop_event = threading.Event()
        self._stop_event = stop_event

        # start sniff thread
        sniff_thread = threading.Thread(target=sniffing_thread_func, args=(iface, t_ip, proto_filter, stop_event), daemon=True)
        sniff_thread.start()

        self.status.config(text=f"Status: Sniffing (target={t_ip or 'any'} proto={proto_filter or 'any'})")
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

    def stop_sniff(self):
        # set stop_event
        if hasattr(self, "_stop_event") and self._stop_event:
            self._stop_event.set()
        self.status.config(text="Status: Stopping...")
        # allow some time
        self.after(500, lambda: self.status.config(text="Status: Idle"))
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def start_scan(self):
        tgt = self.target_entry.get().strip()
        if not tgt:
            messagebox.showwarning("Input required", "Please enter a target IP or domain for port scanning.")
            return
        # run scan in background
        threading.Thread(target=simple_port_scan, args=(tgt, self.log), daemon=True).start()

    def save_log(self):
        text = self.log.get("1.0", tk.END)
        if not text.strip():
            messagebox.showinfo("No data", "No log data to save.")
            return
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            messagebox.showinfo("Saved", f"Log saved to {path}")

    def process_log_queue(self):
        while True:
            try:
                s = log_queue.get_nowait()
            except queue.Empty:
                break
            else:
                self.log.insert(tk.END, s + "\n")
                self.log.see(tk.END)
        self.after(300, self.process_log_queue)

    def update_graphs(self):
        # update protocol bar chart
        counts = [protocol_counts.get(k, 0) for k in PROT_KEYS]
        self.ax1.clear()
        bars = self.ax1.bar(PROT_KEYS, counts, color=["#66ff66" if c>0 else "#263626" for c in counts])
        self.ax1.set_facecolor("#0d0d0d")
        self.ax1.set_title("Protocol Counts", color="lime", fontsize=10)
        self.ax1.tick_params(colors="lime")
        # annotate counts
        for rect, val in zip(bars, counts):
            height = rect.get_height()
            self.ax1.text(rect.get_x() + rect.get_width()/2.0, height + 0.1, str(val), ha='center', va='bottom', color='white', fontsize=8)

        self.canvas1.draw()

        # update PPS line chart
        # We consider pps_history; append current second count into view (do not mutate original)
        with pkt_lock:
            cur = pkt_count_this_second
        hist = list(pps_history) + [cur]
        xs = list(range(-len(hist)+1, 1))  # relative seconds
        self.ax2.clear()
        self.ax2.plot(xs, hist, marker='o', linestyle='-', color='#66ff66')
        self.ax2.set_facecolor("#0d0d0d")
        self.ax2.set_title("Packets/sec (relative time)", color="lime", fontsize=10)
        self.ax2.tick_params(colors="lime")
        # annotate last value
        if hist:
            self.ax2.text(0, hist[-1], f"{hist[-1]} pps", color="white", fontsize=8)

        self.canvas2.draw()

        # schedule next update
        self.after(1000, self.update_graphs)

# ----------------------------
# Start GUI
# ----------------------------
if __name__ == "__main__":
    app = SnifferGUI()
    app.mainloop()
