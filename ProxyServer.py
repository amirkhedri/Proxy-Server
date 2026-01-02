import socket
import threading
import select
import datetime
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import queue
import os

HOST = '127.0.0.1'
PORT = 8080
MAX_CONN = 200
BUFFER_SIZE = 32768
CACHE_SIZE = 50
BLACKLIST = {"example.com", "badsite.org"} 
RATE_LIMIT_WINDOW = 10
MAX_REQUESTS_PER_WINDOW = 20 
LOG_FILE = "proxy_log.txt"

THEME = {
    "bg": "#0F172A",
    "panel": "#1E293B",
    "fg": "#F8FAFC",
    "accent": "#38BDF8",
    "graph_line": "#22C55E",
    "success": "#10B981",
    "warning": "#F59E0B",
    "danger": "#EF4444",
    "table_bg": "#334155"
}

SERVER_RUNNING = False
server_socket = None
log_queue = queue.Queue()

lock_stats = threading.Lock()
lock_cache = threading.Lock()
lock_rate = threading.Lock()
lock_log = threading.Lock()

class StatsEngine:
    def __init__(self):
        self.requests = 0
        self.bytes_sent = 0
        self.active_conns = 0
        self.peak_conns = 0
        self.cache_hits = 0
        self.blocked_count = 0

    def register_request(self):
        with lock_stats: self.requests += 1

    def register_bytes(self, count):
        with lock_stats: self.bytes_sent += count

    def update_conns(self, delta):
        with lock_stats:
            self.active_conns += delta
            if self.active_conns > self.peak_conns:
                self.peak_conns = self.active_conns

    def register_cache_hit(self):
        with lock_stats: self.cache_hits += 1

    def register_block(self):
        with lock_stats: self.blocked_count += 1

    def reset(self):
        with lock_stats:
            self.requests = 0
            self.bytes_sent = 0
            self.active_conns = 0
            self.peak_conns = 0
            self.cache_hits = 0
            self.blocked_count = 0

stats = StatsEngine()
cache = {}       
rate_limits = {} 

def write_to_file(msg):
    with lock_log:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except: pass

def gui_log(msg, level="INFO"):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    full_msg = f"[{timestamp}] {msg}"
    log_queue.put((full_msg, level))
    write_to_file(f"{timestamp}|{level}|{msg}") 

class ClientHandler(threading.Thread):
    def __init__(self, client_sock, client_addr):
        super().__init__()
        self.sock = client_sock
        self.ip = client_addr[0]

    def check_rate_limit(self):
        with lock_rate:
            now = time.time()
            if self.ip in rate_limits:
                rate_limits[self.ip] = [t for t in rate_limits[self.ip] if now - t < RATE_LIMIT_WINDOW]
            else:
                rate_limits[self.ip] = []
            
            if len(rate_limits[self.ip]) >= MAX_REQUESTS_PER_WINDOW: return False
            rate_limits[self.ip].append(now)
            return True

    def run(self):
        stats.update_conns(1)
        try:
            self.sock.settimeout(30)
            while SERVER_RUNNING:
                try:
                    request_data = self.sock.recv(BUFFER_SIZE)
                    if not request_data: break

                    if not self.check_rate_limit():
                        gui_log(f"RATE LIMIT: {self.ip}", "WARNING")
                        self.send_error(429, "Too Many Requests", "Slow down.")
                        break

                    try:
                        req_str = request_data.decode('ISO-8859-1')
                        first_line = req_str.split('\r\n')[0]
                        method, url, _ = first_line.split()
                    except: break

                    stats.register_request()
                    
                    host = None
                    port = 80
                    for line in req_str.split('\r\n'):
                        if line.startswith('Host:'):
                            host = line.split(':', 1)[1].strip()
                            if ':' in host: host, p = host.split(':'); port = int(p)
                            break
                    
                    if not host and '://' in url:
                        import urllib.parse
                        p = urllib.parse.urlparse(url)
                        host = p.hostname; port = p.port or 80; url = p.path

                    if host and any(b in host for b in BLACKLIST):
                        stats.register_block()
                        gui_log(f"BLOCKED: {host}", "DANGER")
                        self.send_error(403, "Access Denied", f"{host} is blocked.")
                        continue

                    if method == 'CONNECT':
                        gui_log(f"TUNNEL: {host}", "INFO")
                        self.handle_https(host, port)
                        break 
                    else:
                        gui_log(f"{method}: {host}{url}", "INFO")
                        self.handle_http(method, url, host, port, request_data)

                except socket.timeout: break
                except OSError: break
        except: pass
        finally:
            stats.update_conns(-1)
            try: self.sock.close()
            except: pass

    def send_error(self, code, title, msg):
        html = f"<html><body style='background:#111;color:#f00;text-align:center'><h1>{code} {title}</h1><p>{msg}</p></body></html>"
        resp = f"HTTP/1.1 {code} {title}\r\nContent-Type: text/html\r\nContent-Length: {len(html)}\r\nConnection: close\r\n\r\n{html}"
        self.sock.sendall(resp.encode())

    def handle_https(self, host, port):
        try:
            target = socket.create_connection((host, port), timeout=10)
            self.sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            inputs = [self.sock, target]
            while SERVER_RUNNING:
                r, _, _ = select.select(inputs, [], inputs, 10)
                if not r: break
                for s in r:
                    other = target if s is self.sock else self.sock
                    data = s.recv(BUFFER_SIZE)
                    if not data: return
                    other.sendall(data)
                    stats.register_bytes(len(data))
        except: pass
        finally:
            try: target.close()
            except: pass

    def handle_http(self, method, url, host, port, req_data):
        full_url = f"http://{host}{url}"
        if method == 'GET':
            with lock_cache:
                if full_url in cache:
                    stats.register_cache_hit()
                    gui_log(f"CACHE HIT: {host}", "SUCCESS")
                    self.sock.sendall(cache[full_url])
                    return

        try:
            target = socket.create_connection((host, port), timeout=10)
            target.sendall(req_data)
            resp_data = b""
            while True:
                chunk = target.recv(BUFFER_SIZE)
                if not chunk: break
                resp_data += chunk
                self.sock.sendall(chunk)
                stats.register_bytes(len(chunk))
            
            if method == 'GET' and len(resp_data) > 0 and len(resp_data) < 500000:
                if b"HTTP/1.1 200" in resp_data[:50]:
                    with lock_cache:
                        if len(cache) >= CACHE_SIZE: cache.pop(next(iter(cache)))
                        cache[full_url] = resp_data
            target.close()
        except: pass

def start_server_thread():
    global server_socket, SERVER_RUNNING
    SERVER_RUNNING = True
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(MAX_CONN)
        gui_log(f"Server Listening on {HOST}:{PORT}", "SUCCESS")
        while SERVER_RUNNING:
            r, _, _ = select.select([server_socket], [], [], 0.5)
            if r:
                c, a = server_socket.accept()
                ClientHandler(c, a).start()
    except Exception as e:
        gui_log(f"Startup Error: {e}", "DANGER")

def stop_server_thread():
    global SERVER_RUNNING, server_socket
    SERVER_RUNNING = False
    if server_socket: server_socket.close()
    gui_log("Server Stopped", "DANGER")

class UltimateProxyGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Amir Khedri Proxy | Ultimate Edition")
        self.root.geometry("1100x850")
        self.root.configure(bg=THEME['bg'])
        self.last_bytes = 0
        self.setup_ui()
        self.start_loops()

    def setup_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TFrame", background=THEME['bg'])
        style.configure("Panel.TFrame", background=THEME['panel'])
        style.configure("Treeview", background=THEME['table_bg'], foreground="white", fieldbackground=THEME['table_bg'], font=("Arial", 9))
        style.configure("Treeview.Heading", background=THEME['panel'], foreground="white", font=("Arial", 10, "bold"))
        style.map("Treeview", background=[('selected', THEME['accent'])])

        head = ttk.Frame(self.root)
        head.pack(fill="x", padx=20, pady=20)
        
        tk.Label(head, text="PROXY CONTROLLER", bg=THEME['bg'], fg=THEME['accent'], font=("Impact", 24)).pack(side="left")
        
        tk.Label(head, text="Amir Khedri", bg=THEME['bg'], fg=THEME['accent'], font=("Impact", 24)).pack(side="right")
        
        self.status = tk.Label(head, text="OFFLINE", bg=THEME['danger'], fg="white", font=("Arial", 10, "bold"), padx=10)
        self.status.pack(side="right", padx=(0, 20))

        stats_box = ttk.Frame(self.root)
        stats_box.pack(fill="x", padx=20)
        self.c_req = self.make_card(stats_box, "REQUESTS", "0", 0)
        self.c_hit = self.make_card(stats_box, "CACHE HITS", "0", 1)
        self.c_blk = self.make_card(stats_box, "BLOCKED", "0", 2)
        self.c_act = self.make_card(stats_box, "ACTIVE CONN", "0", 3)

        mid = ttk.Frame(self.root)
        mid.pack(fill="x", padx=20, pady=15)
        
        g_pan = ttk.Frame(mid, style="Panel.TFrame")
        g_pan.pack(side="left", fill="both", expand=True, padx=(0, 10))
        tk.Label(g_pan, text="LIVE TRAFFIC (KB/s)", bg=THEME['panel'], fg="#888").pack(anchor="w", padx=10, pady=5)
        self.graph = tk.Canvas(g_pan, height=140, bg=THEME['panel'], highlightthickness=0)
        self.graph.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.graph_data = [0]*60

        btns = ttk.Frame(mid, style="Panel.TFrame")
        btns.pack(side="right", fill="y")
        
        self.b_start = tk.Button(btns, text="START SERVER", bg=THEME['graph_line'], fg="white", font=("Arial", 10, "bold"), width=18, command=self.toggle_server)
        self.b_start.pack(pady=10, padx=15)

        tk.Button(btns, text="INSPECT CACHE", bg=THEME['accent'], fg="black", width=18, command=self.open_cache_inspector).pack(pady=5, padx=15)
        tk.Button(btns, text="VIEW LOG REPORT", bg=THEME['warning'], fg="black", width=18, command=self.open_log_table).pack(pady=5, padx=15)
        tk.Button(btns, text="CACHE TEST", bg="#555", fg="white", width=18, command=self.open_cache_test).pack(pady=5, padx=15)
        
        self.lbl_cache = tk.Label(btns, text="Cache: 0/50", bg=THEME['panel'], fg="#ccc")
        self.lbl_cache.pack(pady=10)

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=20, pady=10)
        
        t_term = ttk.Frame(nb); nb.add(t_term, text="  TERMINAL  ")
        self.term = scrolledtext.ScrolledText(t_term, bg="black", fg="white", font=("Consolas", 10))
        self.term.pack(fill="both", expand=True)
        for tag, col in [("INFO", "white"), ("WARNING", THEME['warning']), ("DANGER", THEME['danger']), ("SUCCESS", THEME['success']), ("BLOCKED", "#E91E63")]:
            self.term.tag_config(tag, foreground=col)

        t_blk = ttk.Frame(nb); nb.add(t_blk, text="  BLOCK LIST  ")
        b_head = ttk.Frame(t_blk)
        b_head.pack(fill="x", pady=10)
        self.e_blk = ttk.Entry(b_head, font=("Arial", 12))
        self.e_blk.pack(side="left", fill="x", expand=True, padx=10)
        tk.Button(b_head, text="ADD", bg=THEME['accent'], command=self.add_blk).pack(side="left", padx=5)
        
        self.l_blk = tk.Listbox(t_blk, bg=THEME['panel'], fg="white", font=("Arial", 11), selectmode=tk.SINGLE)
        self.l_blk.pack(fill="both", expand=True, padx=10, pady=5)
        tk.Button(t_blk, text="REMOVE SELECTED SITE", bg=THEME['danger'], fg="white", command=self.rem_blk).pack(fill="x", padx=10, pady=10)
        self.ref_blk()

    def make_card(self, p, t, v, c):
        f = tk.Frame(p, bg=THEME['panel'], padx=15, pady=10)
        f.grid(row=0, column=c, sticky="nsew", padx=5)
        p.columnconfigure(c, weight=1)
        tk.Label(f, text=t, bg=THEME['panel'], fg="#888", font=("Arial", 8, "bold")).pack(anchor="w")
        l = tk.Label(f, text=v, bg=THEME['panel'], fg="white", font=("Arial", 18, "bold"))
        l.pack(anchor="w")
        return l

    def toggle_server(self):
        if SERVER_RUNNING:
            stop_server_thread()
            self.b_start.config(text="START SERVER", bg=THEME['graph_line'])
            self.status.config(text="OFFLINE", bg=THEME['danger'])
        else:
            threading.Thread(target=start_server_thread, daemon=True).start()
            self.b_start.config(text="STOP SERVER", bg=THEME['danger'])
            self.status.config(text="ONLINE", bg=THEME['success'])

    def open_cache_inspector(self):
        win = tk.Toplevel(self.root)
        win.title("Cache Inspector")
        win.geometry("600x450")
        win.configure(bg=THEME['bg'])

        cols = ("URL", "Size")
        tree = ttk.Treeview(win, columns=cols, show='headings')
        tree.heading("URL", text="Cached URL")
        tree.heading("Size", text="Size (KB)")
        tree.column("URL", width=450)
        tree.column("Size", width=100)
        tree.pack(fill="both", expand=True, padx=10, pady=10)

        def load_data():
            for i in tree.get_children(): tree.delete(i)
            with lock_cache:
                for url, data in cache.items():
                    size_kb = len(data) / 1024
                    tree.insert("", "end", values=(url, f"{size_kb:.2f} KB"))

        def clear_cache_safe():
            with lock_cache: cache.clear()
            load_data()
            gui_log("Cache Manually Cleared", "WARNING")

        btn_frame = tk.Frame(win, bg=THEME['bg'])
        btn_frame.pack(fill="x", pady=10)
        tk.Button(btn_frame, text="REFRESH LIST", bg=THEME['accent'], command=load_data).pack(side="left", padx=10)
        tk.Button(btn_frame, text="CLEAR CACHE", bg=THEME['danger'], fg="white", command=clear_cache_safe).pack(side="right", padx=10)
        
        tk.Label(win, text="Developed by Amir Khedri", bg=THEME['bg'], fg="#555", font=("Arial", 10, "italic")).pack(side="bottom", pady=10)
        
        load_data()

    def open_log_table(self):
        win = tk.Toplevel(self.root)
        win.title("Log Report Viewer")
        win.geometry("900x650")
        win.configure(bg=THEME['bg'])

        tk.Label(win, text="SYSTEM LOGS", bg=THEME['bg'], fg="white", font=("Impact", 18)).pack(pady=10)
        
        frame_list = ttk.Frame(win)
        frame_list.pack(fill="both", expand=True, padx=10)

        cols = ("Time", "Level", "Message")
        tree = ttk.Treeview(frame_list, columns=cols, show='headings', selectmode="browse", height=10)
        tree.heading("Time", text="Timestamp")
        tree.heading("Level", text="Type")
        tree.heading("Message", text="Event Preview")
        tree.column("Time", width=100)
        tree.column("Level", width=80)
        tree.column("Message", width=600)
        
        sb = ttk.Scrollbar(frame_list, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        tree.pack(fill="both", expand=True)

        frame_details = tk.LabelFrame(win, text="Event Details Section", bg=THEME['panel'], fg=THEME['accent'], font=("Arial", 10, "bold"))
        frame_details.pack(fill="x", padx=10, pady=10)
        
        details_txt = tk.Text(frame_details, height=6, bg="#0a0a0a", fg="#00ff00", font=("Consolas", 10))
        details_txt.pack(fill="both", expand=True, padx=5, pady=5)

        def on_tree_select(event):
            selected_items = tree.selection()
            if selected_items:
                item = selected_items[0]
                vals = tree.item(item, 'values')
                full_text = f"TIMESTAMP: {vals[0]}\nEVENT TYPE: {vals[1]}\nDETAILS: {vals[2]}"
                details_txt.delete('1.0', 'end')
                details_txt.insert('1.0', full_text)

        tree.bind('<<TreeviewSelect>>', on_tree_select)

        def load_logs():
            for i in tree.get_children(): tree.delete(i)
            if os.path.exists(LOG_FILE):
                try:
                    with open(LOG_FILE, "r") as f:
                        for line in f.readlines():
                            parts = line.strip().split("|")
                            if len(parts) >= 3:
                                tree.insert("", "end", values=(parts[0], parts[1], parts[2]))
                except: pass

        def delete_logs():
            if messagebox.askyesno("Confirm Delete", "Are you sure you want to wipe all logs?"):
                with lock_log:
                    open(LOG_FILE, 'w').close() 
                load_logs()
                details_txt.delete('1.0', 'end')
                gui_log("Logs wiped by User", "WARNING")

        btn_box = tk.Frame(win, bg=THEME['bg'])
        btn_box.pack(fill="x", pady=10, padx=10)
        
        tk.Button(btn_box, text="BACK / CLOSE", bg="#555", fg="white", command=win.destroy).pack(side="left")
        tk.Button(btn_box, text="REFRESH", bg=THEME['accent'], command=load_logs).pack(side="left", padx=10)
        tk.Button(btn_box, text="DELETE ALL LOGS", bg=THEME['danger'], fg="white", command=delete_logs).pack(side="right")
        
        tk.Label(win, text="Developed by Amir Khedri", bg=THEME['bg'], fg="#555", font=("Arial", 10, "italic")).pack(side="bottom", pady=10)

        load_logs()

    def open_cache_test(self):
        win = tk.Toplevel(self.root)
        win.title("Test Cache")
        win.geometry("400x300")
        win.configure(bg=THEME['panel'])
        tk.Label(win, text="Enter HTTP URL to Test:", bg=THEME['panel'], fg="white").pack(pady=10)
        e = ttk.Entry(win, width=40); e.insert(0, "http://httpbin.org/ip"); e.pack(pady=5)
        def run():
            u = e.get()
            win.destroy()
            threading.Thread(target=self._test_url, args=(u,), daemon=True).start()
        tk.Button(win, text="TEST", bg=THEME['success'], command=run).pack(pady=10)
        
        tk.Label(win, text="Developed by Amir Khedri", bg=THEME['panel'], fg="#888", font=("Arial", 10, "italic")).pack(side="bottom", pady=10)

    def _test_url(self, url):
        try:
            import urllib.request
            gui_log(f"Testing: {url}", "INFO")
            ph = urllib.request.ProxyHandler({'http': f'http://{HOST}:{PORT}'})
            opener = urllib.request.build_opener(ph)
            opener.open(url).read()
            gui_log("Test Request Sent.", "SUCCESS")
        except Exception as e:
            gui_log(f"Test Failed: {e}", "DANGER")

    def add_blk(self):
        s = self.e_blk.get().strip()
        if s: BLACKLIST.add(s); self.ref_blk(); self.e_blk.delete(0, 'end')

    def rem_blk(self):
        sel = self.l_blk.curselection()
        if sel:
            site = self.l_blk.get(sel[0])
            BLACKLIST.discard(site)
            self.ref_blk()
            gui_log(f"Removed {site}", "WARNING")

    def ref_blk(self):
        self.l_blk.delete(0, 'end')
        for b in BLACKLIST: self.l_blk.insert('end', b)

    def start_loops(self):
        self.update_logs()
        self.update_stats()

    def update_logs(self):
        while not log_queue.empty():
            msg, lvl = log_queue.get()
            self.term.config(state="normal")
            self.term.insert("end", msg + "\n", lvl)
            self.term.see("end")
            self.term.config(state="disabled")
        self.root.after(50, self.update_logs)

    def update_stats(self):
        if SERVER_RUNNING:
            self.c_req.config(text=str(stats.requests))
            self.c_hit.config(text=str(stats.cache_hits))
            self.c_blk.config(text=str(stats.blocked_count))
            self.c_act.config(text=f"{stats.active_conns} (Peak: {stats.peak_conns})")
            
            with lock_cache: self.lbl_cache.config(text=f"Cache: {len(cache)}/{CACHE_SIZE}")
            
            with lock_stats: curr = stats.bytes_sent
            diff = curr - self.last_bytes
            self.last_bytes = curr
            speed = diff / 1024
            
            self.graph_data.pop(0)
            self.graph_data.append(speed)
            self.graph.delete("all")
            m = max(self.graph_data) or 1
            pts = []
            w, h = self.graph.winfo_width(), self.graph.winfo_height()
            for i, v in enumerate(self.graph_data):
                pts.extend([i * (w/59), h - ((v/m)*(h-20))])
            if len(pts)>2: self.graph.create_line(pts, fill=THEME['graph_line'], width=2)
            
            self.graph.create_text(10, 10, text=f"Current: {speed:.1f} KB/s", fill="white", font=("Arial", 10, "bold"), anchor="nw")
            self.graph.create_text(10, 30, text=f"Peak: {m:.1f} KB/s", fill="#888", font=("Arial", 9), anchor="nw")

        self.root.after(1000, self.update_stats)

if __name__ == "__main__":
    root = tk.Tk()
    app = UltimateProxyGUI(root)
    root.mainloop()
    stop_server_thread()