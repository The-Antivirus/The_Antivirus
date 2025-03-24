import hashlib
import os
import socket
import threading
import time
import tkinter as tk
from tkinter import scrolledtext
from collections import defaultdict
import ipaddress


class UI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("פרוייקט אנטיוירוס")
        self.root.geometry("600x500")
        self.server_thread = None
        self.server_running = False
        self.create_main_screen()

    def create_main_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        title = tk.Label(self.root, text="Antivirus Group Project", font=("Arial", 16))
        title.pack(pady=10)

        scan_button = tk.Button(self.root, text="Scan for Ransomware", command=self.create_ransomware_ui)
        scan_button.pack(pady=10)

        firewall_button = tk.Button(self.root, text="Manage Firewall", command=self.create_firewall_ui)
        firewall_button.pack(pady=10)

        if self.server_running:
            status_label = tk.Label(self.root, text="Anti-DDoS Server is running", fg="green")
            status_label.pack(pady=10)

            stop_button = tk.Button(self.root, text="Turn Off Anti-DDoS Server", command=self.stop_anti_ddos)
            stop_button.pack(pady=10)
        else:
            start_button = tk.Button(self.root, text="Turn On Anti-DDoS Server", command=self.start_anti_ddos)
            start_button.pack(pady=10)

    def create_ransomware_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        title = tk.Label(self.root, text="Malware Scanner", font=("Arial", 16))
        title.pack(pady=10)

        scan_button = tk.Button(self.root, text="Scan for Malware", command=self.scan_downloads_folder)
        scan_button.pack(pady=10)

        self.directory = tk.Entry(self.root)
        self.directory.pack(pady=5)

        self.results_text = scrolledtext.ScrolledText(self.root, width=40, height=10)
        self.results_text.pack(pady=10)

        back_button = tk.Button(self.root, text="Back", command=self.create_main_screen)
        back_button.pack(pady=10)

    def check_file_signature(self, file_path, known_signatures):
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        return file_hash in known_signatures

    def scan_downloads_folder(self):
        known_signatures = {
            'd2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2',
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'a3b5c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852a123',
            '707b752f6bd89d4f97d08602d0546a56d27acfe00e6d5df2a2cb67c5e2eeee30',
            'd0ed92fc807399e522729fb4e47619b295ee19ea8f6f8b2783af449c9e9b70ca',
            'ccc128b0e22257e0ae1b4f87b7660fad90fd4ca71fdf96030d3361220805626b',
            'cc357e0c0d1b4b0c9cdaaa2f7fd530c7fcee6c62136462c1533d50971f97d976',
            '314c7809fde7cf6057a79ae5f14382232c64abfdb4bee5c4ca3a467115052612',
            '7075c0dc922a35a37938013c66a4689ce2048303d5e5ff78e3f0ef9c5c161e95',
            '87bc45c5391ad7c0d752e6d1d0f0eaa6a85bd1fd9412a59f756531e11dad7d14',
            '536012472276876c66374e461e0602d09258425560ba0558b67e118d8add90b6',
            '44e089be452e07bfff71b7aeee2fc9fa521a70356395730948c8077342b18ebc',
            '716176a7908908c64ef32e0fab308cc25d444d565573fe0fad432d61ce7e0a92',
            'ba5e410b54cdce460216aa7234e50f6ebd25badb5ebbc65337ce67327eb25e57',
            '27efe62f4344b7e6c626e2a3bb1e6307c6e2c522d9c99a1f5e8ceaa4fa211b15',
            '79a64e6fe4655e53d3efd7a7dbedd6aa6dc4b00dcc07e8351505d20e1ce2c1d0',
            '9c460f2355bf32e2c407767729ba0b0134f4563be9730e51c70dbaa09c25fb32',
            '1d25f7af62786393a933913bcbd4e0412b7261817ecea3aeb60e2294adaece9d',
            '2f7c4001b496b4bb53c75014f83a55bb7cdf06254806f5cd4591c5af4e146de7',
            '3d2d4932b38d1e1d37482e994eba2c33927a90e9452ee52c06b5049cfa96fb58'
        }

        downloads_folder = os.path.expanduser(self.directory.get())

        files = sorted(
            (os.path.join(root, file) for root, _, files in os.walk(downloads_folder) for file in files),
            key=os.path.getmtime,
            reverse=True
        )

        if len(files) > 30:
            for file_path in files[:30]:
                if self.check_file_signature(file_path, known_signatures):
                    self.results_text.insert(tk.END, f"Ransomware detected in file: {file_path}\n")
                else:
                    self.results_text.insert(tk.END, "No suspicious activities were caught.\n")
        else:
            for file_path in files:
                if self.check_file_signature(file_path, known_signatures):
                    self.results_text.insert(tk.END, f"Ransomware detected in file: {file_path}\n")
                else:
                    self.results_text.insert(tk.END, "No suspicious activities were caught.\n")

        self.results_text.insert(tk.END, "Scan complete.\n \n \n \n")

    def start_anti_ddos(self):
        if not self.server_running:
            self.server_thread = threading.Thread(target=start_server, daemon=True)
            self.server_thread.start()
            self.server_running = True
            self.create_main_screen()

    def stop_anti_ddos(self):
        global server
        self.server_running = False
        if server:
            server.close()
        self.create_main_screen()

    def create_firewall_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        title = tk.Label(self.root, text="Firewall Manager", font=("Arial", 16))
        title.pack(pady=10)

        self.allow_entry = tk.Entry(self.root)
        self.allow_entry.pack(pady=5)
        self.allow_button = tk.Button(self.root, text="Add Allowed IP", command=self.add_allowed_ip)
        self.allow_button.pack(pady=5)

        self.block_entry = tk.Entry(self.root)
        self.block_entry.pack(pady=5)
        self.block_button = tk.Button(self.root, text="Add Blocked IP", command=self.add_blocked_ip)
        self.block_button.pack(pady=5)

        self.current_rules_text = scrolledtext.ScrolledText(self.root, width=40, height=10)
        self.current_rules_text.pack(pady=10)

        back_button = tk.Button(self.root, text="Back", command=self.create_main_screen)
        back_button.pack(pady=10)

        self.display_firewall_rules()

    def add_allowed_ip(self):
        ip = self.allow_entry.get()
        if ip and ip not in firewall_rules["allow"]:
            firewall_rules["allow"].append(ip)
            self.display_firewall_rules()

    def add_blocked_ip(self):
        ip = self.block_entry.get()
        if ip and ip not in firewall_rules["block"]:
            firewall_rules["block"].append(ip)
            self.display_firewall_rules()

    def display_firewall_rules(self):
        self.current_rules_text.delete(1.0, tk.END)
        self.current_rules_text.insert(tk.END, "Allowed IPs:\n")
        for ip in firewall_rules["allow"]:
            self.current_rules_text.insert(tk.END, f"{ip}\n")
        self.current_rules_text.insert(tk.END, "\nBlocked IPs:\n")
        for ip in firewall_rules["block"]:
            self.current_rules_text.insert(tk.END, f"{ip}\n")


class RateLimiter:
    def __init__(self, rate, per):
        self.rate = rate
        self.per = per
        self.allowance = rate
        self.last_check = time.time()

    def allow_packet(self):
        current = time.time()
        time_passed = current - self.last_check
        self.last_check = current
        self.allowance += time_passed * (self.rate / self.per)

        if self.allowance > self.rate:
            self.allowance = self.rate

        if self.allowance < 1.0:
            return False
        else:
            self.allowance -= 1.0
            return True


packet_counter = defaultdict(lambda: RateLimiter(5, 1))


firewall_rules = {
    "allow": ["192.168.1.0/24", "10.0.0.0/8"],
    "block": ["203.0.113.0/24", "198.51.100.0/24"],
}


def is_ip_allowed(ip_address):
    for blocked_range in firewall_rules["block"]:
        if ipaddress.ip_address(ip_address) in ipaddress.ip_network(blocked_range):
            return False
    for allowed_range in firewall_rules["allow"]:
        if ipaddress.ip_address(ip_address) in ipaddress.ip_network(allowed_range):
            return True
    return False


def handle_client(client_socket, client_address):
    client_ip = client_address[0]
    if not is_ip_allowed(client_ip):
        print(f"Connection from {client_ip} blocked by firewall.")
        client_socket.close()
        return

    rate_limiter = packet_counter[client_ip]

    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                break

            if not rate_limiter.allow_packet():
                print(f"Too many packets from {client_ip}. Connection closed.")
                client_socket.close()
                return

            print(f"Packet received from {client_ip}")

        except socket.error:
            break


def start_server():
    global server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 9999))
    server.listen(5)
    print("Server listening on port 9999")

    while True:
        try:
            client_socket, client_address = server.accept()
            print(f"Accepted connection from {client_address}")
            client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_handler.start()

        except Exception as e:
            print(f"Server error: {e}")
            break

if __name__ == "__main__":
    app = UI()
    app.start_anti_ddos()
    app.root.mainloop()