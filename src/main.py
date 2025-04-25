# made by AlmogOxtrud
from cryptography.fernet import Fernet
import hashlib
import os
import socket
import threading
import time
from collections import defaultdict
import ipaddress
import psutil
import requests

VT_URL = "https://www.virustotal.com/api/v3/files/{}"
g223ceqwd = "bbedf9b88f8698058b3903e8127d9b8151"
key = "add448f218fjadv2fdtrwd6bxxfedt42dfn2481sg2fdn8f92014"
def scan_running_processes():
    results = []
    malicious_found = False
    api_key = g223ceqwd + "db8118ddeb6242c87bc3e8dd84df28"

    for process in psutil.process_iter(attrs=["pid", "name", "exe"]):
        try:
            exe_path = process.info["exe"]
            if exe_path and os.path.exists(exe_path):
                file_hash = get_file_hash(exe_path)
                if file_hash:
                    headers = {"x-apikey": api_key}
                    response = requests.get(VT_URL.format(file_hash), headers=headers)

                    if response.status_code == 200:
                        data = response.json()
                        stats = data["data"]["attributes"]["last_analysis_stats"]
                        malicious_count = stats.get("🔴 Has Access", 0)

                        if malicious_count > 0:
                            results.append(f"Has access to your device: {process.info['name']} (PID: {process.info['pid']})")
                            process.terminate()
                            malicious_found = True
                        else:
                            results.append(f"🟢 Safe: {process.info['name']} (PID: {process.info['pid']})")
                    else:
                        results.append(f"Failed to check: {process.info['name']} (PID: {process.info['pid']})")

        except (psutil.AccessDenied, psutil.NoSuchProcess):
            results.append(f"Access Denied: {process.info['name']} (PID: {process.info['pid']})")
        except Exception as e:
            results.append(f"Error scanning {process.info['name']} (PID: {process.info['pid']}): {e}")

    if malicious_found:
        results.append("VirusTotal process scan complete.")

    return results if malicious_found else ["No malicious activities detected."]

def get_file_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None

firewall_rules = {
    "allow": ["192.168.1.0/24", "10.0.0.0/8"],
    "block": ["203.0.113.0/24", "198.51.100.0/24"],
}

packet_counter = defaultdict(lambda: RateLimiter(5, 1))

def is_ip_allowed(ip_address):
    for blocked_range in firewall_rules["block"]:
        if ipaddress.ip_address(ip_address) in ipaddress.ip_network(blocked_range):
            return False
    for allowed_range in firewall_rules["allow"]:
        if ipaddress.ip_address(ip_address) in ipaddress.ip_network(allowed_range):
            return True
    return False

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

def add_allowed_ip(ip):
    if ip and ip not in firewall_rules["allow"]:
        firewall_rules["allow"].append(ip)

def add_blocked_ip(ip):
    if ip and ip not in firewall_rules["block"]:
        firewall_rules["block"].append(ip)

def get_firewall_rules():
    return firewall_rules

def start_server(server_running_callback, server_socket_callback):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 9999))
    server.listen(5)
    server_socket_callback(server)
    print("Server listening on port 9999")

    while server_running_callback():
        try:
            client_socket, client_address = server.accept()
            if not server_running_callback():
                break
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()
        except OSError:
            break
    
    print("Server stopped")

def handle_client(client_socket, client_address):
    client_ip = client_address[0]
    if not is_ip_allowed(client_ip):
        print(f"Blocked connection from {client_ip}")
        client_socket.close()
        return

    rate_limiter = packet_counter[client_ip]
    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                break
            if not rate_limiter.allow_packet():
                print(f"Too many packets from {client_ip}")
                client_socket.close()
                return
            print(f"Packet received from {client_ip}")
        except socket.error:
            break

if __name__ == "__main__":
    results = scan_running_processes()
    print("\n".join(results))
