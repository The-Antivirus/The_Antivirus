import hashlib
import os
import socket
import threading
import time
from collections import defaultdict
import ipaddress
import psutil

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


def scan_running_processes():
    known_signatures = {
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'a3b5c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852a123',
        '707b752f6bd89d4f97d08602d0546a56d27acfe00e6d5df2a2cb67c5e2eeee30',
        'd0ed92fc807399e522729fb4e47619b295ee19ea8f6f8b2783af449c9e9b70ca',
        'ccc128b0e22257e0ae1b4f87b7660fad90fd4ca71fdf96030d3361220805626b',
        'cc357e0c0d1b4b0c9cdaaa2f7fd530c7fcee6c62136462c1533d50971f97d976',
        '314c7809fde7cf6057a79ae5f14382232c64abfdb4bee5c4ca3a467115052612',
        '7075c0dc922a35a37938013c66a4689ce2048303d5e5ff78e3f0ef9c5c161e95',
        '87bc45c5391ad7c0d752e6d1d0f0eaa6a85bd1fd9412a59f756531e11dad7d14',
        'a896l274m892o262g588o262x756t372r019u287d1898ddf2871gh18adf18d9r',
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

    results = []
    malicious_found = False

    for process in psutil.process_iter(attrs=['pid', 'name', 'exe']):
        try:
            exe_path = process.info['exe']
            if exe_path and os.path.exists(exe_path):
                with open(exe_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                    if file_hash in known_signatures:
                        results.append(f"Malicious process detected: {process.info['name']} (PID: {process.info['pid']})")
                        malicious_found = True
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            results.append(f"Access Denied: {process.info['name']} (PID: {process.info['pid']})")
        except Exception as e:
            results.append(f"Error scanning {process.info['name']} (PID: {process.info['pid']}): {e}")

    if not malicious_found:
        results.append("No malicious activities were detected.")

    results.append("Process scan complete.")
    return results


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
    server_socket_callback(server)  # Pass the server socket back to the caller
    print("Server listening on port 9999")

    while server_running_callback():
        try:
            client_socket, client_address = server.accept()
            if not server_running_callback():
                break
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()
        except OSError:
            # This exception occurs when the socket is closed
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