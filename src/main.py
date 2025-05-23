import sys
import hashlib
import os
import socket
import threading
import time
from collections import defaultdict
import ipaddress
import psutil
import requests
import speech_recognition as sr  # NEW: For voice recognition
from googletrans import Translator # NEW: For translation (removed service_urls)

import ai
from ui import ChatBox # Assuming ui.py is in the same directory

from PyQt6.QtCore import QObject, pyqtSignal, QThread, Qt
from PyQt6.QtWidgets import QApplication, QVBoxLayout

VT_URL = "https://www.virustotal.com/api/v3/files/{}"
key = "b2387dh37shef38dbe3yfbv37bbdd37fake84b732dd73b823dbb361bd8182brf3n"
API = "8127bwyd7sd3gsd7832hd712fake38fvsh38fhvb39djasd92hfbds772bfd82bf" + key
z3ncmr23u = "b8118ddeb6242c87bc3e8dd84df28"
VIRUSTOTAL_API_KEY = "bbedf9b88f8698058b3903e8127d9b8151d" + z3ncmr23u

class Worker(QObject):
    ai_response_signal = pyqtSignal(str)
    scan_status_signal = pyqtSignal(str)
    scan_result_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        # NEW: Initialize speech recognizer and translator
        self.recognizer = sr.Recognizer()
        # Use a specific service_urls to avoid common googletrans issues
        self.translator = Translator()

    def process_user_prompt(self, user_prompt):
        """Handles text prompts from the UI."""
        self.scan_status_signal.emit("AI analyzing text prompt...")
        self._send_prompt_to_ai_and_process_response(user_prompt)

    def process_voice_input(self):
        """
        NEW: Handles voice input, converts to text, translates,
        and then passes to AI.
        """
        self.scan_status_signal.emit("Listening for voice input... Please speak now.")
        try:
            with sr.Microphone() as source:
                # Adjust for ambient noise for better recognition
                self.recognizer.adjust_for_ambient_noise(source)
                audio = self.recognizer.listen(source, timeout=7, phrase_time_limit=7) # Listen for up to 7 seconds

            self.scan_status_signal.emit("Speech detected. Recognizing...")
            recognized_text = self.recognizer.recognize_google(audio) # Use Google Web Speech API

            self.ai_response_signal.emit(f"<p style='color:#007bff; font-weight:bold;'>You (Voice):</p><p>{recognized_text}</p>")
            
            # Now, attempt to translate the recognized text
            translated_text = self._translate_prompt_to_english(recognized_text)
            
            # Pass the translated (or original if translation failed) prompt to the AI
            self._send_prompt_to_ai_and_process_response(translated_text, is_voice_input=True)

        except sr.UnknownValueError:
            self.scan_status_signal.emit("Could not understand audio. Please try again.")
        except sr.RequestError as e:
            self.scan_status_signal.emit(f"Could not request results from speech recognition service; {e}")
        except Exception as e:
            self.scan_status_signal.emit(f"Error during voice input: {e}")

    def _translate_prompt_to_english(self, prompt):
        """Attempts to translate the given prompt to English."""
        try:
            detected_lang = self.translator.detect(prompt).lang
            if detected_lang != 'en':
                self.scan_status_signal.emit(f"Translating prompt from '{detected_lang}' to English...")
                translation = self.translator.translate(prompt, src=detected_lang, dest='en')
                translated_prompt = translation.text
                self.ai_response_signal.emit(f"<p style='color:#6c757d;'><i>(Translated: {translated_prompt})</i></p>")
                return translated_prompt
            else:
                self.scan_status_signal.emit("Prompt is already in English.")
                return prompt
        except Exception as e:
            self.scan_status_signal.emit(f"Translation failed: {e}. Proceeding with original prompt.")
            return prompt # Fallback to original prompt if translation fails

    def _send_prompt_to_ai_and_process_response(self, prompt, is_voice_input=False):
        """
        Centralized function to send prompt to AI and process its response
        for both text and voice inputs.
        """
        if is_voice_input:
            self.scan_status_signal.emit("AI analyzing translated voice prompt...")
        else:
            self.scan_status_signal.emit("AI analyzing text prompt...")

        ai_response = ai.generate_prompt(prompt) # AI processes the prompt
        self.ai_response_signal.emit(f"<p style='color:#28a745; font-weight:bold;'>AI:</p><p>{ai_response}</p>")

        if ai_response.startswith("SUSPICION_DETECTED:"):
            suspicion_data = ai_response[len("SUSPICION_DETECTED:"):]
            suspicions = suspicion_data.split(', ')
            
            for suspicion in suspicions:
                if suspicion == "downloads":
                    self.scan_status_signal.emit("AI detected 'downloads' suspicion. Initiating Downloads folder scan...")
                    downloads_path = os.path.join(os.path.expanduser("~"), "Downloads")
                    self._scan_directory(downloads_path)
                elif suspicion == "running_file":
                    self.scan_status_signal.emit("AI detected 'running_file' suspicion. Initiating running process scan...")
                    self._scan_running_processes()
                else:
                    self.scan_status_signal.emit(f"AI detected unrecognized suspicion: {suspicion}")
        else:
            self.scan_status_signal.emit("No specific security suspicion detected by AI. Performing default process scan...")
            self._scan_running_processes()

        all_scan_results = ai.get_queue_contents()
        if all_scan_results:
            self.scan_status_signal.emit("--- All Scan Results ---")
            for result in all_scan_results:
                self.scan_result_signal.emit(result)
        else:
            self.scan_status_signal.emit("No specific scan results to display from the queue.")

    def _scan_directory(self, directory_path):
        if not os.path.isdir(directory_path):
            self.scan_result_signal.emit(f"🔴 Error: Directory not found: {directory_path}")
            return

        self.scan_status_signal.emit(f"Scanning directory: {directory_path}...")
        malicious_found_in_dir = False

        for root, _, files in os.walk(directory_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                if file_name.lower().endswith((".exe", ".dll", ".bat", ".ps1", ".vbs", ".cmd")):
                    try:
                        file_hash = _get_file_hash(file_path)
                        if not file_hash:
                            self.scan_result_signal.emit(f"🟡 File: {file_name} - Could not generate hash")
                            continue

                        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
                        response = requests.get(VT_URL.format(file_hash), headers=headers)

                        if response.status_code == 200:
                            data = response.json()
                            stats = data["data"]["attributes"]["last_analysis_stats"]
                            malicious_count = stats.get("malicious", 0)

                            result_prefix = "🟢"
                            if malicious_count > 0:
                                result_prefix = "🔴"
                                malicious_found_in_dir = True

                            result = f"{result_prefix} File: {file_name}"
                            if malicious_count > 0:
                                result += f" - Malicious detected ({malicious_count} engines)"
                            else:
                                result += " - Safe"
                        elif response.status_code == 404:
                            result = f"🟡 File: {file_name} - Hash not found on VirusTotal"
                        else:
                            result = f"🟠 File: {file_name} - VirusTotal API Error: {response.status_code} - {response.text}"
                    except requests.exceptions.RequestException as req_e:
                        result = f"🟠 File: {file_name} - Network Error: {req_e}"
                    except Exception as e:
                        result = f"Error scanning {file_name}: {e}"

                    self.scan_result_signal.emit(result)

        if malicious_found_in_dir:
            self.scan_status_signal.emit(f"🔴 Directory scan of {directory_path} complete. Malicious files found.")
        else:
            self.scan_status_signal.emit(f"🟢 Directory scan of {directory_path} complete. No malicious executable files detected.")

    def _scan_running_processes(self):
        malicious_found = False
        self.scan_status_signal.emit("Scanning running processes...")

        for process in psutil.process_iter(attrs=["pid", "name", "exe"]):
            try:
                exe_path = process.info["exe"]
                if not exe_path or not os.path.exists(exe_path):
                    continue

                file_hash = _get_file_hash(exe_path)
                if not file_hash:
                    self.scan_result_signal.emit(f"🟡 {process.info['name']} (PID: {process.info['pid']}) - Could not generate hash")
                    continue

                headers = {"x-apikey": VIRUSTOTAL_API_KEY}
                response = requests.get(VT_URL.format(file_hash), headers=headers)

                if response.status_code == 200:
                    data = response.json()
                    stats = data["data"]["attributes"]["last_analysis_stats"]
                    malicious_count = stats.get("malicious", 0)

                    result_prefix = "🟢"
                    if malicious_count > 0:
                        result_prefix = "🔴"
                        malicious_found = True
                        try:
                            process.terminate()
                            self.scan_result_signal.emit(f"🔴 Terminated: {process.info['name']} (PID: {process.info['pid']})")
                        except psutil.AccessDenied:
                            self.scan_result_signal.emit(f"🟠 Failed to terminate: {process.info['name']} (PID: {process.info['pid']}) - Access Denied")
                        except Exception as term_e:
                            self.scan_result_signal.emit(f"🟠 Error terminating {process.info['name']} (PID: {process.info['pid']}): {term_e}")

                    result = f"{result_prefix} {process.info['name']} (PID: {process.info['pid']})"
                    if malicious_count > 0:
                        result += f" - Malicious detected ({malicious_count} engines)"
                    else:
                        result += " - Safe"

                    self.scan_result_signal.emit(result)

                elif response.status_code == 404:
                    self.scan_result_signal.emit(f"🟡 {process.info['name']} (PID: {process.info['pid']}) - Hash not found on VirusTotal")
                else:
                    self.scan_result_signal.emit(f"🟠 {process.info['name']} (PID: {process.info['pid']}) - VirusTotal API Error: {response.status_code} - {response.text}")

            except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
                self.scan_result_signal.emit(f"Access Denied/No Process: {process.info.get('name', 'N/A')} (PID: {process.info.get('pid', 'N/A')}) - {e}")
            except requests.exceptions.RequestException as req_e:
                self.scan_result_signal.emit(f"🟠 {process.info.get('name', 'N/A')} (PID: {process.info.get('pid', 'N/A')}) - Network Error: {req_e}")
            except Exception as e:
                self.scan_result_signal.emit(f"Error scanning {process.info.get('name', 'N/A')} (PID: {process.info.get('pid', 'N/A')}): {e}")

        if malicious_found:
            self.scan_status_signal.emit("VirusTotal process scan complete. Malicious processes found.")
        else:
            self.scan_status_signal.emit("VirusTotal process scan complete. No malicious processes detected.")


def _get_file_hash(file_path):
    try:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (FileNotFoundError, PermissionError) as e:
        return None
    except Exception as e:
        return None

firewall_rules = {
    "allow": ["192.168.1.0/24", "10.0.0.0/8"],
    "block": ["203.0.113.0/24", "198.51.100.0/24"],
}

packet_counter = defaultdict(lambda: RateLimiter(5, 1))

def is_ip_allowed(ip_address_str):
    try:
        ip_obj = ipaddress.ip_address(ip_address_str)
        for blocked_range in firewall_rules["block"]:
            if ip_obj in ipaddress.ip_network(blocked_range):
                return False
        for allowed_range in firewall_rules["allow"]:
            if ip_obj in ipaddress.ip_network(allowed_range):
                return True
        return False
    except ValueError as e:
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

_server_running = False
_server_socket = None
_server_thread = None

def _server_thread_func():
    global _server_socket, _server_running
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(1.0)
    try:
        server.bind(("0.0.0.0", 9999))
        server.listen(5)
        _server_socket = server

        while _server_running:
            try:
                client_socket, client_address = server.accept()
                if not _server_running:
                    client_socket.close()
                    break
                client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
                client_thread.daemon = True
                client_thread.start()
            except socket.timeout:
                pass
            except OSError as e:
                break
            except Exception as e:
                pass
    except Exception as e:
        pass
    finally:
        if server:
            server.close()
        _server_socket = None

def start_server_in_thread():
    global _server_running, _server_thread
    if not _server_running:
        _server_running = True
        _server_thread = threading.Thread(target=_server_thread_func)
        _server_thread.daemon = True
        _server_thread.start()

def stop_server():
    global _server_running, _server_socket, _server_thread
    if _server_running:
        _server_running = False
        if _server_socket:
            try:
                _server_socket.shutdown(socket.SHUT_RDWR)
                _server_socket.close()
            except OSError as e:
                pass
            _server_socket = None
        if _server_thread and _server_thread.is_alive():
            _server_thread.join(timeout=2)
            _server_thread = None

def handle_client(client_socket, client_address):
    client_ip = client_address[0]
    if not is_ip_allowed(client_ip):
        client_socket.close()
        return

    rate_limiter = packet_counter[client_ip]
    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                break
            if not rate_limiter.allow_packet():
                client_socket.close()
                return
        except socket.error as e:
            break
        except Exception as e:
            break
    client_socket.close()

if __name__ == "__main__":
    return_code = 0

    try:
        app = QApplication(sys.argv)
        chatbox = ChatBox()
        worker_thread = QThread()
        worker = Worker()
        worker.moveToThread(worker_thread)

        # Connect signals for both text and voice input
        chatbox.message_sent.connect(worker.process_user_prompt)
        chatbox.voice_input_requested.connect(worker.process_voice_input) # NEW CONNECTION

        # Connect signals from worker to UI for displaying results
        worker.ai_response_signal.connect(chatbox.display_ai_response_signal)
        worker.scan_status_signal.connect(chatbox.display_scan_status_signal)
        worker.scan_result_signal.connect(chatbox.display_scan_result_signal)

        worker_thread.start()
        chatbox.show()
        return_code = app.exec()

    except Exception as e:
        import traceback
        traceback.print_exc(file=sys.stderr)
        return_code = 1

    finally:
        stop_server()

        if worker_thread.isRunning():
            worker_thread.quit()
            if not worker_thread.wait(3000):
                pass
        
        sys.exit(return_code)
