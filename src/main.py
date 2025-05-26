import sys
import hashlib
import os
import psutil
import requests
import speech_recognition as sr
from googletrans import Translator
import traceback

from PyQt6.QtCore import QObject, pyqtSignal, QThread
from PyQt6.QtWidgets import QApplication

# Assuming 'ai.py' is in the same directory
import ai

# Import your separated UI class
from ui import ChatBox

# --- Global Constants ---
VT_URL = "https://www.virustotal.com/api/v3/files/{}"
# IMPORTANT: For production, load API keys from environment variables or config files.
# Hardcoding is for demonstration purposes only.
VIRUSTOTAL_API_KEY = "bbedf9b88f8698058b3903e8127d9b8151d" + "b8118ddeb6242c87bc3e8dd84df28"

# --- Helper Function for File Hashing ---
def _get_file_hash(file_path):
    """Calculates the SHA256 hash of a file for VirusTotal lookup."""
    try:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (FileNotFoundError, PermissionError):
        return None
    except Exception: # Catch any other unexpected errors
        return None

# --- Worker Class for Background Operations (Now part of main.py) ---
class Worker(QObject):
    # Signals emitted by the worker to update the UI
    ai_response_signal = pyqtSignal(str)
    scan_status_signal = pyqtSignal(str)
    scan_result_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.recognizer = sr.Recognizer()
        self.translator = Translator()

    def process_user_prompt(self, user_prompt):
        """Processes a text prompt from the user."""
        self.scan_status_signal.emit("AI analyzing text prompt...")
        self._send_prompt_to_ai_and_process_response(user_prompt)

    def process_voice_input(self):
        """Handles voice input, converts it to text, translates, and sends to AI."""
        self.scan_status_signal.emit("Listening for voice input... Please speak now.")
        try:
            with sr.Microphone() as source:
                self.recognizer.adjust_for_ambient_noise(source)
                # Listen for up to 7 seconds
                audio = self.recognizer.listen(source, timeout=7, phrase_time_limit=7)

            self.scan_status_signal.emit("Speech detected. Recognizing...")
            recognized_text = self.recognizer.recognize_google(audio)

            # Emit recognized text back to UI immediately for display
            self.ai_response_signal.emit(f"<p style='color:#007bff; font-weight:bold;'>You (Voice):</p><p>{recognized_text}</p>")

            translated_text = self._translate_prompt_to_english(recognized_text)

            self._send_prompt_to_ai_and_process_response(translated_text, is_voice_input=True)

        except sr.UnknownValueError:
            self.scan_status_signal.emit("Could not understand audio. Please try again.")
        except sr.RequestError as e:
            self.scan_status_signal.emit(f"Could not request results from speech recognition service; {e}")
        except Exception as e:
            self.scan_status_signal.emit(f"Error during voice input: {e}")

    def _translate_prompt_to_english(self, prompt):
        """Translates the given prompt to English using Google Translate."""
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
            return prompt

    def _send_prompt_to_ai_and_process_response(self, prompt, is_voice_input=False):
        """Sends the prompt to the AI and processes its response, initiating scans if needed."""
        if is_voice_input:
            self.scan_status_signal.emit("AI analyzing translated voice prompt...")
        else:
            self.scan_status_signal.emit("AI analyzing text prompt...")

        # Assuming ai.generate_prompt is a blocking call, it runs safely in this worker thread
        ai_response = ai.generate_prompt(prompt)
        self.ai_response_signal.emit(f"{ai_response}") # Send AI's raw response; UI formats it

        # Check for specific security suspicions from AI
        if ai_response.startswith("SUSPICION_DETECTED:"):
            suspicion_data = ai_response[len("SUSPICIÓN_DETECTED:"):]
            suspicions = [s.strip() for s in suspicion_data.split(',')]

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

        # Retrieve any queued scan results from the AI module (if AI module buffers them)
        all_scan_results = ai.get_queue_contents()
        if all_scan_results:
            self.scan_status_signal.emit("--- All Scan Results ---")
            for result in all_scan_results:
                self.scan_result_signal.emit(result)
        else:
            self.scan_status_signal.emit("No specific scan results to display from the queue.")

    def _scan_directory(self, directory_path):
        """Scans executable files in a given directory using VirusTotal."""
        if not os.path.isdir(directory_path):
            self.scan_result_signal.emit(f"🔴 Error: Directory not found: {directory_path}")
            return

        self.scan_status_signal.emit(f"Scanning directory: {directory_path}...")
        malicious_found_in_dir = False

        for root, _, files in os.walk(directory_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                # Only check common executable/script file types to avoid scanning everything
                if file_name.lower().endswith((".exe", ".dll", ".bat", ".ps1", ".vbs", ".cmd")):
                    try:
                        file_hash = _get_file_hash(file_path)
                        if not file_hash:
                            self.scan_result_signal.emit(f"🟡 File: {file_name} - Could not generate hash (Permission denied or file read error)")
                            continue

                        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
                        response = requests.get(VT_URL.format(file_hash), headers=headers, timeout=10) # Added timeout

                        if response.status_code == 200:
                            data = response.json()
                            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
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
                    except requests.exceptions.Timeout:
                        result = f"🟠 File: {file_name} - VirusTotal API request timed out."
                    except requests.exceptions.RequestException as req_e:
                        result = f"🟠 File: {file_name} - Network Error contacting VirusTotal: {req_e}"
                    except Exception as e:
                        result = f"Error scanning {file_name}: {e}"

                    self.scan_result_signal.emit(result)

        if malicious_found_in_dir:
            self.scan_status_signal.emit(f"🔴 Directory scan of {directory_path} complete. Malicious files found.")
        else:
            self.scan_status_signal.emit(f"🟢 Directory scan of {directory_path} complete. No malicious executable files detected.")

    def _scan_running_processes(self):
        """Scans running processes for malicious executables using VirusTotal."""
        malicious_found = False
        self.scan_status_signal.emit("Scanning running processes...")

        for process in psutil.process_iter(attrs=["pid", "name", "exe"]):
            try:
                exe_path = process.info["exe"]
                if not exe_path or not os.path.exists(exe_path):
                    continue

                file_hash = _get_file_hash(exe_path)
                if not file_hash:
                    self.scan_result_signal.emit(f"🟡 {process.info['name']} (PID: {process.info['pid']}) - Could not generate hash (Permission denied or file read error)")
                    continue

                headers = {"x-apikey": VIRUSTOTAL_API_KEY}
                response = requests.get(VT_URL.format(file_hash), headers=headers, timeout=10) # Added timeout

                if response.status_code == 200:
                    data = response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious_count = stats.get("malicious", 0)

                    result_prefix = "🟢"
                    if malicious_count > 0:
                        result_prefix = "🔴"
                        malicious_found = True
                        try:
                            # Attempt to terminate malicious processes identified by VirusTotal
                            process.terminate()
                            self.scan_result_signal.emit(f"🔴 Terminated: {process.info['name']} (PID: {process.info['pid']}) - Malicious ({malicious_count} engines)")
                        except psutil.AccessDenied:
                            self.scan_result_signal.emit(f"🟠 Failed to terminate: {process.info['name']} (PID: {process.info['pid']}) - Access Denied (Malicious: {malicious_count} engines)")
                        except Exception as term_e:
                            self.scan_result_signal.emit(f"🟠 Error terminating {process.info['name']} (PID: {process.info['pid']}): {term_e} (Malicious: {malicious_count} engines)")

                    result = f"{result_prefix} {process.info['name']} (PID: {process.info['pid']})"
                    if malicious_count == 0:
                        result += " - Safe"

                    self.scan_result_signal.emit(result)

                elif response.status_code == 404:
                    self.scan_result_signal.emit(f"🟡 {process.info['name']} (PID: {process.info['pid']}) - Hash not found on VirusTotal")
                else:
                    self.scan_result_signal.emit(f"🟠 {process.info['name']} (PID: {process.info['pid']}) - VirusTotal API Error: {response.status_code} - {response.text}")

            except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
                # Handle cases where a process might have just exited or access is denied
                self.scan_result_signal.emit(f"Access Denied/No Process: {process.info.get('name', 'N/A')} (PID: {process.info.get('pid', 'N/A')}) - {e}")
            except requests.exceptions.Timeout:
                self.scan_result_signal.emit(f"🟠 {process.info.get('name', 'N/A')} (PID: {process.info.get('pid', 'N/A')}) - VirusTotal API request timed out.")
            except requests.exceptions.RequestException as req_e:
                self.scan_result_signal.emit(f"🟠 {process.info.get('name', 'N/A')} (PID: {process.info.get('pid', 'N/A')}) - Network Error contacting VirusTotal: {req_e}")
            except Exception as e:
                self.scan_result_signal.emit(f"Error scanning {process.info.get('name', 'N/A')} (PID: {process.info.get('pid', 'N/A')}): {e}")

        if malicious_found:
            self.scan_status_signal.emit("🔴 VirusTotal process scan complete. Malicious processes found.")
        else:
            self.scan_status_signal.emit("🟢 VirusTotal process scan complete. No malicious processes detected.")

# --- Main Application Entry Point ---
def main():
    app = QApplication(sys.argv)

    # 1. Create the UI instance
    chatbox = ChatBox()

    # 2. Create the Worker instance and move it to a new QThread
    worker_thread = QThread()
    worker = Worker()
    worker.moveToThread(worker_thread)

    # 3. Connect signals from UI to Worker: User actions in the UI trigger tasks in the background
    chatbox.message_sent.connect(worker.process_user_prompt)
    chatbox.voice_input_requested.connect(worker.process_voice_input)

    # 4. Connect signals from Worker to UI: Background tasks send updates to the UI
    worker.ai_response_signal.connect(chatbox.display_ai_response_signal)
    worker.scan_status_signal.connect(chatbox.display_scan_status_signal)
    worker.scan_result_signal.connect(chatbox.display_scan_result_signal)

    # 5. Start the worker thread
    worker_thread.start()

    # 6. Show the main UI window
    chatbox.show()

    # 7. Start the Qt event loop. This blocks until the application exits.
    return_code = app.exec()

    # 8. Clean up: Ensure the worker thread quits gracefully before the application exits
    if worker_thread.isRunning():
        worker_thread.quit() # Request the thread to stop its event loop
        # Wait for the thread to finish for a maximum of 3 seconds to ensure cleanup
        if not worker_thread.wait(3000):
            print("Warning: Worker thread did not terminate gracefully.", file=sys.stderr)

    sys.exit(return_code)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # Catch any unexpected errors that occur during initial setup or before the event loop
        print(f"An unhandled application error occurred: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr) # Print full traceback for debugging
        sys.exit(1) # Exit with an error code
