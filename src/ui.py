import sys
import threading
import socket
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
    QTextEdit,
    QLineEdit,
    QFrame
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
import main
class AntivirusUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Antivirus Project")
        self.setGeometry(100, 100, 600, 600)
        self.server_running = False
        self.server_thread = None
        self.server_socket = None
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        self.button_style_open = """
            QPushButton {
                border-radius: 7px;
                padding: 10px;
                background-color: #32CD99;
                color: white;
                font-size: 10px;
            }
        """

        self.button_style_close = """
            QPushButton {
                border-radius: 7px;
                padding: 10px;
                background-color: #FF0000;
                color: white;
                font-size: 10px;
            }
        """
        self.frame_visible = False
        self.create_main_screen()

    def create_main_screen(self):
        self.clear_layout()

        self.frame = QFrame(self)
        self.frame.setFrameShape(QFrame.Shape.Box)
        self.frame.setLineWidth(0)
        self.frame.setFixedWidth(150)
        self.frame.setFixedHeight(500)
        self.frame.hide()

        self.frame_layout = QVBoxLayout(self.frame)

        font_title = QFont("Segoe Script", 30, QFont.Weight.Bold)
        self.title_label = QLabel("Antivirus Project")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setStyleSheet("font-size: 30px; font-weight: bold; color: #32CD99;")
        self.title_label.setFont(font_title)
        self.layout.addWidget(self.title_label)

        scan_button = QPushButton("Scan for Malware")
        scan_button.setStyleSheet(self.button_style_open)
        scan_button.clicked.connect(self.create_scanner_ui)
        scan_button.setFont(QFont("Segoe Script", 10, QFont.Weight.Bold))
        self.frame_layout.addWidget(scan_button)

        self.firewall_button = QPushButton("Manage Firewall")
        self.firewall_button.setStyleSheet(self.button_style_open)
        self.firewall_button.clicked.connect(self.create_firewall_ui)
        self.firewall_button.setFont(QFont("Segoe Script", 10, QFont.Weight.Bold))
        self.frame_layout.addWidget(self.firewall_button)

        if self.server_running:
            stop_button = QPushButton("Turn Off ADS")
            stop_button.setStyleSheet(self.button_style_close)
            stop_button.clicked.connect(self.stop_anti_ddos)
            stop_button.setFont(QFont("Segoe Script", 10, QFont.Weight.Bold))
            self.frame_layout.addWidget(stop_button)
        else:
            start_button = QPushButton("Turn On ADS")
            start_button.setStyleSheet(self.button_style_open)
            start_button.clicked.connect(self.start_anti_ddos)
            start_button.setFont(QFont("Segoe Script", 10, QFont.Weight.Bold))
            self.frame_layout.addWidget(start_button)

        self.toggle_button = QPushButton("Open")
        self.toggle_button.setStyleSheet(self.button_style_open)
        self.toggle_button.clicked.connect(self.toggle_frame)
        self.toggle_button.setFont(QFont("Segoe Script", 10, QFont.Weight.Bold))
        self.toggle_button.setFixedWidth(80)
        self.layout.addWidget(self.toggle_button)

        self.layout.addWidget(self.frame)

    def toggle_frame(self):
        if not self.frame_visible:
            self.frame.show()
            self.toggle_button.setText("Close")
            self.toggle_button.setStyleSheet(self.button_style_close)
            self.frame_visible = True
        else:
            self.frame.hide()
            self.toggle_button.setText("Open")
            self.toggle_button.setStyleSheet(self.button_style_open)
            self.frame_visible = False

    def create_scanner_ui(self):
        self.clear_layout()
        font2 = QFont("Segoe Script", 10, QFont.Weight.Bold)

        title = QLabel("Malware Scanner")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #32CD99;")
        title.setFont(font2)
        self.layout.addWidget(title)

        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.layout.addWidget(self.results_text)

        process_button = QPushButton("Scan Running Processes")
        process_button.setStyleSheet("color: #32CD99;")
        process_button.clicked.connect(self.scan_running_processes)
        process_button.setFont(font2)
        self.layout.addWidget(process_button)

        back_button = QPushButton("Back")
        back_button.setStyleSheet("color: #32CD99;")
        back_button.clicked.connect(self.create_main_screen)
        back_button.setFont(font2)
        self.layout.addWidget(back_button)

    def scan_running_processes(self):
        results = main.scan_running_processes()
        self.results_text.clear()
        self.results_text.append("\n".join(results))

    def create_firewall_ui(self):
        self.clear_layout()
        font2 = QFont("Segoe Script", 10, QFont.Weight.Bold)

        title = QLabel("Firewall Manager")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #32CD99;")
        title.setFont(font2)
        self.layout.addWidget(title)

        self.allow_entry = QLineEdit()
        self.allow_entry.setPlaceholderText("Enter IP to allow")
        self.allow_entry.setFont(font2)
        self.layout.addWidget(self.allow_entry)

        allow_button = QPushButton("Add Allowed IP")
        allow_button.setStyleSheet("color: #32CD99;")
        allow_button.clicked.connect(self.add_allowed_ip)
        allow_button.setFont(font2)
        self.layout.addWidget(allow_button)

        self.block_entry = QLineEdit()
        self.block_entry.setPlaceholderText("Enter IP to block")
        self.block_entry.setFont(font2)
        self.layout.addWidget(self.block_entry)

        block_button = QPushButton("Add Blocked IP")
        block_button.setStyleSheet("color: #32CD99;")
        block_button.clicked.connect(self.add_blocked_ip)
        block_button.setFont(font2)
        self.layout.addWidget(block_button)

        self.rules_text = QTextEdit()
        self.rules_text.setReadOnly(True)
        self.layout.addWidget(self.rules_text)

        back_button = QPushButton("Back")
        back_button.setStyleSheet("color: #32CD99;")
        back_button.clicked.connect(self.create_main_screen)
        back_button.setFont(font2)
        self.layout.addWidget(back_button)

        self.display_firewall_rules()

    def add_allowed_ip(self):
        ip = self.allow_entry.text()
        main.add_allowed_ip(ip)
        self.display_firewall_rules()

    def add_blocked_ip(self):
        ip = self.block_entry.text()
        main.add_blocked_ip(ip)
        self.display_firewall_rules()

    def display_firewall_rules(self):
        rules = main.get_firewall_rules()
        self.rules_text.clear()
        self.rules_text.append("Allowed IPs:")
        self.rules_text.append("\n".join(rules["allow"]))
        self.rules_text.append("\nBlocked IPs:")
        self.rules_text.append("\n".join(rules["block"]))

    def start_anti_ddos(self):
        if not self.server_running:
            self.server_running = True
            def server_socket_callback(server_socket):
                self.server_socket = server_socket
            self.server_thread = threading.Thread(
                target=main.start_server,
                args=(lambda: self.server_running, server_socket_callback),
                daemon=True,
            )

            self.server_thread.start()
            self.create_main_screen()

    def stop_anti_ddos(self):
        if self.server_running:
            self.server_running = False
            if self.server_socket:
                self.server_socket.close()
            self.server_thread.join()
            self.create_main_screen()

    def clear_layout(self):
        while self.layout.count():
            child = self.layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

def run_app():
    app = QApplication(sys.argv)
    window = AntivirusUI()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    run_app()
