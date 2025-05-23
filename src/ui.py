from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QTextEdit, QLineEdit, QPushButton, QScrollBar, QHBoxLayout
from PyQt6.QtCore import pyqtSignal

class ChatBox(QWidget):
    message_sent = pyqtSignal(str)
    # THIS IS THE MISSING SIGNAL:
    voice_input_requested = pyqtSignal()
    display_ai_response_signal = pyqtSignal(str)
    display_scan_status_signal = pyqtSignal(str)
    display_scan_result_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()

        self.setWindowTitle("Security AI Chat")
        self.setGeometry(100, 100, 600, 700)

        main_layout = QVBoxLayout()

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        # No stylesheet for chat_display
        main_layout.addWidget(self.chat_display)

        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Type your message here...")
        self.input_field.returnPressed.connect(self.send_message)
        # No stylesheet for input_field
        main_layout.addWidget(self.input_field)

        # Horizontal layout for buttons
        button_layout = QHBoxLayout()

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        # No stylesheet for send_button
        button_layout.addWidget(self.send_button)

        # THIS IS THE BUTTON CONNECTED TO THE SIGNAL:
        self.voice_button = QPushButton("Voice Input")
        self.voice_button.clicked.connect(self.request_voice_input)
        # No stylesheet for voice_button
        button_layout.addWidget(self.voice_button)

        main_layout.addLayout(button_layout) # Add the button layout to the main layout

        self.setLayout(main_layout)

        # Connect signals from Worker in main.py to UI display methods
        self.display_ai_response_signal.connect(self._display_ai_response_on_ui)
        self.display_scan_status_signal.connect(self._display_scan_status_on_ui)
        self.display_scan_result_signal.connect(self._display_scan_result_on_ui)

    def send_message(self):
        message = self.input_field.text().strip()
        if message:
            self.chat_display.append(f"<p style='color:#007bff; font-weight:bold;'>You:</p><p>{message}</p>")
            self.message_sent.emit(message) # Emits text prompt to main.py
            self.input_field.clear()
            self._auto_scroll()

    # THIS IS THE METHOD THAT EMITS THE SIGNAL:
    def request_voice_input(self):
        """Emits a signal to main.py to start voice recognition."""
        self.chat_display.append(f"<p style='color:#6c757d;'><i>Voice input requested... Please allow microphone access if prompted.</i></p>")
        self._auto_scroll()
        self.voice_input_requested.emit() # Emits signal to main.py

    def _display_ai_response_on_ui(self, text):
        self.chat_display.append(text)
        self._auto_scroll()

    def _display_scan_status_on_ui(self, text):
        self.chat_display.append(f"<p style='color:#6c757d;'><i>{text}</i></p>")
        self._auto_scroll()

    def _display_scan_result_on_ui(self, text):
        self.chat_display.append(text)
        self._auto_scroll()

    def _auto_scroll(self):
        self.chat_display.verticalScrollBar().setValue(self.chat_display.verticalScrollBar().maximum())
