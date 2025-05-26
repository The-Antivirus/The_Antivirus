# ui.py
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit,
    QPushButton, QLabel, QGroupBox, QFormLayout, QSpinBox, QColorDialog,
    QApplication, QMessageBox # QApplication and QMessageBox imported for stylesheet and error popups
)
from PyQt6.QtGui import QColor

class ChatBox(QWidget):
    # Signals emitted by the UI that the main application logic will connect to
    message_sent = pyqtSignal(str)
    voice_input_requested = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI Assistant with Security Scanner")
        self.setGeometry(100, 100, 800, 700)
        self.setMinimumSize(600, 500)

        # Store configurable style properties
        self.default_style_properties = {
            "window_bg": "#f0f2f5",
            "chat_display_bg": "#ffffff",
            "chat_display_text_color": "#333333",
            "chat_display_font_size": 14,
            "input_border_color": "#cccccc",
            "button_bg": "#007bff",
            "button_text_color": "#ffffff",
            "button_hover_bg": "#0056b3",
            "button_pressed_bg": "#004085",
            "button_font_size": 14,
            "status_label_color": "#555555",
            "status_label_font_size": 12,
            "scan_result_label_color": "#555555",
            "scan_result_label_font_size": 12,
        }
        # A mutable copy for current settings, allowing user modifications
        self.style_properties = self.default_style_properties.copy()

        # Initialize UI elements first to ensure they exist when referenced
        self._init_ui()

        # Apply initial stylesheet AFTER UI elements are created
        self._apply_generated_stylesheet(initial_setup=True)

    def _init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(10)

        # Chat display area where messages appear
        self.chat_display = QTextEdit()
        self.chat_display.setObjectName("chatDisplay") # Used for QSS styling
        self.chat_display.setReadOnly(True)
        main_layout.addWidget(self.chat_display)

        # Labels for status updates and scan results
        self.status_label = QLabel("Idle")
        self.status_label.setObjectName("statusLabel") # Used for QSS styling
        main_layout.addWidget(self.status_label)

        self.scan_result_label = QLabel("No scan results yet.")
        self.scan_result_label.setObjectName("scanResultLabel") # Used for QSS styling
        main_layout.addWidget(self.scan_result_label)

        # Input field and action buttons
        input_layout = QHBoxLayout()
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Type your message or command...")
        # When Enter is pressed, trigger the message send
        self.user_input.returnPressed.connect(self._send_message)
        input_layout.addWidget(self.user_input)

        send_button = QPushButton("Send")
        send_button.clicked.connect(self._send_message)
        input_layout.addWidget(send_button)

        voice_button = QPushButton("Voice Input")
        voice_button.clicked.connect(self._request_voice_input)
        input_layout.addWidget(voice_button)

        main_layout.addLayout(input_layout)

        # Stylesheet customization section
        self.stylesheet_button = QPushButton("Customize Appearance")
        self.stylesheet_button.clicked.connect(self._toggle_style_editor_visibility)
        main_layout.addWidget(self.stylesheet_button)

        # Style Input Panel (hidden by default, toggled by "Customize Appearance" button)
        self.style_input_panel = QGroupBox("Appearance Settings")
        self.style_input_panel.setObjectName("style_input_panel") # Used for QSS styling
        self.style_input_panel.setVisible(False)
        self.style_input_panel.setContentsMargins(10, 10, 10, 10)
        style_form_layout = QFormLayout()

        # Input widgets for specific style properties (colors and font sizes)
        self.inputs = {} # Stores references to the QLineEdit/QSpinBox widgets

        self._add_color_input(style_form_layout, "Window Background:", "window_bg")
        self._add_color_input(style_form_layout, "Chat Background:", "chat_display_bg")
        self._add_color_input(style_form_layout, "Chat Text Color:", "chat_display_text_color")
        self._add_spinbox_input(style_form_layout, "Chat Font Size:", "chat_display_font_size", min_val=8, max_val=24)
        self._add_color_input(style_form_layout, "Input Border Color:", "input_border_color")
        self._add_color_input(style_form_layout, "Button Background:", "button_bg")
        self._add_color_input(style_form_layout, "Button Text Color:", "button_text_color")
        self._add_spinbox_input(style_form_layout, "Button Font Size:", "button_font_size", min_val=8, max_val=20)

        # Action buttons for style management (Reset and Apply)
        style_action_layout = QHBoxLayout()
        reset_style_button = QPushButton("Reset to Default")
        reset_style_button.clicked.connect(self._reset_styles_to_default)
        style_action_layout.addWidget(reset_style_button)

        apply_style_button = QPushButton("Apply Custom Styles")
        apply_style_button.clicked.connect(self._apply_generated_stylesheet)
        style_action_layout.addWidget(apply_style_button)

        style_form_layout.addRow(style_action_layout)

        self.style_input_panel.setLayout(style_form_layout)
        main_layout.addWidget(self.style_input_panel)

        self.setLayout(main_layout)

    def _is_valid_color(self, color_str):
        """Checks if a string can be interpreted as a valid QColor."""
        return QColor(color_str).isValid()

    def _add_color_input(self, layout, label_text, prop_key):
        """Adds a color input field with a color picker button to the layout."""
        hbox = QHBoxLayout()
        line_edit = QLineEdit(self.style_properties[prop_key])
        line_edit.setPlaceholderText("#RRGGBB or color name")

        # Connect text changes to a validator that also updates the property
        line_edit.textChanged.connect(lambda text, pk=prop_key, le=line_edit: self._validate_and_update_color(pk, text, le))

        hbox.addWidget(line_edit)

        color_picker_button = QPushButton("...")
        color_picker_button.setFixedSize(25, 25)
        color_picker_button.clicked.connect(lambda _, le=line_edit: self._open_color_picker(le))
        hbox.addWidget(color_picker_button)

        layout.addRow(label_text, hbox)
        self.inputs[prop_key] = line_edit

    def _validate_and_update_color(self, key, text, line_edit):
        """Validates color input from a QLineEdit and applies visual feedback."""
        if self._is_valid_color(text):
            self.style_properties[key] = text
            line_edit.setStyleSheet("") # Clear any error style
        else:
            line_edit.setStyleSheet("border: 1px solid red;") # Show error with red border
            # Do NOT update style_properties here with an invalid value.
            # The _generate_stylesheet_from_properties will handle fallbacks.

    def _add_spinbox_input(self, layout, label_text, prop_key, min_val=6, max_val=72):
        """Adds a QSpinBox for numerical inputs like font sizes."""
        spin_box = QSpinBox()
        spin_box.setRange(min_val, max_val)
        spin_box.setValue(self.style_properties[prop_key])
        spin_box.valueChanged.connect(lambda val, pk=prop_key: self._update_property(pk, val))
        layout.addRow(label_text, spin_box)
        self.inputs[prop_key] = spin_box

    def _open_color_picker(self, line_edit):
        """Opens a QColorDialog to visually pick a color."""
        # Use the current text as initial color, falling back to a safe default if invalid
        initial_color = QColor(line_edit.text())
        if not initial_color.isValid():
            prop_key = next((k for k, v in self.inputs.items() if v == line_edit), None)
            if prop_key and prop_key in self.style_properties:
                initial_color = QColor(self.style_properties[prop_key])
            else:
                initial_color = QColor("#000000") # Fallback to black

        color = QColorDialog.getColor(initial_color, self, "Select Color")
        if color.isValid():
            line_edit.setText(color.name()) # Sets hex string (e.g., #FF0000)

    def _update_property(self, key, value):
        """Updates a specific style property in the internal dictionary."""
        self.style_properties[key] = value

    def _toggle_style_editor_visibility(self):
        """Toggles the visibility of the appearance settings panel."""
        is_visible = self.style_input_panel.isVisible()
        self.style_input_panel.setVisible(not is_visible)
        if not is_visible:
            self.stylesheet_button.setText("Hide Appearance Settings")
            self._update_input_widgets_from_properties() # Sync inputs when showing
        else:
            self.stylesheet_button.setText("Customize Appearance")

    def _update_input_widgets_from_properties(self):
        """Updates the UI input widgets to reflect the current style_properties."""
        for key, widget in self.inputs.items():
            # Block signals temporarily to prevent unintended side effects when setting values programmatically
            widget.blockSignals(True)
            if isinstance(widget, QLineEdit):
                widget.setText(self.style_properties[key])
                widget.setStyleSheet("") # Clear any old error styles
            elif isinstance(widget, QSpinBox):
                widget.setValue(self.style_properties[key])
            widget.blockSignals(False)

    def _reset_styles_to_default(self):
        """Resets all style properties to their initial default values."""
        self.style_properties = self.default_style_properties.copy()
        self._update_input_widgets_from_properties() # Update UI to show defaults
        self._apply_generated_stylesheet() # Apply the default stylesheet
        self.display_scan_status_signal("Styles reset to default.")

    def _generate_stylesheet_from_properties(self):
        """Constructs the QSS string from the current style properties."""
        props = self.style_properties.copy() # Use a copy to ensure immutability during generation

        # Validate color values and fallback to defaults if invalid
        color_keys = [
            "window_bg", "chat_display_bg", "chat_display_text_color",
            "input_border_color", "button_bg", "button_text_color",
            "button_hover_bg", "button_pressed_bg"
        ]
        for key in color_keys:
            current_value = props.get(key)
            if not self._is_valid_color(current_value):
                fallback_value = self.default_style_properties[key]
                self.display_scan_status_signal(
                    f"Warning: Invalid color '{current_value}' for '{key}'. Using default: '{fallback_value}'."
                )
                props[key] = fallback_value # Use the safe fallback

        # The core QSS string, dynamically populated
        qss = f"""
            QWidget {{
                background-color: {props['window_bg']};
                font-family: 'Segoe UI', sans-serif;
            }}
            #chatDisplay {{
                background-color: {props['chat_display_bg']};
                border: 1px solid #dcdcdc;
                border-radius: 8px;
                padding: 10px;
                font-size: {props['chat_display_font_size']}px;
                color: {props['chat_display_text_color']};
            }}
            QLineEdit {{
                border: 1px solid {props['input_border_color']};
                border-radius: 6px;
                padding: 8px 10px;
                font-size: 14px;
            }}
            QPushButton {{
                background-color: {props['button_bg']};
                color: {props['button_text_color']};
                border: none;
                border-radius: 6px;
                padding: 8px 15px;
                font-size: {props['button_font_size']}px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {props['button_hover_bg']};
            }}
            QPushButton:pressed {{
                background-color: {props['button_pressed_bg']};
            }}
            #statusLabel {{
                color: {props['status_label_color']};
                font-size: {props['status_label_font_size']}px;
                padding: 5px;
            }}
            #scanResultLabel {{
                color: {props['scan_result_label_color']};
                font-size: {props['scan_result_label_font_size']}px;
                padding: 5px;
            }}
            QGroupBox#style_input_panel {{
                border: 1px solid #cccccc;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background-color: #f8f9fa;
            }}
            QGroupBox#style_input_panel::title {{
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 3px;
                background-color: {props['window_bg']};
            }}
            /* Specific style for color input error state */
            QLineEdit[style*="border: 1px solid red;"] {{
                border: 1px solid red;
                background-color: #ffe0e0;
            }}
        """
        return qss

    def _apply_generated_stylesheet(self, initial_setup=False):
        """Applies the generated QSS to the QApplication instance."""
        generated_qss = self._generate_stylesheet_from_properties()
        try:
            QApplication.instance().setStyleSheet(generated_qss)
            if not initial_setup:
                self.display_scan_status_signal("Custom styles applied successfully!")
        except Exception as e:
            # Fallback for unexpected QSS errors
            QMessageBox.warning(self, "Stylesheet Application Error",
                                f"An unexpected error occurred while applying styles: {e}\n\n"
                                "Please ensure all inputs are valid. You can try 'Reset to Default'.")
            self.display_scan_status_signal(f"Stylesheet application failed: {e}")

    ### Public Slots (to be connected from Worker) ###

    def display_user_message(self, message):
        """Displays a user message in the chat display."""
        self.chat_display.append(f"<p style='color:#007bff; font-weight:bold;'>You:</p><p>{message}</p>")

    def display_ai_response_signal(self, response):
        """Displays an AI response in the chat display."""
        self.chat_display.append(f"<p style='color:#28a745; font-weight:bold;'>AI:</p><p>{response}</p>")

    def display_scan_status_signal(self, status):
        """Updates the status label."""
        self.status_label.setText(f"Status: {status}")

    def display_scan_result_signal(self, result):
        """Updates the scan result label and appends to chat."""
        self.scan_result_label.setText(f"Last Scan Result: {result}")
        self.chat_display.append(f"<p style='color:#800080; font-size:12px;'><i>{result}</i></p>")

    ### Private UI Action Handlers (emit signals) ###

    def _send_message(self):
        """Handler for sending a text message."""
        message = self.user_input.text().strip()
        if message:
            self.message_sent.emit(message) # Emit signal for worker
            self.user_input.clear()

    def _request_voice_input(self):
        """Handler for requesting voice input."""
        self.voice_input_requested.emit() # Emit signal for worker
