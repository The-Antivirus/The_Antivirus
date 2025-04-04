# The Antivirus

![Antivirus Logo](images/Untitled-1-01.png)

The Antivirus is a Python-based application designed to provide essential security features such as malware scanning, firewall management, and an anti-DDoS server. It is built with a user-friendly graphical interface using `tkinter` and leverages the `psutil` library for system monitoring and resource management.

---

## Features
- **Malware Scanning**: Detect and identify potential malware on your system.
- **Firewall Management**: Manage and configure firewall settings to enhance system security.
- **Anti-DDoS Server**: Start and stop an anti-DDoS server to protect against distributed denial-of-service attacks.
- **User-Friendly Interface**: Built with `tkinter` for an intuitive and easy-to-use GUI.

---

## Requirements
- Python 3.6 or higher
- Dependencies:
  - `psutil>=5.9.0`
  - `PyQt6`
  - Standard Python libraries: `hashlib`, `os`, `socket`, `threading`, `time`, `tkinter`, `collections`, `ipaddress`

---

## Installation

### Option 1: Install from PyPI
You can install the latest version of The Antivirus directly from PyPI:
```bash
pip install The-Antivirus
```

### Option 2: Install from Source
1. Clone the repository:
   ```bash
   git clone https://github.com/The-Antivirus/The_Antivirus.git
   cd Downloads\The_Antivirus-main\The_Antivirus-main\src
   ```

2. Install the package:
   ```bash
   pip install -e .
   ```

3. (Optional) Install development dependencies:
   ```bash
   pip install -e .[dev]
   ```

---

## Usage
If you installed the package from PyPI, you can run the application using:
```bash
the-antivirus
```

If you cloned the repository, run the application using the following command:
```bash
python ui.py
```

### Features in the Application:
1. **Malware Scanning**:
   - Click the "Scan for Malware" button to initiate a malware scan.

2. **Firewall Management**:
   - Click the "Manage Firewall" button to configure firewall settings.

3. **Anti-DDoS Server**:
   - Start or stop the anti-DDoS server using the respective buttons.

---

## Contributing
Contributions are welcome! If you’d like to contribute to this project:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Submit a pull request with a detailed description of your changes.

---
~
## Authors
- ![Danielscos](https://www.gravatar.com/avatar/2bc553781cecd02a316c59729e84e33e?s=100)  
  **Danielscos**  
  Email: [sawfish696@anglernook.com](mailto:sawfish696@anglernook.com)  

- **Almogoxt**

---

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Support
If you encounter any issues or have questions, feel free to open an issue on the [GitHub repository](https://github.com/The-Antivirus/The_Antivirus/issues).

---

## Acknowledgments
Special thanks to the contributors and the open-source community for their support and inspiration.
