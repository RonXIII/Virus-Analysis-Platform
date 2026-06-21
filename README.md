1.  # 🛡️ Virus Analysis Platform
2.  ✨ Features
3.  📋 Prerequisites
4.  🚀 Installation
5.  🧪 Quick Start
6.  🏗️ Building the .exe
7.  🔐 Profile & Security
8.  📂 Project Structure
9.  🧰 Dependencies
10. ⚠️ Important Notes
11. 🤝 Contributing          
12. 🙏 Acknowledgements      
13. 📬 Contact               
14. 📄 License
15. ⭐ Support the Project
16. 📌 Version History
17. 🚀 Roadmap

# 🛡️ Virus Analysis Platform

A comprehensive, offline-first malware analysis platform with static and machine learning-based detection, secure profile management, and multi-source malware acquisition.

---

## ✨ Features

- **Static Analysis** – YARA rule scanning + PE header analysis + entropy and byte n‑gram feature extraction
- **Machine Learning** – Random Forest (scikit-learn) and optional CNN (TensorFlow) for advanced detection
- **Secure Profiles** – Encrypted API key storage with password-protected login
- **Multi-Source Download** – Acquire samples from MalwareBazaar, TheZoo (GitHub), and MalShare
- **Automatic Extraction** – 7‑Zip fallback for LZMA-compressed ZIP files
- **Training Interface** – Retrain models directly from the GUI without touching the command line
- **Offline First** – No cloud dependencies; all analysis happens locally
- **Real-Time Progress** – Training and download progress bars with percentage completion
- **Model Status** – View when your models were last updated

---

## 📋 Prerequisites

| Requirement | Version / Notes |
|-------------|-----------------|
| **Python** | 3.13 (3.12 if using TensorFlow) |
| **RAM** | 4 GB minimum (8 GB recommended for CNN training) |
| **Storage** | 1 GB+ for malware samples and trained models |
| **7‑Zip** | Required for extracting LZMA-compressed samples |
| **Operating System** | Windows 10 / 11 (64‑bit) |

---

## 🚀 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/RonXIII/virus-analysis-platform.git
   cd virus-analysis-platform
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:
   ```bash
   python gui_main.py
   ```

---

## 🧪 Quick Start

1. **Create a profile** – On first launch, click "Create Account" and set a username and password.
2. **Download samples** – Go to the Download tab, select a source, and click "Download".
3. **Train models** – In the Train tab, point to your malware and benign folders, then click "Train RF" or "Train CNN".
4. **Scan files** – Use the Scan tab to analyze suspicious files.

---

## 🏗️ Building the `.exe`

<<<<<<< Updated upstream
## 🏗️ Building the `.exe`

=======
>>>>>>> Stashed changes
```bash
pyinstaller virus_scanner.spec
```

The output will be in `dist/VirusScanner/`. The application uses `onedir` mode so that `profiles.db` remains writable for saving API keys.

<<<<<<< Updated upstream
=======
---
>>>>>>> Stashed changes

## 🔐 Profile & Security

Profiles are stored locally in `profiles.db` (SQLite). API keys are encrypted using Fernet (AES) with a key derived from your password. Passwords are salted and hashed – never stored in plain text. The `profiles.db` file is ignored by Git – your keys are never exposed.

<<<<<<< Updated upstream
## 📂 Project Structure
virus-analysis-platform/
├── gui_main.py # Main GUI application
├── profile_manager.py # Profile & API key encryption
├── gui_downloaders.py # Malware downloaders
├── config.py # Configuration
├── requirements.txt # Python dependencies
├── virus_scanner.spec # PyInstaller build spec
├── core/
│ ├── init.py
│ ├── scanner.py # Main scanner orchestrator
│ ├── yara_engine.py # YARA rule engine
│ ├── ml_detector.py # Random Forest detector
│ ├── deep_ml.py # CNN detector (optional)
│ ├── anti_evasion.py # Anti-debugging/VM detection
│ └── reporting.py # Report generator
├── rules/
│ └── yara/
│ └── malware.yar # Sample YARA rules
├── templates/
│ └── report.html # Report template
└── models/ # Trained models (created by user)

=======
---

## 📂 Project Structure

```
virus-analysis-platform/
├── gui_main.py              # Main GUI application
├── profile_manager.py       # Profile & API key encryption
├── gui_downloaders.py       # Malware downloaders
├── config.py                # Configuration
├── requirements.txt         # Python dependencies
├── virus_scanner.spec       # PyInstaller build spec
├── core/
│   ├── __init__.py
│   ├── scanner.py           # Main scanner orchestrator
│   ├── yara_engine.py       # YARA rule engine
│   ├── ml_detector.py       # Random Forest detector
│   ├── deep_ml.py           # CNN detector (optional)
│   ├── anti_evasion.py      # Anti-debugging/VM detection
│   └── reporting.py         # Report generator
├── rules/
│   └── yara/
│       └── malware.yar      # Sample YARA rules
├── templates/
│   └── report.html          # Report template
└── models/                  # Trained models (created by user)
```

---
>>>>>>> Stashed changes

## 🧰 Dependencies

| Package | Purpose |
|---------|---------|
| `scikit-learn` | Random Forest ML detection |
| `tensorflow` | CNN deep learning (optional) |
| `pefile` | PE header parsing |
| `yara-python` | YARA rule scanning |
| `cryptography` | Secure API key encryption |
| `requests` | HTTP requests for downloads |
| `Pillow` | GUI icon support |
| `pyinstaller` | Building the `.exe` |

See `requirements.txt` for the full list.

<<<<<<< Updated upstream
## ⚠️ Important Notes

- **Malware samples** are dangerous – always handle them inside an isolated VM.
- **7‑Zip** must be installed for extracting LZMA-compressed ZIP files.
- **TensorFlow** is optional – if you don't need CNN training, comment it out in `requirements.txt` to keep the `.exe` small.
- **PDF reports** require `wkhtmltopdf` to be installed on the system. If not, only HTML reports are generated.
- **Do not include malware samples** in the benign folder – it will confuse the model.
=======
---

## ⚠️ Important Notes
>>>>>>> Stashed changes

- **Malware samples** are dangerous – always handle them inside an isolated VM.
- **7‑Zip** must be installed for extracting LZMA-compressed ZIP files.
- **TensorFlow** is optional – if you don't need CNN training, comment it out in `requirements.txt` to keep the `.exe` small.
- **PDF reports** require `wkhtmltopdf` to be installed on the system. If not, only HTML reports are generated.
- **Do not include malware samples** in the benign folder – it will confuse the model.

---

## 🤝 Contributing
<<<<<<< Updated upstream
We welcome contributions from the community! Here's how you can help:
=======
>>>>>>> Stashed changes

We welcome contributions from the community!

### How to Contribute

<<<<<<< Updated upstream
2.Create a new branch for your feature or bugfix:
   ```bash
   git checkout -b feature/your-feature-name

3.Commit your changes
   ```bash
   git commit -m "Add your descriptive commit message"

4.Push to your branch:
   ```bash
   git push origin feature/your-feature-name
=======
1. Fork the repository.
2. Create a new branch for your feature or bugfix:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add your descriptive commit message"
   ```
4. Push to your branch:
   ```bash
   git push origin feature/your-feature-name
   ```
5. Open a Pull Request against the `main` branch.

### Guidelines

- Follow the existing code style and naming conventions.
- Include docstrings and comments for new functions and classes.
- Test your changes thoroughly before submitting.
- Update the README if you add new features.
>>>>>>> Stashed changes

### Areas Where Help Is Needed

<<<<<<< Updated upstream


## Guidelines:
=======
- Additional YARA rule sets – Expand detection coverage
- New malware sources – Integrate VirusTotal, Hybrid Analysis, etc.
- Improved feature extraction – Better ML features for higher accuracy
- UI/UX improvements – Make the interface even more polished
- Bug fixes – Squash any issues you find
- Documentation – Improve or translate documentation
- Performance optimization – Speed up scanning and training
>>>>>>> Stashed changes

### Reporting Issues

Found a bug or have a suggestion? Please open an issue on GitHub with:
- A clear description of the problem or suggestion
- Steps to reproduce (if a bug)
- Screenshots or logs (if applicable)

---

## 🙏 Acknowledgements

This project stands on the shoulders of giants. Special thanks to:

- [MalwareBazaar](https://bazaar.abuse.ch) – Free, open repository of malware samples
- [TheZoo](https://github.com/ytisf/theZoo) – Curated collection of live malware for research
- [MalShare](https://malshare.com) – Free API access to malware samples
- [YARA](https://virustotal.github.io/yara/) – Powerful pattern-matching engine
- [scikit-learn](https://scikit-learn.org/) – Random Forest ML implementation
- [TensorFlow](https://www.tensorflow.org/) – Deep learning framework (optional)
- [abuse.ch](https://abuse.ch) – MalwareBazaar and threat intelligence platforms
- [PEfile](https://github.com/erocarrera/pefile) – PE file parsing library
- [PyInstaller](https://pyinstaller.org/) – Packaging Python applications into executables
- [Python](https://www.python.org/) – The programming language that powers it all

### Individual Thanks

- The open-source community for creating and maintaining the incredible libraries used in this project.
- Security researchers worldwide who contribute samples to MalwareBazaar and other repositories.
- Everyone who has starred, forked, or contributed to this project – you make it better!

---

## 📬 Contact

- **Author:** Aaron Chuah
- **GitHub:** [RonXIII](https://github.com/RonXIII)
- **Email:** [Tiongenxiii@gmail.com](mailto:Tiongenxiii@gmail.com)

For security vulnerabilities, please **do not** create a public issue. Instead, contact the author directly via GitHub (private) or email.

<<<<<<< Updated upstream


## Reporting Issues:
Found a bug or have a suggestion? Please open an issue on GitHub with a clear description of the problem or suggestion, steps to reproduce (if a bug), and screenshots or logs (if applicable).



## 🙏 Acknowledgements
This project stands on the shoulders of giants. Special thanks to MalwareBazaar for providing a free, open repository of malware samples, TheZoo for curating a collection of live malware for research, MalShare for offering free API access to malware samples, YARA for the powerful pattern-matching engine, scikit-learn for the Random Forest ML implementation, TensorFlow for the deep learning framework (optional), abuse.ch for MalwareBazaar and threat intelligence platforms, PEfile for PE file parsing library, PyInstaller for packaging Python applications into executables, and Python for the programming language that powers it all.
=======
For general questions, feature requests, or discussions, feel free to open an issue or reach out.

---
>>>>>>> Stashed changes

## 📄 License

<<<<<<< Updated upstream


## 📬 Contact
Author: Aaron Chuah
GitHub: RonXIII (https://github.com/RonXIII)
Email: Tiongenxiii@gmail.com

For security vulnerabilities, please do not create a public issue. Instead, contact the author directly via GitHub (private) or email. For general questions, feature requests, or discussions, feel free to open an issue or reach out.



## 📄 License
=======
>>>>>>> Stashed changes
This project is licensed under the MIT License.

```
MIT License

Copyright (c) 2026 Aaron Chuah

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

<<<<<<< Updated upstream


## ⭐ Support the Project
If you find this tool useful, please consider starring the repository on GitHub, sharing it with colleagues and friends, contributing code, documentation, or bug reports, and reporting issues and suggesting improvements. Your support helps keep this project alive and growing!

## 📌 Version History
v4.0 (June 2026) – Complete rewrite with profile system, multi-source downloaders, and enhanced GUI
v3.0 (May 2026) – Added CNN training and 7‑Zip fallback
v2.0 (April 2026) – Added YARA and Random Forest detection
v1.0 (March 2026) – Initial release



## 🚀 Roadmap
=======
---

## ⭐ Support the Project

If you find this tool useful, please consider:

- **Starring** the repository on GitHub
- **Sharing** it with colleagues and friends
- **Contributing** code, documentation, or bug reports
- **Reporting** issues and suggesting improvements

Your support helps keep this project alive and growing!

---

## 📌 Version History

| Version | Date | Changes |
|---------|------|---------|
| v4.0 | June 2026 | Complete rewrite with profile system, multi-source downloaders, and enhanced GUI |
| v3.0 | May 2026 | Added CNN training and 7‑Zip fallback |
| v2.0 | April 2026 | Added YARA and Random Forest detection |
| v1.0 | March 2026 | Initial release |

---

## 🚀 Roadmap

>>>>>>> Stashed changes
Planned features for future releases:

- [ ] Support for ELF and Mach-O binaries
- [ ] Integration with VirusTotal API
- [ ] Cloud-based sandbox integration
- [ ] Automated YARA rule generation from ML results
- [ ] Export results in STIX/TAXII format
- [ ] Multi-language support (GUI translations)
- [ ] Dark/light theme toggle
- [ ] Batch scanning of multiple files
- [ ] Schedule periodic model retraining

---

**Thank you for using the Virus Analysis Platform!** 🛡️

<<<<<<< Updated upstream
Automated YARA rule generation from ML results

Export results in STIX/TAXII format

Multi-language support (GUI translations)

Dark/light theme toggle

Batch scanning of multiple files

Schedule periodic model retraining

Thank you for using the Virus Analysis Platform! Stay safe, and happy analyzing!
## Screenshots

<img width="399" height="377" alt="Screenshot 2026-06-21 181447" src="https://github.com/user-attachments/assets/9c3f4dd9-4670-4dad-8733-8a7076829be2" />
<img width="1143" height="1058" alt="Screenshot 2026-06-21 181517" src="https://github.com/user-attachments/assets/c737cc55-64c2-4c7d-be67-20637befcb53" />
<img width="1708" height="878" alt="Screenshot 2026-06-21 182244" src="https://github.com/user-attachments/assets/c05779d2-4374-4906-835f-8250bd36ab6d" />
<img width="1713" height="880" alt="Screenshot 2026-06-21 182306" src="https://github.com/user-attachments/assets/cdde814a-2adb-46f2-ba55-85bf2d7c47d7" />
<img width="1716" height="880" alt="Screenshot 2026-06-21 182358" src="https://github.com/user-attachments/assets/aa4a7657-3671-4909-83f8-81ae7b080c40" />
<img width="1711" height="856" alt="Screenshot 2026-06-21 182900" src="https://github.com/user-attachments/assets/a064d19d-baaa-46ef-a018-bf59fba30496" />
<img width="1707" height="877" alt="Screenshot 2026-06-21 183008" src="https://github.com/user-attachments/assets/952971fa-43dc-4b3b-8e6d-2077f895a8af" />





=======
Stay safe, and happy analyzing! 🔍
>>>>>>> Stashed changes
