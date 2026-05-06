# ⚡ KUSHZNDR / VulneraX

**Intelligent Automated Vulnerability Assessment Framework**

> Open-source · Zero-Setup · Python · CLI · Plugin System

[![License: MIT](https://img.shields.io/badge/License-MIT-7c3aed.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-00ff9d.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue.svg)]()

---

## 🎯 What is this?

This is a production-ready, **open-source** cybersecurity framework built for everyone from beginners to advanced penetration testers. It requires **zero setup** to run its base scans!

- Takes a **single input** (URL, IP, or domain) and performs a fully automated scan.
- Includes **Native Python Scanners** (Port scanner, Web Misconfiguration scanner, Header Security scanner) that run instantly with no external installations required.
- Capable of orchestrating **Nmap, OWASP ZAP, Nuclei, and Nikto** in parallel for advanced users.
- **Correlates findings** to remove duplicates and false positives.
- Generates **professional, cyberpunk-themed HTML reports** instantly.
- Supports a **dynamic plugin system**   add your own Python scanners in minutes!

---

## 🚀 How It Works (Quick Start)

### 1. Install Requirements
Ensure you have Python installed. Then, clone the repository and install the required Python libraries from `requirements.txt`:
```bash
git clone https://github.com/KUSHZNDR/vulnerax.git
cd vulnerax
pip install -r requirements.txt
```

### 2. Run (Beginner-Friendly Mode)
We built a "Zero-Setup" interactive mode. You don't need to install Nmap or any complex tools. Just run:
```bash
python main.py
```
This will launch the **Simple Interactive Mode** with the cool KUSHZNDR ASCII banner. It will ask for a domain/IP and immediately scan it using blazing-fast, built-in Python tools. The terminal output is 100% clean, and the results will be saved automatically to a `scan_results` folder.

### 3. Advanced Full Scan (For Power Users)
If you want to perform a deep, aggressive vulnerability assessment (and you have Nmap, Nuclei, Nikto, and ZAP installed on your operating system), run:
```bash
python main.py scan https://example.com --full
```

---

## 📦 Requirements

All Python dependencies are listed in `requirements.txt`. Simply install them using `pip install -r requirements.txt`.
External tools like Nmap, Nuclei, or ZAP are **completely optional** and only required if you explicitly use the `--full` mode. The default mode runs natively on pure Python!

---

## 🔌 Writing a Custom Plugin

1. Create a Python script in `plugins/my_scanner.py`
2. Subclass `PluginBase` and implement the `run()` function
3. VulneraX auto-discovers it on the next launch!

See `plugins/example_plugin.py` for a fully working example.

---

## 🤝 Open Source
This project is fully Open Source. Feel free to fork, modify, and submit Pull Requests!


