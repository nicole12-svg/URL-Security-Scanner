# URL Security Scanner

A professional Python project for automated URL/link security analysis with both CLI and GUI access.

This tool crawls a target website from a starting URL, identifies broken links, potential SQL injection/XSS payloads, suspicious redirects, malicious domains, and risky downloads, and surfaces results in a concise report.

## Why this project matters

- Demonstrates practical knowledge of web crawling, security scanning, and threat detection.
- Shows experience building both command-line tools and a lightweight GUI.
- Includes Python threading, request handling, parsing, and structured result reporting.

## Key features

- Domain-restricted crawling with configurable depth
- Link validation and broken link detection
- Security indicator detection including payload patterns and suspicious destination analysis
- Minimal Tkinter GUI with live progress logs and result display
- Extensible report generation for text or JSON output

## Project structure

- `url_scanner.py` - core scanner implementation and command-line interface
- `gui.py` - Tkinter-based graphical front end that runs scanning in a background thread and displays live logs

## Requirements

- Python 3.8 or newer
- Tkinter (built-in for most Python installs; Linux may require `python3-tk`)

## Run the project

1. Launch the GUI:

```bash
python gui.py
```

2. Or run the scanner from the command line:

```bash
python url_scanner.py
```

## Usage notes

- The GUI keeps the interface responsive by running the crawler on a separate thread.
- The default configuration limits crawling to the initial domain and a safe number of pages.
- Behavior can be extended and tuned inside `url_scanner.py`, including crawl depth, link filtering, and result formatting.

## Extensibility and next improvements

- Add asynchronous requests or worker pools to improve scanning performance
- Integrate additional security checks such as CSP, cookie flags, HTTPS enforcement, or header analysis
- Add export options like CSV, XML, or JSON report files
- Expand the GUI with user-configurable scan settings and scheduled reports

## Notes for reviewers

This repository is intended to showcase a practical security automation tool built in Python, along with a clean user-facing interface and room for further enhancement.

