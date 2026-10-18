# CyberLens

**Static File Threat Triage & Malware Analysis Workbench**

*"See the file. Understand the risk."*

## Overview

CyberLens is a defensive static analysis platform designed to help security analysts investigate suspicious files by examining static characteristics and presenting evidence-based risk indicators. It performs safe static analysis without ever executing uploaded files.

## Important Disclaimer

CyberLens performs static analysis and does not execute uploaded files. Results are indicators intended for preliminary security triage and should not be treated as definitive malware classification. Always investigate suspicious files in an isolated, controlled environment.

## Installation

### Prerequisites

- Python 3.12+
- pip

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd cyberlens
```

2. Create a virtual environment:
```bash
python -m venv venv
```

3. Activate the virtual environment:

On Windows:
```bash
venv\Scripts\activate
```

On macOS/Linux:
```bash
source venv/bin/activate
```

4. Install dependencies:
```bash
pip install -r requirements.txt
```

5. Create a `.env` file:
```bash
copy .env.example .env
```

Edit `.env` and set your secret key and other configuration values.

6. Run the application:
```bash
python app.py
```

7. Open your browser and navigate to:
```
http://localhost:5000
```

## Project Structure

```
cyberlens/
├── app.py                 # Flask application
├── config.py              # Configuration
├── requirements.txt       # Python dependencies
├── .env.example          # Environment variables template
├── .gitignore            # Git ignore rules
├── README.md             # This file
├── LICENSE               # License file
├── analyzer/             # Static analysis modules
├── database/             # Database models
├── routes/               # API routes
├── reports/              # Report generation
├── templates/            # HTML templates
├── static/               # CSS, JS, assets
├── uploads/              # File upload directory
├── sample_data/          # Test samples
├── tests/                # Test suite
└── instance/             # Database instance
```

## Features

- Safe static file analysis (no execution)
- Cryptographic hashing (MD5, SHA-1, SHA-256)
- File identification and metadata extraction
- String extraction and analysis
- Entropy analysis
- PE file analysis for Windows executables
- Suspicious indicator detection
- Transparent risk scoring system
- Professional investigation reports
- Investigation history with search and filtering

## Security Model

CyberLens follows a strict static-only analysis approach:

- All uploaded files are treated as untrusted input
- Files are never executed, opened, or launched
- Filenames are sanitized and randomized for storage
- File size limits prevent resource exhaustion
- Path traversal protection prevents directory escape
- Analysis results are indicators, not definitive classifications

## Technology Stack

- **Backend**: Python 3.12+, Flask, SQLAlchemy, SQLite
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Analysis**: hashlib, pathlib, os, re, math, datetime, python-magic, pefile
- **Reports**: ReportLab
- **Testing**: pytest
- **Configuration**: python-dotenv

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Future Improvements

Planned features for future versions:

- YARA rules integration
- VirusTotal hash lookup
- Threat intelligence feeds
- ClamAV integration
- Sandbox integration
- MITRE ATT&CK mapping
- IOC extraction
- User authentication
- Multi-user analyst support
- Docker isolation
- Malware family classification

## Contact

For questions or issues, please open an issue on GitHub.
