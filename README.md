# CyberLens

**Static File Threat Triage & Malware Analysis Workbench**

> *See the file. Understand the risk.*

## Overview

CyberLens is a defensive static analysis platform designed to help security analysts investigate files by examining their static characteristics and presenting evidence-based security indicators.

CyberLens performs analysis **without executing uploaded files**. It combines file identification, cryptographic hashing, metadata inspection, string extraction, entropy analysis, PE analysis, indicator detection, and explainable risk scoring into a single investigation workflow.

## Important Disclaimer

CyberLens is designed for **preliminary security triage** and educational analysis.

Analysis results represent static indicators and should **not** be treated as definitive malware classification. Suspicious files should always be investigated in an isolated and controlled environment.

CyberLens does not execute uploaded files.

---

## Key Features

- Secure file upload and validation
- Static analysis without file execution
- File type and MIME identification
- MD5, SHA-1 and SHA-256 hashing
- File metadata analysis
- String extraction and categorization
- Entropy analysis
- PE file analysis
- Suspicious indicator detection
- Explainable risk scoring
- Analyst verdicts and recommendations
- Investigation history
- Search and filtering
- PDF investigation reports
- Responsive security-focused interface

---

## Analysis Workflow

```text
File Upload
     ↓
File Identification
     ↓
Cryptographic Hashing
     ↓
Metadata Analysis
     ↓
String Extraction
     ↓
Entropy Analysis
     ↓
PE Analysis
     ↓
Indicator Detection
     ↓
Risk Scoring
     ↓
Analyst Verdict
     ↓
Investigation Report