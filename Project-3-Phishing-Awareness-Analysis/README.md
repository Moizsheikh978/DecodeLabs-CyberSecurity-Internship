# Project 3: Phishing Awareness Analysis

## DecodeLabs Cyber Security Internship

This project is a beginner-friendly phishing awareness and
triage tool created using Python.

The program analyzes sample emails or messages and identifies
common phishing indicators.

## Project Objectives

- Identify suspicious links and keywords.
- Detect sender and Reply-To domain mismatches.
- List red flags found in suspicious messages.
- Explain why a message may be unsafe.
- Classify messages as Safe, Suspicious or Malicious.
- Provide a suitable security response.

## Features

The program checks for:

- Sender-domain mismatches
- Suspicious keywords
- Urgency and pressure
- Password-verification requests
- Financial requests
- URL shorteners
- Insecure HTTP links
- IP-address links
- Nested subdomains
- Dangerous attachments
- Secrecy and procedure-bypass requests

## Project Files

| File | Description |
|---|---|
| phishing_analyzer.py | Main Python program |
| PHISHING_TRIAGE_CHECKLIST.md | Phishing checklist and decision tree |
| SAMPLE_ANALYSIS_REPORT.md | Written analysis of the sample messages |
| sample_messages.txt | Three fictional messages used for testing |
| README.md | Project documentation |

## Requirements

- Python 3
- Visual Studio Code
- No external libraries are required

## How to Run

Open the project folder in Visual Studio Code.

Run:

```bash
python phishing_analyzer.py