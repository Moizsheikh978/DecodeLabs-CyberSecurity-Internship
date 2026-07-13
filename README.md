# DecodeLabs Cybersecurity Internship Projects

This repository contains my cybersecurity internship projects completed as part of the **DecodeLabs Industrial Training Kit**.

---

## Project 1: Password Strength Checker

This project checks the strength of a user-entered password based on common password security requirements.

### Features

- Checks password length
- Checks for uppercase letters
- Checks for lowercase letters
- Checks for numbers
- Checks for special symbols
- Detects common weak passwords
- Displays password strength as Weak, Medium, or Strong

### How to Run

```bash
cd Project-1-Password-Checker
python password_checker.py
```

---

## Project 2: Basic Encryption and Decryption

This project implements a basic Caesar cipher encryption and decryption tool.

### Features

- Accepts user text input
- Accepts a shift key
- Encrypts text using Caesar cipher logic
- Decrypts encrypted text back to the original text
- Displays the original, encrypted, and decrypted output

### How to Run

```bash
cd Project-2-Caesar-Cipher
python caesar_cipher.py
```

---

## Project 3: Phishing Awareness Analysis

This project is a basic phishing awareness and email triage tool developed using Python. It analyzes sample emails or messages and identifies common indicators of phishing attacks.

### Features

- Checks sender and Reply-To domain mismatches
- Detects suspicious words and phrases
- Identifies urgency and pressure tactics
- Detects password and account verification requests
- Identifies financial and wire transfer requests
- Checks suspicious and shortened URLs
- Detects insecure HTTP links
- Identifies IP-address links
- Detects nested or suspicious subdomains
- Checks for dangerous attachment types
- Lists the red flags found in a message
- Explains why the message may be unsafe
- Classifies messages as Safe, Suspicious, or Malicious
- Provides a recommended action for each result

### Project Files

- `phishing_analyzer.py` - Main Python program
- `PHISHING_TRIAGE_CHECKLIST.md` - Phishing checklist and decision tree
- `SAMPLE_ANALYSIS_REPORT.md` - Analysis of the sample messages
- `sample_messages.txt` - Fictional messages used for testing
- `README.md` - Project documentation

### How to Run

```bash
cd Project-3-Phishing-Awareness-Analysis
python phishing_analyzer.py
```

The program allows the user to analyze three prepared sample messages or enter a custom message for analysis.

---

## Technologies Used

- Python
- Caesar Cipher
- Password security logic
- Regular expressions
- URL parsing
- Phishing detection rules
- Email and domain analysis
- Basic cybersecurity concepts

---

## Purpose

The purpose of these projects is to demonstrate basic cybersecurity skills through hands-on Python programming.

- **Project 1** focuses on password security and identifying weak passwords.
- **Project 2** focuses on data confidentiality using encryption and decryption.
- **Project 3** focuses on phishing awareness, suspicious message analysis, and threat identification.

These projects helped me practise secure programming, input validation, encryption concepts, phishing detection, and cybersecurity decision-making.
