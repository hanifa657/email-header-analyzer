# Email Header Analyzer

A beginner SOC analyst project built with Python.

## Features
- Email header parsing
- SPF detection
- DKIM detection
- Reply-To analysis
- Risk scoring system

## Technologies Used
- Python
- VS Code

## How to Run

```bash
python main.py

## Sample Output
```text
=== Email Header Analysis ===
Sender: paypal-security@gmail.com

Email Analysis Result
-----------------------
Risk Score: 80/100
Status: HIGH RISK - Possible Phishing

Reasons:
SPF failed, DKIM failed, Suspicious Reply-To address
```