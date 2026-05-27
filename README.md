# Email Header Analyzer

A Python-based SOC analyst project for phishing email investigation and email header analysis.

## Features

- Email header parsing
- SPF authentication analysis
- DKIM authentication analysis
- DMARC authentication analysis
- Sender IP extraction using Regex
- Suspicious Reply-To detection
- Suspicious domain detection
- Risk scoring system
- Flask web interface
- Styled cybersecurity dashboard UI

## Technologies Used

- Python
- Flask
- HTML
- CSS
- Regex
- VS Code

## Project Structure

email-header-analyzer/
│
├── app.py
├── main.py
├── README.md
│
├── analyzer/
│ ├── parser.py
│ ├── detector.py
│
├── templates/
│ ├── index.html
│
├── sample_headers/
│ ├── phishing1.txt

## How to Run

### Install Flask

```bash
pip install flask