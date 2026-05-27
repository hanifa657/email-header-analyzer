from analyzer.parser import extract_headers
from analyzer.detector import check_phishing

file_path = "sample_headers/phishing1.txt"

headers = extract_headers(file_path)

# Extract sender email
sender = headers.get("From", "Unknown Sender")

# Run phishing detection
result = check_phishing(headers)

print("\n=== Email Header Analysis ===")
print(f"Sender: {sender}")

print(result)