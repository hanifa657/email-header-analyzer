def check_phishing(headers):

    risk_score = 0
    reasons = []

    # SPF Check
    spf_result = headers.get("Received-SPF", "").lower()

    if "fail" in spf_result:
        risk_score += 30
        reasons.append("SPF failed")
        spf_status = "FAIL"

    else:
        spf_status = "PASS"

    # DKIM Check
    dkim_result = headers.get("Authentication-Results", "").lower()

    if "dkim=fail" in dkim_result:
        risk_score += 30
        reasons.append("DKIM failed")
        dkim_status = "FAIL"

    else:
        dkim_status = "PASS"

    # DMARC Check
    dmarc_result = headers.get("DMARC", "").lower()

    if "fail" in dmarc_result:
        risk_score += 30
        reasons.append("DMARC failed")
        dmarc_status = "FAIL"

    else:
        dmarc_status = "PASS"

    # Reply-To Check
    reply_to = headers.get("Reply-To", "")

    if "evil.com" in reply_to.lower():
        risk_score += 20
        reasons.append("Suspicious Reply-To address")

    # Suspicious Domain Check
    sender = headers.get("From", "").lower()

    suspicious_domains = [
        ".ru",
        "secure-paypal",
        "login-alert",
        "verify-account"
    ]

    for domain in suspicious_domains:

        if domain in sender:
            risk_score += 20
            reasons.append(f"Suspicious domain detected: {domain}")

    # Limit score to 100
    if risk_score > 100:
        risk_score = 100

    # Final Risk Status
    if risk_score >= 70:
        status = "HIGH RISK - Possible Phishing"

    elif risk_score >= 30:
        status = "MEDIUM RISK"

    else:
        status = "LOW RISK"

    return f"""
Email Authentication Summary
------------------------------
SPF: {spf_status}
DKIM: {dkim_status}
DMARC: {dmarc_status}

Email Analysis Result
-----------------------
Risk Score: {risk_score}/100
Status: {status}

Reasons:
{', '.join(reasons)}
"""