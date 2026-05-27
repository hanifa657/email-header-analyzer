def check_phishing(headers):

    risk_score = 0
    reasons = []

    # SPF Check
    spf_result = headers.get("Received-SPF", "")

    if "fail" in spf_result.lower():
        risk_score += 30
        reasons.append("SPF failed")

    # DKIM Check
    dkim_result = headers.get("Authentication-Results", "")

    if "dkim=fail" in dkim_result.lower():
        risk_score += 30
        reasons.append("DKIM failed")

    # Reply-To Check
    reply_to = headers.get("Reply-To", "")

    if "evil.com" in reply_to.lower():
        risk_score += 20
        reasons.append("Suspicious Reply-To address")

    # Final Result
    if risk_score >= 50:
        status = "HIGH RISK - Possible Phishing"

    elif risk_score >= 20:
        status = "MEDIUM RISK"

    else:
        status = "LOW RISK"

    return f"""
Email Analysis Result
-----------------------
Risk Score: {risk_score}/100
Status: {status}

Reasons:
{', '.join(reasons)}
"""