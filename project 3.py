# =====================================================
# DecodeLabs Cyber Security Project 3
# Phishing Awareness Analysis
# =====================================================

import re

print("=" * 60)
print("          PHISHING AWARENESS ANALYSIS")
print("=" * 60)

message = input("\nPaste the email/message below:\n\n")

message_lower = message.lower()

# Suspicious keywords
keywords = [
    "urgent",
    "verify",
    "login",
    "password",
    "bank",
    "account",
    "click here",
    "winner",
    "congratulations",
    "free",
    "gift",
    "prize",
    "claim",
    "limited time",
    "update",
    "confirm",
    "security alert",
    "invoice",
    "payment",
    "bitcoin",
    "crypto",
    "wire transfer",
    "refund",
    "tax",
    "suspended",
    "locked",
    "act now"
]

found_keywords = []

for word in keywords:
    if word in message_lower:
        found_keywords.append(word)

# Detect URLs
url_pattern = r'(https?://\S+|www\.\S+)'
urls = re.findall(url_pattern, message)

# Detect email addresses
email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
emails = re.findall(email_pattern, message)

# Risk calculation
risk_score = 0

risk_score += len(found_keywords)

if len(urls) > 0:
    risk_score += 3

if len(emails) > 0:
    risk_score += 1

# Suspicious domains
bad_domains = [
    ".xyz",
    ".top",
    ".ru",
    ".tk",
    ".gq",
    ".cf"
]

suspicious_domains = []

for url in urls:
    for domain in bad_domains:
        if domain in url.lower():
            suspicious_domains.append(url)
            risk_score += 2

# Final Result
print("\n" + "=" * 60)
print("ANALYSIS REPORT")
print("=" * 60)

print("\nMessage:")
print(message)

print("\nDetected URLs:")

if urls:
    for url in urls:
        print(" -", url)
else:
    print(" None")

print("\nDetected Email Addresses:")

if emails:
    for email in emails:
        print(" -", email)
else:
    print(" None")

print("\nSuspicious Keywords Found:")

if found_keywords:
    for word in found_keywords:
        print(" -", word)
else:
    print(" None")

print("\nRed Flags:")

red_flags = []

if urls:
    red_flags.append("Contains clickable links.")

if suspicious_domains:
    red_flags.append("Uses suspicious domain extension.")

if "urgent" in found_keywords:
    red_flags.append("Creates urgency.")

if "click here" in found_keywords:
    red_flags.append("Requests immediate clicking.")

if "verify" in found_keywords:
    red_flags.append("Requests account verification.")

if "password" in found_keywords:
    red_flags.append("Mentions password.")

if "bank" in found_keywords:
    red_flags.append("Mentions banking information.")

if "winner" in found_keywords or "prize" in found_keywords:
    red_flags.append("Claims fake rewards.")

if "free" in found_keywords:
    red_flags.append("Promises free offers.")

if "account" in found_keywords:
    red_flags.append("Targets user accounts.")

if "bitcoin" in found_keywords or "crypto" in found_keywords:
    red_flags.append("Requests cryptocurrency.")

if "wire transfer" in found_keywords:
    red_flags.append("Requests money transfer.")

if "refund" in found_keywords:
    red_flags.append("Uses refund scam language.")

if red_flags:
    for flag in red_flags:
        print(" -", flag)
else:
    print(" No major red flags detected.")

print("\nWhy This Message May Be Unsafe:")

if risk_score >= 8:
    print("""
This message contains multiple phishing indicators.
It attempts to create urgency, asks for sensitive
information, or contains suspicious links.
Do NOT click any links or provide personal data.
""")

elif risk_score >= 4:
    print("""
This message appears suspicious.
Always verify the sender before clicking any links
or sharing confidential information.
""")

else:
    print("""
Very few phishing indicators were detected.
However, always verify unknown senders before
opening links or attachments.
""")

print("Risk Score :", risk_score)

if risk_score >= 8:
    print("Verdict    : HIGH RISK PHISHING")
elif risk_score >= 4:
    print("Verdict    : SUSPICIOUS MESSAGE")
else:
    print("Verdict    : LIKELY SAFE")

print("=" * 60)