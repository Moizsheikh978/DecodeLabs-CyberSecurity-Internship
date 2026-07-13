import re
from urllib.parse import urlparse


# Words and phrases commonly found in phishing messages
SUSPICIOUS_KEYWORDS = [
    "urgent",
    "immediately",
    "verify your account",
    "password expires",
    "account suspended",
    "click here",
    "sign in",
    "update billing",
    "wire transfer",
    "gift card",
    "strictly confidential",
    "do not tell anyone",
    "bypass procedure",
    "claim your prize"
]


# Common URL-shortening services
SHORTENED_URL_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "ow.ly",
    "cutt.ly",
    "rb.gy"
]


# File types that may be dangerous when unexpected
DANGEROUS_EXTENSIONS = [
    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".bat",
    ".cmd",
    ".iso",
    ".img",
    ".lnk",
    ".zip",
    ".rar",
    ".docm",
    ".xlsm"
]


def get_email_domain(email_address):
    """Extract the domain from an email address."""

    if "@" not in email_address:
        return ""

    return email_address.split("@")[-1].lower().strip()


def extract_urls(text):
    """Find URLs inside the message body."""

    pattern = r'https?://[^\s]+|www\.[^\s]+'
    return re.findall(pattern, text)


def check_url(url):
    """Inspect a URL and return any red flags."""

    red_flags = []

    # Remove punctuation that may appear after a URL
    clean_url = url.rstrip(".,);]")

    # Add http temporarily if the URL begins with www
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "http://" + clean_url

    parsed_url = urlparse(clean_url)
    hostname = parsed_url.hostname or ""

    # Check whether the link uses insecure HTTP
    if clean_url.startswith("http://"):
        red_flags.append(
            "The link does not use HTTPS."
        )

    # Check for shortened links
    if hostname in SHORTENED_URL_DOMAINS:
        red_flags.append(
            "The link uses a URL shortener that hides the real destination."
        )

    # Check whether an IP address is used instead of a domain
    ip_pattern = r"\d{1,3}(\.\d{1,3}){3}"

    if re.fullmatch(ip_pattern, hostname):
        red_flags.append(
            "The link uses an IP address instead of a normal domain."
        )

    # Check for too many subdomains
    if len(hostname.split(".")) >= 5:
        red_flags.append(
            "The link contains many nested subdomains."
        )

    # Check for suspicious words inside the domain
    suspicious_domain_words = [
        "login",
        "verify",
        "secure",
        "update",
        "account",
        "billing"
    ]

    found_words = []

    for word in suspicious_domain_words:
        if word in hostname:
            found_words.append(word)

    if len(found_words) >= 2:
        red_flags.append(
            "The domain contains several suspicious words: "
            + ", ".join(found_words)
        )

    return red_flags


def analyze_message(sender, reply_to, subject, body, attachment):
    """Analyze an email or message for phishing indicators."""

    red_flags = []
    score = 0

    sender_domain = get_email_domain(sender)
    reply_to_domain = get_email_domain(reply_to)

    # Check whether sender and Reply-To domains match
    if (
        sender_domain
        and reply_to_domain
        and sender_domain != reply_to_domain
    ):
        red_flags.append(
            f"Sender-domain mismatch: '{sender_domain}' does not match "
            f"Reply-To domain '{reply_to_domain}'."
        )

        score += 3

    # Combine subject and body for keyword analysis
    full_message = f"{subject} {body}".lower()

    found_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in full_message:
            found_keywords.append(keyword)

    if found_keywords:
        red_flags.append(
            "Suspicious words or phrases found: "
            + ", ".join(found_keywords)
        )

        # Maximum of four points for keywords
        score += min(len(found_keywords), 4)

    # Extract and inspect links
    urls = extract_urls(body)

    for url in urls:
        url_flags = check_url(url)

        for flag in url_flags:
            red_flags.append(
                f"{flag} Link: {url}"
            )

            score += 2

    # Check the attachment extension
    if attachment:
        attachment_lower = attachment.lower()

        for extension in DANGEROUS_EXTENSIONS:
            if attachment_lower.endswith(extension):
                red_flags.append(
                    f"Dangerous attachment type detected: '{attachment}'."
                )

                score += 4
                break

    # Decide the classification
    if score >= 8:
        classification = "MALICIOUS"

        action = (
            "Do not interact. Block the sender and escalate "
            "to the security team."
        )

    elif score >= 3:
        classification = "SUSPICIOUS"

        action = (
            "Warn the user and verify the request using "
            "a trusted second channel."
        )

    else:
        classification = "SAFE / LOW RISK"

        action = (
            "Close the triage event, but continue normal caution."
        )

    # Display the analysis result
    print("\n" + "=" * 65)
    print("PHISHING AWARENESS ANALYSIS RESULT")
    print("=" * 65)

    print(f"Sender: {sender}")
    print(f"Reply-To: {reply_to}")
    print(f"Subject: {subject}")
    print(f"Risk Score: {score}")
    print(f"Classification: {classification}")
    print(f"Recommended Action: {action}")

    print("\nRed Flags Found:")

    if red_flags:
        for number, flag in enumerate(red_flags, start=1):
            print(f"{number}. {flag}")

    else:
        print("No major red flags were detected.")

    print("\nWhy the message may be unsafe:")

    if red_flags:
        print(
            "The message contains indicators commonly used in phishing, "
            "such as sender mismatches, pressure words, deceptive links, "
            "or risky attachments."
        )

    else:
        print(
            "The sender information and message content do not contain "
            "major phishing indicators in this basic analysis."
        )

    print("=" * 65)


# Three fictional messages used for safe testing
SAMPLE_EMAILS = {
    "1": {
        "name": "Legitimate Project Update",

        "sender": "sarah.lee@company.com",

        "reply_to": "sarah.lee@company.com",

        "subject": "Q3 Project Status Update",

        "body": (
            "Hi Team, please review the project update "
            "when convenient."
        ),

        "attachment": "Q3_Status.pdf"
    },

    "2": {
        "name": "Suspicious Password Reset",

        "sender": "support@microsoft-security-alert.com",

        "reply_to": "verify@account-services.com",

        "subject": "URGENT: Password expires within 24 hours",

        "body": (
            "Dear user, verify your account immediately. "
            "Click here and sign in: "
            "http://microsoft.secure-login-update.example.com"
        ),

        "attachment": ""
    },

    "3": {
        "name": "Malicious Executive Payment Request",

        "sender": "ceo.office@executive-update.com",

        "reply_to": "transfer@fast-payments.com",

        "subject": "IMMEDIATE ACTION: Wire Transfer",

        "body": (
            "This is strictly confidential. Do not tell anyone. "
            "Bypass procedure and complete the wire transfer immediately."
        ),

        "attachment": "Payment_Instructions.iso"
    }
}


def analyze_custom_message():
    """Allow the user to enter another message for analysis."""

    print("\nEnter the message details.")

    sender = input(
        "Sender email address: "
    ).strip()

    reply_to = input(
        "Reply-To email address: "
    ).strip()

    subject = input(
        "Subject: "
    ).strip()

    body = input(
        "Message body in one line: "
    ).strip()

    attachment = input(
        "Attachment name, or press Enter if none: "
    ).strip()

    analyze_message(
        sender,
        reply_to,
        subject,
        body,
        attachment
    )


def main():
    """Display the main program menu."""

    while True:
        print("\nPROJECT 3 - PHISHING AWARENESS ANALYSIS")

        print("1. Analyze Sample 1 - Legitimate message")
        print("2. Analyze Sample 2 - Suspicious password reset")
        print("3. Analyze Sample 3 - Malicious payment request")
        print("4. Analyze your own message")
        print("5. Exit")

        choice = input(
            "Choose an option from 1 to 5: "
        ).strip()

        if choice in SAMPLE_EMAILS:
            sample = SAMPLE_EMAILS[choice]

            print(
                f"\nAnalyzing: {sample['name']}"
            )

            analyze_message(
                sample["sender"],
                sample["reply_to"],
                sample["subject"],
                sample["body"],
                sample["attachment"]
            )

        elif choice == "4":
            analyze_custom_message()

        elif choice == "5":
            print(
                "Program closed. Remember: Pause, Verify, Report."
            )

            break

        else:
            print(
                "Invalid choice. Please enter a number from 1 to 5."
            )


if __name__ == "__main__":
    main()