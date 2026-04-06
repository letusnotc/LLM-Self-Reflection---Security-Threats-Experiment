"""
Phishing Email Detection — Domain-specific prompts and preprocessing.
"""


class PhishingPrompts:
    """Prompts tailored for phishing email detection."""

    DOMAIN = "phishing"
    DESCRIPTION = "Phishing Email Detection"

    @staticmethod
    def get_detection_prompt() -> str:
        return """You are a specialized phishing email detection analyst. Analyze the email below
for phishing indicators. Consider:

1. SENDER ANALYSIS: Check for spoofed domains, suspicious sender patterns, display name mismatches
2. CONTENT ANALYSIS: Look for urgency language, fear tactics, too-good-to-be-true offers
3. LINK ANALYSIS: Check for suspicious URLs, URL shorteners, domain misspellings, mismatched anchor text
4. ATTACHMENT ANALYSIS: Flag suspicious file types (.exe, .scr, .zip with macros)
5. HEADER ANOMALIES: SPF/DKIM failures, routing inconsistencies, unusual reply-to addresses
6. SOCIAL ENGINEERING: Impersonation of authority figures, brand spoofing, emotional manipulation
7. GRAMMATICAL CUES: Poor grammar, unusual formatting, mixed languages
8. REQUEST PATTERNS: Requests for credentials, personal data, money transfers, or urgent action

Be especially alert for sophisticated spear-phishing that targets specific individuals or organizations."""

    @staticmethod
    def get_critic_context() -> str:
        return """When reviewing phishing detection, pay special attention to:
- False positives: Legitimate marketing emails, password reset emails from real services,
  automated notifications that may look suspicious but are genuine
- False negatives: Sophisticated spear-phishing with correct grammar and personalized content,
  Business Email Compromise (BEC) attacks that don't contain obvious phishing indicators
- Context matters: An email from "IT department" about password changes could be legitimate
  or phishing — check for specific organizational indicators"""

    @staticmethod
    def format_sample(email_data: dict) -> str:
        """Format email data into a string for the agent."""
        parts = []
        if "subject" in email_data:
            parts.append(f"Subject: {email_data['subject']}")
        if "sender" in email_data:
            parts.append(f"From: {email_data['sender']}")
        if "body" in email_data:
            parts.append(f"\nBody:\n{email_data['body']}")
        if "text" in email_data:
            parts.append(f"\nContent:\n{email_data['text']}")
        return "\n".join(parts) if parts else str(email_data)
