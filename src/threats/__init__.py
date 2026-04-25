from .phishing import PhishingPrompts
from .network_intrusion import NetworkIntrusionPrompts

THREAT_DOMAINS = {
    "phishing": PhishingPrompts,
    "network_intrusion": NetworkIntrusionPrompts,
}
