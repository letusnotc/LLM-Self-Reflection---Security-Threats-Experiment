from .phishing import PhishingPrompts
from .network_intrusion import NetworkIntrusionPrompts
from .malware import MalwarePrompts
from .log_analysis import LogAnalysisPrompts

THREAT_DOMAINS = {
    "phishing": PhishingPrompts,
    "network_intrusion": NetworkIntrusionPrompts,
    "malware": MalwarePrompts,
    "log_analysis": LogAnalysisPrompts,
}
