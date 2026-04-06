"""
Network Intrusion Detection — Domain-specific prompts and preprocessing.
"""


class NetworkIntrusionPrompts:
    """Prompts tailored for network intrusion detection (NSL-KDD style features)."""

    DOMAIN = "network_intrusion"
    DESCRIPTION = "Network Intrusion Detection"

    @staticmethod
    def get_detection_prompt() -> str:
        return """You are a specialized network intrusion detection analyst. Analyze the network
connection features below for signs of malicious activity. Consider:

1. CONNECTION BASICS: Protocol type, service, duration, and flag status
2. TRAFFIC VOLUME: Bytes sent/received — anomalous ratios may indicate data exfiltration or DoS
3. CONTENT FEATURES: Number of failed logins, root access attempts, su attempts, compromised conditions
4. TIME-BASED PATTERNS: Connection rates to same host/service in recent window
5. HOST-BASED PATTERNS: Number of connections to same host, error rates, service diversity

Common attack categories to check for:
- DoS (Denial of Service): High traffic volume, SYN floods, connection exhaustion
- Probe: Port scans, network mapping (unusual variety of services/ports)
- R2L (Remote to Local): Unauthorized remote access attempts, brute force
- U2R (User to Root): Privilege escalation attempts, buffer overflow indicators

Analyze the numerical features in context — a single anomalous feature may not indicate
an attack, but patterns across multiple features are strong signals."""

    @staticmethod
    def get_critic_context() -> str:
        return """When reviewing network intrusion detection, consider:
- False positives: Legitimate traffic spikes (backups, updates), network scans by security teams,
  high-volume legitimate services (streaming, file transfer)
- False negatives: Low-and-slow attacks that stay under thresholds, encrypted attack traffic,
  attacks that mimic normal user behavior patterns
- Check if the analyst properly correlated multiple features rather than relying on a single indicator"""

    @staticmethod
    def format_sample(record: dict) -> str:
        """Format network connection record into readable text."""
        lines = ["Network Connection Features:"]
        feature_groups = {
            "Basic": ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes"],
            "Content": ["land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
                       "logged_in", "num_compromised", "root_shell", "su_attempted",
                       "num_root", "num_file_creations", "num_shells", "num_access_files"],
            "Traffic": ["count", "srv_count", "serror_rate", "srv_serror_rate",
                       "rerror_rate", "srv_rerror_rate", "same_srv_rate",
                       "diff_srv_rate", "srv_diff_host_rate"],
            "Host": ["dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
                    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
                    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
                    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
                    "dst_host_srv_rerror_rate"],
        }

        for group_name, features in feature_groups.items():
            present = {f: record[f] for f in features if f in record}
            if present:
                lines.append(f"\n{group_name} Features:")
                for feat, val in present.items():
                    lines.append(f"  {feat}: {val}")

        # Fallback: show all features if none matched the groups
        if len(lines) == 1:
            for key, val in record.items():
                if key not in ("label", "attack_type", "class"):
                    lines.append(f"  {key}: {val}")

        return "\n".join(lines)
