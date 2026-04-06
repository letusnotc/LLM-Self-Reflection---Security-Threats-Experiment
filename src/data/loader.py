"""
Data Loader — Unified dataset loading and preprocessing for all threat domains.
Supports loading from CSV files and generates synthetic samples for testing.
"""

import os
import glob
import random
import pandas as pd
import logging
from typing import Optional

from src.config import DATA_DIR, RANDOM_SEED, SAMPLES_PER_DOMAIN

random.seed(RANDOM_SEED)
logger = logging.getLogger(__name__)


class DataLoader:
    """
    Loads and preprocesses datasets for each threat domain.
    Each sample is returned as: {"text": str, "label": int (0=benign, 1=malicious), "raw": dict}
    """

    def __init__(self, data_dir: str = None, samples_per_domain: int = None):
        self.data_dir = data_dir or DATA_DIR
        self.samples_per_domain = samples_per_domain or SAMPLES_PER_DOMAIN

    def _find_csv(self, subdir: str, preferred_names: list[str]) -> Optional[str]:
        """Find a CSV file in the given subdirectory, trying preferred names first, then any CSV."""
        folder = os.path.join(self.data_dir, subdir)
        # Try preferred filenames first
        for name in preferred_names:
            path = os.path.join(folder, name)
            if os.path.exists(path):
                return path
        # Fallback: grab any CSV in the folder
        csvs = glob.glob(os.path.join(folder, "*.csv"))
        if csvs:
            return csvs[0]
        return None

    def load(self, domain: str, split: str = "test") -> list[dict]:
        """
        Load dataset for a specific domain.

        Args:
            domain: One of 'phishing', 'network_intrusion', 'malware', 'log_analysis'
            split: 'train', 'test', or 'all'

        Returns:
            List of dicts with 'text', 'label', and 'raw' keys
        """
        loaders = {
            "phishing": self._load_phishing,
            "network_intrusion": self._load_network,
            "malware": self._load_malware,
            "log_analysis": self._load_logs,
        }

        if domain not in loaders:
            raise ValueError(f"Unknown domain: {domain}. Options: {list(loaders.keys())}")

        data = loaders[domain]()

        # Balance and sample
        data = self._balance_and_sample(data)

        return data

    def _load_phishing(self) -> list[dict]:
        """Load phishing email dataset from CSV."""
        path = self._find_csv("phishing", ["phishing_emails.csv", "CEAS_08.csv", "Nazario.csv"])

        if path:
            df = pd.read_csv(path)
            samples = []
            for _, row in df.iterrows():
                row_dict = row.to_dict()
                # Flexible text extraction
                text = row_dict.get("body", row_dict.get("text", row_dict.get("email_text", "")))
                subject = row_dict.get("subject", "")
                sender = row_dict.get("sender", row_dict.get("from", ""))

                # Build a proper email dict for format_sample
                email_data = {"subject": subject, "sender": sender, "body": str(text)[:2000]}

                # Flexible label extraction
                label_val = row_dict.get("label", row_dict.get("class", row_dict.get("is_phishing", 0)))
                label = 1 if str(label_val).lower() in ("1", "phishing", "spam", "yes", "true") else 0

                from src.threats.phishing import PhishingPrompts
                formatted = PhishingPrompts.format_sample(email_data)
                samples.append({"text": formatted, "label": label, "raw": email_data})

            # Check if dataset is single-class (e.g., Nazario is all phishing)
            labels = set(s["label"] for s in samples)
            if len(labels) == 1:
                logger.warning(f"Phishing dataset has only class {labels}. Adding synthetic samples for the missing class.")
                synthetic = self._synthetic_phishing()
                missing_class = 0 if 1 in labels else 1
                extras = [s for s in synthetic if s["label"] == missing_class]
                samples.extend(extras)

            return samples

        # Generate synthetic samples if no dataset found
        return self._synthetic_phishing()

    def _load_network(self) -> list[dict]:
        """Load NSL-KDD or similar network intrusion dataset."""
        path = self._find_csv("network", ["kdd_test.csv", "NSL-KDD_labeled.csv", "network_data.csv"])

        if path:
            df = pd.read_csv(path)
            samples = []
            for _, row in df.iterrows():
                row_dict = row.to_dict()
                # Flexible label detection
                label_col = [c for c in df.columns if c.lower() in ("label", "class", "attack_type", "target")]
                label_val = row_dict.get(label_col[0], "normal") if label_col else "normal"
                label = 0 if str(label_val).lower() in ("normal", "0", "benign") else 1

                from src.threats.network_intrusion import NetworkIntrusionPrompts
                text = NetworkIntrusionPrompts.format_sample(row_dict)
                samples.append({"text": text, "label": label, "raw": row_dict})
            return samples

        return self._synthetic_network()

    def _load_malware(self) -> list[dict]:
        """Load malware PE features dataset."""
        path = self._find_csv("malware", ["malware_features.csv", "pe_features.csv",
                                           "ClaMP_Integrated-5184.csv"])

        if path:
            df = pd.read_csv(path)
            samples = []
            for _, row in df.iterrows():
                row_dict = row.to_dict()
                # Flexible label detection
                label_col = [c for c in df.columns if c.lower() in ("label", "class", "malware", "legitimate")]
                label_val = row_dict.get(label_col[0], 0) if label_col else 0
                label = 1 if str(label_val).lower() in ("1", "malware", "malicious", "yes", "true") else 0

                from src.threats.malware import MalwarePrompts
                text = MalwarePrompts.format_sample(row_dict)
                samples.append({"text": text, "label": label, "raw": row_dict})
            return samples

        return self._synthetic_malware()

    def _load_logs(self, window_size: int = 7) -> list[dict]:
        """
        Load system/auth log dataset using a sliding window approach.
        Instead of single events, groups nearby events by user into windows
        so the model can see behavioral patterns (e.g., login → USB → file → disconnect).

        A window is labeled malicious (1) if ANY event in the window is malicious.
        """
        path = self._find_csv("logs", ["auth_logs.csv", "auth_logs_small.csv", "log_data.csv"])

        if path:
            df = pd.read_csv(path, low_memory=False)

            # Map CERT dataset columns to display-friendly names
            col_map = {}
            if "pc" in df.columns and "resource" not in df.columns:
                col_map["pc"] = "resource"
            if "source" in df.columns and "source_type" not in df.columns:
                col_map["source"] = "source_type"
            if "size" in df.columns and "bytes_transferred" not in df.columns:
                col_map["size"] = "bytes_transferred"
            # NOTE: Keep "activity" as-is — format_sample() expects "activity", not "action"
            if col_map:
                df = df.rename(columns=col_map)

            # Sort by user and time for proper windowing
            df = df.sort_values(["user", "date"]).reset_index(drop=True)

            # Detect label column
            label_col = [c for c in df.columns if c.lower() in ("label", "class", "threat", "insider_threat")]
            label_col = label_col[0] if label_col else None

            from src.threats.log_analysis import LogAnalysisPrompts

            samples = []
            # Build windows per user
            for user_id, user_df in df.groupby("user"):
                user_df = user_df.reset_index(drop=True)
                n_events = len(user_df)

                # Slide window with step = window_size (non-overlapping)
                for start in range(0, n_events, window_size):
                    end = min(start + window_size, n_events)
                    window = user_df.iloc[start:end]

                    # Label: malicious if any event in window is malicious
                    if label_col:
                        labels = window[label_col].astype(str).str.lower()
                        label = 1 if labels.isin(["1", "malicious", "threat", "yes", "true"]).any() else 0
                    else:
                        label = 0

                    # Build window text — show all events as a sequence
                    event_lines = []
                    for idx, (_, row) in enumerate(window.iterrows()):
                        row_dict = row.to_dict()
                        clean_dict = {k: v for k, v in row_dict.items()
                                      if pd.notna(v) and k not in ("label", "class", "threat", "id")}
                        event_lines.append(f"  Event {idx+1}: " + " | ".join(
                            f"{k}={v}" for k, v in clean_dict.items()
                            if k in ("date", "source_type", "activity", "action", "resource",
                                     "filename", "url", "to", "from", "bytes_transferred",
                                     "attachments")
                        ))

                    window_text = (
                        f"Activity Window for Employee {user_id} ({len(window)} events):\n"
                        + "\n".join(event_lines)
                    )

                    raw = {
                        "user": user_id,
                        "window_start": str(window.iloc[0].get("date", "")),
                        "window_end": str(window.iloc[-1].get("date", "")),
                        "num_events": len(window),
                        "events": [
                            {k: v for k, v in row.to_dict().items()
                             if pd.notna(v) and k not in ("label", "class", "threat")}
                            for _, row in window.iterrows()
                        ],
                    }

                    samples.append({"text": window_text, "label": label, "raw": raw})

            return samples

        return self._synthetic_logs()

    def _balance_and_sample(self, data: list[dict]) -> list[dict]:
        """Balance classes and sample to target size."""
        benign = [s for s in data if s["label"] == 0]
        malicious = [s for s in data if s["label"] == 1]

        n = min(len(benign), len(malicious), self.samples_per_domain // 2)
        if n == 0:
            return data[:self.samples_per_domain]

        random.shuffle(benign)
        random.shuffle(malicious)

        balanced = benign[:n] + malicious[:n]
        random.shuffle(balanced)
        return balanced

    # --- Synthetic Data Generators (for testing without real datasets) ---

    def _synthetic_phishing(self) -> list[dict]:
        """Generate synthetic phishing email samples for testing."""
        phishing_samples = [
            {"subject": "URGENT: Your account has been compromised!", "sender": "security@paypa1.com",
             "body": "Dear Customer, We detected unusual activity on your account. Click here immediately to verify your identity: http://paypa1-secure.tk/verify. Failure to act within 24 hours will result in permanent account suspension. PayPal Security Team"},
            {"subject": "You've won $1,000,000!", "sender": "lottery@winner-notify.xyz",
             "body": "Congratulations! You have been selected as the winner of our international lottery. To claim your prize, send your full name, address, bank details, and a processing fee of $50 to: claims@winner-notify.xyz"},
            {"subject": "Invoice #INV-2024-0892 Payment Required", "sender": "accounting@micros0ft-billing.com",
             "body": "Please find attached your invoice for $4,299.00. Payment is due within 48 hours to avoid service interruption. Click the link below to make payment: http://micros0ft-billing.com/pay/INV-2024-0892"},
            {"subject": "Reset your password now", "sender": "noreply@arnazon-security.com",
             "body": "We noticed a login attempt from an unrecognized device. For your protection, please reset your password immediately using the secure link below. This link expires in 1 hour. http://arnazon-security.com/reset?token=x8f92k"},
            {"subject": "Shared document: Q4 Financial Report", "sender": "ceo@company-docs.net",
             "body": "Hi, I've shared an important document with you. Please review the Q4 financial projections before tomorrow's board meeting. Click here to access: http://company-docs.net/share/q4report.exe"},
        ]

        benign_samples = [
            {"subject": "Team standup notes - March 15", "sender": "sarah.chen@company.com",
             "body": "Hi team, Here are the notes from today's standup. Backend: API migration 80% complete. Frontend: New dashboard deployed to staging. QA: Regression suite passing. Next standup: Wednesday 9am."},
            {"subject": "Your Amazon order has shipped", "sender": "ship-confirm@amazon.com",
             "body": "Your order #112-4567890-1234567 has shipped. Estimated delivery: March 18-20. Track your package at amazon.com/orders. Items: Wireless Mouse, USB-C Hub."},
            {"subject": "Weekly newsletter: Tech Updates", "sender": "newsletter@techcrunch.com",
             "body": "This week in tech: AI advances in healthcare, new chip designs from NVIDIA, and the future of remote work. Read more at techcrunch.com/weekly."},
            {"subject": "Meeting rescheduled to 3 PM", "sender": "john.smith@company.com",
             "body": "Hi, I need to push our 1:1 to 3 PM today. Same conference room. Let me know if that works. Thanks, John"},
            {"subject": "Your monthly bank statement is ready", "sender": "alerts@chase.com",
             "body": "Your March statement for account ending in 4567 is now available. Log in to chase.com to view your statement. If you have questions, call 1-800-935-9935."},
        ]

        samples = []
        for email in phishing_samples:
            from src.threats.phishing import PhishingPrompts
            text = PhishingPrompts.format_sample(email)
            samples.append({"text": text, "label": 1, "raw": email})

        for email in benign_samples:
            from src.threats.phishing import PhishingPrompts
            text = PhishingPrompts.format_sample(email)
            samples.append({"text": text, "label": 0, "raw": email})

        return samples

    def _synthetic_network(self) -> list[dict]:
        """Generate synthetic network connection samples."""
        attack_samples = [
            {"duration": 0, "protocol_type": "tcp", "service": "http", "flag": "S0",
             "src_bytes": 0, "dst_bytes": 0, "count": 511, "srv_count": 511,
             "serror_rate": 1.0, "same_srv_rate": 1.0, "dst_host_count": 255,
             "dst_host_serror_rate": 1.0, "attack_type": "neptune (SYN flood DoS)"},
            {"duration": 0, "protocol_type": "icmp", "service": "ecr_i", "flag": "SF",
             "src_bytes": 1032, "dst_bytes": 0, "count": 511, "srv_count": 511,
             "same_srv_rate": 1.0, "dst_host_count": 255, "dst_host_same_srv_rate": 1.0,
             "attack_type": "smurf (ICMP flood DoS)"},
            {"duration": 0, "protocol_type": "tcp", "service": "telnet", "flag": "S0",
             "src_bytes": 0, "dst_bytes": 0, "count": 2, "srv_count": 2,
             "num_failed_logins": 0, "serror_rate": 1.0, "dst_host_count": 1,
             "attack_type": "portsweep (probe)"},
            {"duration": 1, "protocol_type": "tcp", "service": "ftp", "flag": "SF",
             "src_bytes": 294, "dst_bytes": 4983, "num_failed_logins": 5,
             "logged_in": 1, "root_shell": 1, "count": 3, "srv_count": 3,
             "attack_type": "ftp_write (R2L)"},
            {"duration": 12, "protocol_type": "tcp", "service": "telnet", "flag": "SF",
             "src_bytes": 4521, "dst_bytes": 2890, "logged_in": 1, "root_shell": 1,
             "su_attempted": 1, "num_root": 5, "count": 1, "srv_count": 1,
             "attack_type": "rootkit (U2R)"},
        ]

        normal_samples = [
            {"duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF",
             "src_bytes": 232, "dst_bytes": 8153, "count": 5, "srv_count": 5,
             "serror_rate": 0.0, "same_srv_rate": 1.0, "dst_host_count": 30,
             "attack_type": "normal"},
            {"duration": 0, "protocol_type": "tcp", "service": "smtp", "flag": "SF",
             "src_bytes": 1684, "dst_bytes": 363, "count": 19, "srv_count": 19,
             "serror_rate": 0.0, "same_srv_rate": 1.0, "dst_host_count": 5,
             "attack_type": "normal"},
            {"duration": 5, "protocol_type": "tcp", "service": "ftp_data", "flag": "SF",
             "src_bytes": 0, "dst_bytes": 5110, "count": 1, "srv_count": 1,
             "serror_rate": 0.0, "same_srv_rate": 1.0, "logged_in": 1,
             "attack_type": "normal"},
            {"duration": 0, "protocol_type": "udp", "service": "domain_u", "flag": "SF",
             "src_bytes": 42, "dst_bytes": 121, "count": 10, "srv_count": 10,
             "serror_rate": 0.0, "same_srv_rate": 1.0, "dst_host_count": 50,
             "attack_type": "normal"},
            {"duration": 2, "protocol_type": "tcp", "service": "ssh", "flag": "SF",
             "src_bytes": 2048, "dst_bytes": 3072, "count": 1, "srv_count": 1,
             "serror_rate": 0.0, "same_srv_rate": 1.0, "logged_in": 1,
             "attack_type": "normal"},
        ]

        samples = []
        from src.threats.network_intrusion import NetworkIntrusionPrompts
        for record in attack_samples:
            text = NetworkIntrusionPrompts.format_sample(record)
            samples.append({"text": text, "label": 1, "raw": record})
        for record in normal_samples:
            text = NetworkIntrusionPrompts.format_sample(record)
            samples.append({"text": text, "label": 0, "raw": record})

        return samples

    def _synthetic_malware(self) -> list[dict]:
        """Generate synthetic PE malware feature samples."""
        malware_samples = [
            {"SizeOfCode": 512, "SizeOfInitializedData": 1024, "AddressOfEntryPoint": 4096,
             "NumberOfSections": 1, "SectionsMaxEntropy": 7.98, "SectionsMeanEntropy": 7.98,
             "NumberOfImports": 3, "SizeOfImage": 65536, "DllCharacteristics": 0,
             "ResourcesMaxEntropy": 7.95, "Characteristics": 258},
            {"SizeOfCode": 2048, "SizeOfInitializedData": 512, "AddressOfEntryPoint": 8192,
             "NumberOfSections": 7, "SectionsMaxEntropy": 7.85, "SectionsMeanEntropy": 6.9,
             "NumberOfImports": 145, "SizeOfImage": 131072, "DllCharacteristics": 0,
             "ResourcesMaxEntropy": 7.91, "Characteristics": 258},
            {"SizeOfCode": 256, "SizeOfInitializedData": 45056, "AddressOfEntryPoint": 512,
             "NumberOfSections": 2, "SectionsMaxEntropy": 7.99, "SectionsMeanEntropy": 7.5,
             "NumberOfImports": 5, "SizeOfImage": 49152, "DllCharacteristics": 0,
             "ResourcesMaxEntropy": 7.88, "Characteristics": 770},
            {"SizeOfCode": 4096, "SizeOfInitializedData": 2048, "AddressOfEntryPoint": 16384,
             "NumberOfSections": 9, "SectionsMaxEntropy": 7.92, "SectionsMeanEntropy": 7.1,
             "NumberOfImports": 8, "SizeOfImage": 262144, "DllCharacteristics": 0,
             "ResourcesMaxEntropy": 6.8, "Characteristics": 258},
            {"SizeOfCode": 1024, "SizeOfInitializedData": 0, "AddressOfEntryPoint": 1024,
             "NumberOfSections": 1, "SectionsMaxEntropy": 7.97, "SectionsMeanEntropy": 7.97,
             "NumberOfImports": 2, "SizeOfImage": 8192, "DllCharacteristics": 0,
             "ResourcesMaxEntropy": 0, "Characteristics": 258},
        ]

        benign_samples = [
            {"SizeOfCode": 151552, "SizeOfInitializedData": 57344, "AddressOfEntryPoint": 100944,
             "NumberOfSections": 5, "SectionsMaxEntropy": 6.42, "SectionsMeanEntropy": 4.85,
             "NumberOfImports": 72, "SizeOfImage": 245760, "DllCharacteristics": 33120,
             "ResourcesMaxEntropy": 3.41, "Characteristics": 258},
            {"SizeOfCode": 524288, "SizeOfInitializedData": 196608, "AddressOfEntryPoint": 321456,
             "NumberOfSections": 4, "SectionsMaxEntropy": 6.18, "SectionsMeanEntropy": 5.12,
             "NumberOfImports": 156, "SizeOfImage": 786432, "DllCharacteristics": 33120,
             "ResourcesMaxEntropy": 4.52, "Characteristics": 34},
            {"SizeOfCode": 65536, "SizeOfInitializedData": 32768, "AddressOfEntryPoint": 45012,
             "NumberOfSections": 4, "SectionsMaxEntropy": 5.89, "SectionsMeanEntropy": 4.56,
             "NumberOfImports": 43, "SizeOfImage": 131072, "DllCharacteristics": 33120,
             "ResourcesMaxEntropy": 2.89, "Characteristics": 258},
            {"SizeOfCode": 2097152, "SizeOfInitializedData": 524288, "AddressOfEntryPoint": 1048576,
             "NumberOfSections": 6, "SectionsMaxEntropy": 6.55, "SectionsMeanEntropy": 5.34,
             "NumberOfImports": 234, "SizeOfImage": 3145728, "DllCharacteristics": 33120,
             "ResourcesMaxEntropy": 5.12, "Characteristics": 34},
            {"SizeOfCode": 32768, "SizeOfInitializedData": 16384, "AddressOfEntryPoint": 20480,
             "NumberOfSections": 3, "SectionsMaxEntropy": 6.01, "SectionsMeanEntropy": 4.78,
             "NumberOfImports": 28, "SizeOfImage": 65536, "DllCharacteristics": 33120,
             "ResourcesMaxEntropy": 3.67, "Characteristics": 258},
        ]

        samples = []
        from src.threats.malware import MalwarePrompts
        for feat in malware_samples:
            text = MalwarePrompts.format_sample(feat)
            samples.append({"text": text, "label": 1, "raw": feat})
        for feat in benign_samples:
            text = MalwarePrompts.format_sample(feat)
            samples.append({"text": text, "label": 0, "raw": feat})

        return samples

    def _synthetic_logs(self) -> list[dict]:
        """Generate synthetic insider threat log samples."""
        threat_samples = [
            {"timestamp": "2024-03-15 02:34:00", "user": "john.doe", "action": "file_download",
             "resource": "/sensitive/customer_database_full.sql", "source_ip": "10.0.5.23",
             "bytes_transferred": 524288000, "status": "success", "role": "junior_analyst",
             "department": "marketing", "notes": "Employee submitted resignation last week"},
            {"timestamp": "2024-03-15 23:45:00", "user": "admin_temp", "action": "privilege_escalation",
             "resource": "/etc/shadow", "source_ip": "192.168.1.105", "status": "success",
             "role": "contractor", "num_failed_logins": 12, "session_duration": 180,
             "notes": "Contract ending this month"},
            {"timestamp": "2024-03-16 03:12:00", "user": "sarah.smith", "action": "bulk_email_forward",
             "resource": "confidential_project_docs/*", "source_ip": "10.0.3.45",
             "file_count": 47, "bytes_transferred": 89000000, "status": "success",
             "role": "engineer", "department": "R&D",
             "notes": "Forwarded to personal gmail account"},
            {"timestamp": "2024-03-16 01:00:00", "user": "mike.jones", "action": "usb_copy",
             "resource": "/projects/proprietary_algorithm/", "source_ip": "10.0.2.78",
             "bytes_transferred": 2147483648, "status": "success", "role": "senior_developer",
             "department": "engineering", "notes": "USB device connected at 1 AM"},
            {"timestamp": "2024-03-15 14:30:00", "user": "lisa.wang", "action": "unauthorized_access",
             "resource": "/hr/salary_data/executive_compensation.xlsx", "source_ip": "10.0.1.12",
             "status": "success", "role": "intern", "department": "IT",
             "notes": "Accessed files outside job scope"},
        ]

        benign_samples = [
            {"timestamp": "2024-03-15 09:15:00", "user": "alice.johnson", "action": "login",
             "resource": "workstation-042", "source_ip": "10.0.4.15", "status": "success",
             "role": "analyst", "department": "finance", "notes": "Regular morning login"},
            {"timestamp": "2024-03-15 10:30:00", "user": "bob.williams", "action": "file_access",
             "resource": "/shared/quarterly_report_q1.xlsx", "source_ip": "10.0.3.22",
             "bytes_transferred": 245000, "status": "success", "role": "manager",
             "department": "finance", "notes": "Preparing for quarterly review"},
            {"timestamp": "2024-03-15 14:00:00", "user": "admin_ops", "action": "system_backup",
             "resource": "/backup/daily/", "source_ip": "10.0.0.5",
             "bytes_transferred": 10737418240, "status": "success", "role": "sysadmin",
             "department": "IT", "notes": "Scheduled daily backup"},
            {"timestamp": "2024-03-15 11:45:00", "user": "carol.davis", "action": "file_upload",
             "resource": "/shared/team_presentation.pptx", "source_ip": "10.0.2.33",
             "bytes_transferred": 5242880, "status": "success", "role": "designer",
             "department": "marketing", "notes": "Uploading to shared drive"},
            {"timestamp": "2024-03-15 16:30:00", "user": "david.lee", "action": "logout",
             "resource": "workstation-078", "source_ip": "10.0.4.89", "status": "success",
             "role": "developer", "department": "engineering",
             "session_duration": 28800, "notes": "End of work day"},
        ]

        samples = []
        from src.threats.log_analysis import LogAnalysisPrompts
        for log in threat_samples:
            text = LogAnalysisPrompts.format_sample(log)
            samples.append({"text": text, "label": 1, "raw": log})
        for log in benign_samples:
            text = LogAnalysisPrompts.format_sample(log)
            samples.append({"text": text, "label": 0, "raw": log})

        return samples
