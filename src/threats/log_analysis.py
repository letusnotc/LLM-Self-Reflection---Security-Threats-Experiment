"""
Log-Based Insider Threat Detection — Domain-specific prompts and preprocessing.
"""


class LogAnalysisPrompts:
    """Prompts tailored for detecting insider threats from system/auth logs."""

    DOMAIN = "log_analysis"
    DESCRIPTION = "Log-Based Insider Threat Detection"

    @staticmethod
    def get_detection_prompt() -> str:
        return """You are an insider threat detection analyst examining a window of consecutive
log events from a single employee in an enterprise environment.

You will see a sequence of events (typically 5-7) showing what the employee did over
a period of time. Analyze the PATTERN of activity across the window.

Each event may contain these fields:
- date: Timestamp of the event.
- source_type: Which log system generated it (logon, device, file, email, http).
- activity: What happened (Logon, Logoff, Connect, Disconnect, etc.).
- resource: Which workstation was used.
- filename: File accessed (if applicable).
- url: Website visited (if applicable).
- to/from: Email recipients/sender (if applicable).
- bytes_transferred: Amount of data involved (if applicable).
- attachments: Email attachment info (if applicable).

Look at the SEQUENCE of actions — what did this employee do, in what order, and does
the pattern look like normal work activity or does it raise security concerns?

Classify the activity window as "malicious" (insider threat) or "benign" (normal activity)."""

    @staticmethod
    def get_critic_context() -> str:
        return """When reviewing insider threat log analysis, consider:
- Is the analyst looking at the full SEQUENCE of events, or fixating on one event?
- Could this pattern of activity have a legitimate business explanation?
- Did the analyst overlook transitions between events that might change their assessment?
- Consider the combination of event types, timing, and resources accessed across the window."""

    @staticmethod
    def format_sample(log_data: dict) -> str:
        """Format log entry data into readable text."""
        lines = ["Enterprise Log Event:"]

        if isinstance(log_data, dict):
            priority_fields = [
                ("source_type", "Log Source"),
                ("activity", "Activity"),
                ("action", "Action"),
                ("date", "Timestamp"),
                ("user", "Employee ID"),
                ("resource", "Workstation"),
            ]

            for field, display in priority_fields:
                if field in log_data:
                    val = log_data[field]
                    if str(val) not in ("nan", "NaN", "None", ""):
                        lines.append(f"  {display}: {val}")

            context_fields = [
                ("filename", "File Accessed"),
                ("url", "URL Visited"),
                ("to", "Email To"),
                ("from", "Email From"),
                ("bytes_transferred", "Bytes Transferred"),
                ("size", "Size"),
                ("attachments", "Attachments"),
                ("content", "Content/Keywords"),
            ]

            for field, display in context_fields:
                if field in log_data:
                    val = log_data[field]
                    if str(val) not in ("nan", "NaN", "None", ""):
                        val_str = str(val)[:500]
                        lines.append(f"  {display}: {val_str}")

            shown = {f for f, _ in priority_fields + context_fields}
            shown.update({"label", "class", "threat", "id", "insider_threat"})
            for key, val in log_data.items():
                if key not in shown and str(val) not in ("nan", "NaN", "None", ""):
                    lines.append(f"  {key}: {val}")
        else:
            lines.append(f"  {log_data}")

        return "\n".join(lines)
