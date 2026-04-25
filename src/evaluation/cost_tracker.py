"""
Cost Tracker — Tracks token usage, API calls, and latency per analysis.
"""

import time
from dataclasses import dataclass, field
from typing import Optional
from langchain_core.callbacks import BaseCallbackHandler


@dataclass
class AnalysisCost:
    """Cost data for a single threat analysis."""
    domain: str = ""
    level: int = 0
    sample_index: int = 0
    total_tokens: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    api_calls: int = 0
    wall_time_seconds: float = 0.0
    num_reflection_rounds: int = 0


class CostTracker:
    """
    Tracks cumulative cost metrics across experiments.
    """

    def __init__(self):
        self.records: list[AnalysisCost] = []
        self._current: Optional[AnalysisCost] = None
        self._start_time: float = 0.0

    def start(self, domain: str, level: int, sample_index: int):
        """Start tracking a new analysis."""
        self._current = AnalysisCost(
            domain=domain,
            level=level,
            sample_index=sample_index,
        )
        self._start_time = time.time()

    def record_api_call(self, prompt_tokens: int = 0, completion_tokens: int = 0):
        """Record an API call with token counts."""
        if self._current:
            self._current.api_calls += 1
            self._current.prompt_tokens += prompt_tokens
            self._current.completion_tokens += completion_tokens
            self._current.total_tokens += prompt_tokens + completion_tokens

    def finish(self, num_rounds: int = 0) -> AnalysisCost:
        """Finish tracking and return the cost record."""
        if self._current:
            self._current.wall_time_seconds = time.time() - self._start_time
            self._current.num_reflection_rounds = num_rounds
            record = self._current
            self.records.append(record)
            self._current = None
            return record
        return AnalysisCost()

    def get_summary(self) -> dict:
        """Get aggregate cost statistics."""
        if not self.records:
            return {}

        import pandas as pd
        df = pd.DataFrame([vars(r) for r in self.records])

        summary = {}
        for level in sorted(df["level"].unique()):
            level_df = df[df["level"] == level]
            summary[f"level_{level}"] = {
                "total_api_calls": int(level_df["api_calls"].sum()),
                "total_tokens": int(level_df["total_tokens"].sum()),
                "avg_tokens_per_sample": float(level_df["total_tokens"].mean()),
                "avg_api_calls_per_sample": float(level_df["api_calls"].mean()),
                "avg_wall_time_seconds": float(level_df["wall_time_seconds"].mean()),
                "total_wall_time_seconds": float(level_df["wall_time_seconds"].sum()),
                "num_samples": len(level_df),
            }

        return summary

    def get_domain_summary(self) -> dict:
        """Get cost stats grouped by domain and level."""
        if not self.records:
            return {}

        import pandas as pd
        df = pd.DataFrame([vars(r) for r in self.records])

        summary = {}
        for domain in sorted(df["domain"].unique()):
            summary[domain] = {}
            domain_df = df[df["domain"] == domain]
            for level in sorted(domain_df["level"].unique()):
                level_df = domain_df[domain_df["level"] == level]
                summary[domain][f"level_{level}"] = {
                    "avg_tokens": float(level_df["total_tokens"].mean()),
                    "avg_api_calls": float(level_df["api_calls"].mean()),
                    "avg_wall_time": float(level_df["wall_time_seconds"].mean()),
                    "num_samples": len(level_df),
                }

        return summary

    def to_dataframe(self):
        """Convert records to a pandas DataFrame."""
        import pandas as pd
        return pd.DataFrame([vars(r) for r in self.records])


class TokenCountingCallback(BaseCallbackHandler):
    """LangChain callback handler for counting tokens."""

    def __init__(self, cost_tracker: CostTracker):
        self.cost_tracker = cost_tracker

    def on_llm_end(self, response, **kwargs):
        """Record token usage when an LLM call completes."""
        usage = {}

        # Try standard llm_output first (Google, OpenAI)
        if hasattr(response, "llm_output") and response.llm_output:
            usage = response.llm_output.get("token_usage", {})

        # Fallback: Ollama reports usage in generation_info
        if not usage and hasattr(response, "generations") and response.generations:
            for gen_list in response.generations:
                for gen in gen_list:
                    info = getattr(gen, "generation_info", {}) or {}
                    if "prompt_eval_count" in info or "eval_count" in info:
                        usage = {
                            "prompt_tokens": info.get("prompt_eval_count", 0),
                            "completion_tokens": info.get("eval_count", 0),
                        }
                        break

        self.cost_tracker.record_api_call(
            prompt_tokens=usage.get("prompt_tokens", 0),
            completion_tokens=usage.get("completion_tokens", 0),
        )
