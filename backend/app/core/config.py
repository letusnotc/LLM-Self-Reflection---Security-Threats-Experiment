import os
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "")
L0_MODEL: str = os.getenv("L0_MODEL", "gemini-2.5-flash-lite")
L1_MODEL: str = os.getenv("L1_MODEL", "gemini-2.5-flash")
L2_MODEL: str = os.getenv("L2_MODEL", "gemini-2.5-flash")

# USD per 1M tokens (Standard tier, text)
PRICING: dict[str, dict[str, float]] = {
    "gemini-2.0-flash-lite":  {"input": 0.075 / 1_000_000, "output": 0.30  / 1_000_000},
    "gemini-2.0-flash":       {"input": 0.10  / 1_000_000, "output": 0.40  / 1_000_000},
    "gemini-2.5-flash-lite":  {"input": 0.10  / 1_000_000, "output": 0.40  / 1_000_000},
    "gemini-2.5-flash":       {"input": 0.30  / 1_000_000, "output": 2.50  / 1_000_000},
    # OpenRouter free models — $0 cost
    "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free":  {"input": 0.0, "output": 0.0},
    "nvidia/nemotron-3-super-120b-a12b:free":              {"input": 0.0, "output": 0.0},
    "google/gemma-4-31b-it:free":                          {"input": 0.0, "output": 0.0},
}

def token_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    p = PRICING.get(model, PRICING["gemini-2.5-flash"])
    return input_tokens * p["input"] + output_tokens * p["output"]
