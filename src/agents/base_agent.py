"""
Base Threat Detection Agent (Level 0 - No Reflection)
Single-pass analysis: receives a threat sample and returns a verdict.
"""

import json
import logging
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel, Field
from typing import Optional

from src.config import get_llm

logger = logging.getLogger(__name__)


class ThreatVerdict(BaseModel):
    """Structured output for threat detection."""
    verdict: str = Field(description="Either 'malicious' or 'benign'")
    confidence: float = Field(description="Confidence score between 0.0 and 1.0")
    reasoning: str = Field(description="Step-by-step reasoning for the verdict")
    indicators: list[str] = Field(description="Key indicators that influenced the decision")
    threat_type: Optional[str] = Field(
        default=None,
        description="Specific threat category if malicious (e.g., 'spear_phishing', 'ddos', 'trojan', 'privilege_escalation')"
    )


class ThreatDetectionAgent:
    """
    Level 0 baseline agent — single-pass threat detection with no reflection.

    Takes a threat sample and domain-specific system prompt, returns a structured verdict.
    """

    def __init__(self, domain_prompts=None, llm=None):
        self.llm = llm or get_llm()
        self.parser = JsonOutputParser(pydantic_object=ThreatVerdict)
        self.domain_prompts = domain_prompts

    def _build_chain(self, system_prompt: str):
        prompt = ChatPromptTemplate.from_messages([
            ("human", f"""{system_prompt}

Analyze the following threat sample and provide your assessment.

THREAT SAMPLE:
{{sample}}

You MUST respond with a valid JSON object with these exact fields:
{{{{
  "verdict": "malicious" or "benign",
  "confidence": a float between 0.0 and 1.0,
  "reasoning": "your step-by-step analysis",
  "indicators": ["list", "of", "key", "indicators"],
  "threat_type": "specific threat category if malicious, or null if benign"
}}}}

Respond ONLY with the JSON object, no other text.""")
        ])
        return prompt | self.llm

    def analyze(self, sample: str, system_prompt: str = None) -> dict:
        """
        Analyze a single threat sample.

        Args:
            sample: The threat sample text/data to analyze
            system_prompt: Domain-specific system prompt (uses default if not provided)

        Returns:
            dict with verdict, confidence, reasoning, indicators, threat_type
        """
        if system_prompt is None and self.domain_prompts:
            system_prompt = self.domain_prompts.get_detection_prompt()
        elif system_prompt is None:
            system_prompt = self._default_system_prompt()

        chain = self._build_chain(system_prompt)
        response = chain.invoke({"sample": sample})

        # Parse the response
        try:
            content = response.content
            # Try to extract JSON from the response
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            result = json.loads(content.strip())

            # Validate and normalize
            result["verdict"] = str(result.get("verdict", "benign")).lower().strip()
            if result["verdict"] not in ("malicious", "benign"):
                logger.warning(f"Invalid verdict '{result['verdict']}', defaulting to benign")
                result["verdict"] = "benign"

            result["confidence"] = max(0.0, min(1.0, float(result.get("confidence", 0.0))))

            if not isinstance(result.get("indicators"), list):
                result["indicators"] = []

            if not isinstance(result.get("reasoning"), str):
                result["reasoning"] = str(result.get("reasoning", ""))

        except (json.JSONDecodeError, IndexError, ValueError) as e:
            logger.warning(f"Failed to parse detection response: {e}. Raw: {response.content[:300]}")
            result = {
                "verdict": "benign",
                "confidence": 0.0,
                "reasoning": f"Failed to parse response: {response.content[:200]}",
                "indicators": [],
                "threat_type": None,
            }

        return result

    def _default_system_prompt(self) -> str:
        return """You are an expert cybersecurity threat analyst. Your job is to analyze
potential security threats with high accuracy. Consider all possible indicators
of compromise and analyze the sample thoroughly before making a determination.
Be precise and methodical in your analysis."""
