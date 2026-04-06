"""
Critic Agent — Reviews and challenges the detection agent's analysis.
Identifies potential errors, biases, and overlooked indicators.
"""

import json
import logging
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field

from src.config import get_llm

logger = logging.getLogger(__name__)


class CriticReview(BaseModel):
    """Structured output for the critic's review."""
    agree: bool = Field(description="Whether the critic agrees with the original verdict")
    errors_found: list[str] = Field(description="List of errors or issues found in the analysis")
    overlooked_indicators: list[str] = Field(description="Indicators the detection agent may have missed")
    suggestions: str = Field(description="Specific suggestions for improving the analysis")
    revised_verdict: str = Field(description="'malicious' or 'benign' — the critic's own assessment")
    revised_confidence: float = Field(description="Critic's confidence in their revised verdict (0.0-1.0)")


CRITIC_SYSTEM_PROMPT = """You are a senior cybersecurity review analyst. Your role is to critically
evaluate threat assessments made by another analyst. You must:

1. VERIFY the verdict matches the evidence — does the reasoning support the conclusion?
2. CHECK for false positives — was something benign incorrectly flagged as a threat?
3. CHECK for false negatives — was a real threat missed or downplayed as benign?
4. IDENTIFY overlooked indicators — only ones actually present in the sample
5. EVALUATE the reasoning chain for logical errors or gaps
6. CONSIDER alternative explanations for the observed indicators

CRITICAL GUIDELINES:
- Be BALANCED. A false positive is equally as bad as a false negative.
- Apply the SAME level of scrutiny to "malicious" and "benign" verdicts.
  If the analyst says "malicious", check if the evidence truly supports it.
  If the analyst says "benign", check if they missed genuine threat indicators.
- Only set "agree" to false if you found a genuine error or concrete evidence for a different verdict.
- Base your review only on what's actually present in the sample."""


class CriticAgent:
    """
    Reviews the detection agent's verdict and reasoning.
    Outputs agreement/disagreement with detailed feedback.
    """

    def __init__(self, llm=None):
        self.llm = llm or get_llm()

    def review(self, sample: str, detection_result: dict, domain_context: str = "") -> dict:
        """
        Review a detection agent's analysis.

        Args:
            sample: The original threat sample
            detection_result: The detection agent's output (verdict, reasoning, etc.)
            domain_context: Additional domain-specific context

        Returns:
            dict with agree, errors_found, overlooked_indicators, suggestions,
            revised_verdict, revised_confidence
        """
        # Build domain context section
        domain_section = ""
        if domain_context:
            domain_section = f"\nDOMAIN-SPECIFIC REVIEW GUIDANCE:\n{domain_context}\n"

        prompt = ChatPromptTemplate.from_messages([
            ("human", f"""{CRITIC_SYSTEM_PROMPT}
{domain_section}
ORIGINAL THREAT SAMPLE:
{{sample}}

DETECTION AGENT'S ANALYSIS:
- Verdict: {{verdict}}
- Confidence: {{confidence}}
- Reasoning: {{reasoning}}
- Indicators Found: {{indicators}}
- Threat Type: {{threat_type}}

Critically review this analysis. Look for errors, missed indicators, false positive/negative risks,
and logical gaps.

You MUST respond with a valid JSON object with these exact fields:
{{{{
  "agree": true or false,
  "errors_found": ["list", "of", "specific", "errors"],
  "overlooked_indicators": ["indicators", "the", "analyst", "missed"],
  "suggestions": "specific suggestions for improvement",
  "revised_verdict": "malicious" or "benign",
  "revised_confidence": float between 0.0 and 1.0
}}}}

Respond ONLY with the JSON object, no other text.""")
        ])

        chain = prompt | self.llm

        response = chain.invoke({
            "sample": sample,
            "verdict": detection_result.get("verdict", "unknown"),
            "confidence": detection_result.get("confidence", 0.0),
            "reasoning": detection_result.get("reasoning", "No reasoning provided"),
            "indicators": ", ".join(detection_result.get("indicators", [])) or "None listed",
            "threat_type": detection_result.get("threat_type", "None"),
        })

        try:
            content = response.content
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            result = json.loads(content.strip())

            # Validate and normalize fields
            result["agree"] = bool(result.get("agree", True))

            if not isinstance(result.get("errors_found"), list):
                result["errors_found"] = []
            if not isinstance(result.get("overlooked_indicators"), list):
                result["overlooked_indicators"] = []
            if not isinstance(result.get("suggestions"), str):
                result["suggestions"] = str(result.get("suggestions", ""))

            result["revised_verdict"] = str(result.get("revised_verdict", "benign")).lower().strip()
            if result["revised_verdict"] not in ("malicious", "benign"):
                result["revised_verdict"] = detection_result.get("verdict", "benign")

            result["revised_confidence"] = max(0.0, min(1.0, float(result.get("revised_confidence", 0.5))))

        except (json.JSONDecodeError, IndexError, ValueError) as e:
            logger.warning(f"Failed to parse critic response: {e}. Raw: {response.content[:300]}")
            result = {
                "agree": True,
                "errors_found": [],
                "overlooked_indicators": [],
                "suggestions": f"Failed to parse critic response",
                "revised_verdict": detection_result.get("verdict", "benign"),
                "revised_confidence": detection_result.get("confidence", 0.0),
            }

        return result
