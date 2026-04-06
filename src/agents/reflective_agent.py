"""
Reflective Agent — Orchestrates self-reflection loops at different levels.

Level 0: No reflection (delegates to base agent directly)
Level 1: Single reflection (detect -> critic -> revise)
Level 2: Iterative reflection (detect <-> critic loop, max N rounds)
"""

import json
import time
import logging
from langchain_core.prompts import ChatPromptTemplate

from src.config import get_llm, MAX_REFLECTION_ROUNDS, CONSENSUS_THRESHOLD
from src.agents.base_agent import ThreatDetectionAgent
from src.agents.critic_agent import CriticAgent

logger = logging.getLogger(__name__)


class ReflectiveAgent:
    """
    Orchestrates threat detection with configurable reflection depth.
    Tracks all intermediate states for analysis.
    """

    def __init__(self, domain_prompts=None, llm=None,
                 consensus_threshold=None, max_rounds=None):
        self.llm = llm or get_llm()
        self.detector = ThreatDetectionAgent(domain_prompts=domain_prompts, llm=self.llm)
        self.critic = CriticAgent(llm=self.llm)
        self.domain_prompts = domain_prompts
        self.consensus_threshold = consensus_threshold or CONSENSUS_THRESHOLD
        self.max_rounds = max_rounds or MAX_REFLECTION_ROUNDS

        # Cache domain context — no need to re-fetch per sample (#10)
        self._domain_context_cache = None

    def _get_domain_context(self) -> str:
        """Get and cache domain-specific critic context."""
        if self._domain_context_cache is None:
            if self.domain_prompts:
                self._domain_context_cache = self.domain_prompts.get_critic_context()
            else:
                self._domain_context_cache = ""
        return self._domain_context_cache

    def _timed_call(self, fn, *args, **kwargs):
        """Wrap a function call with timing (#11)."""
        t = time.time()
        result = fn(*args, **kwargs)
        return result, round(time.time() - t, 3)

    def _is_consensus(self, detection: dict, critique: dict) -> bool:
        """Check for true consensus — verdicts must match + both confident (#8)."""
        critic_agrees = critique.get("agree", False)
        verdicts_match = (
            str(detection.get("verdict", "")).lower().strip()
            == str(critique.get("revised_verdict", "")).lower().strip()
        )
        both_confident = (
            critique.get("revised_confidence", 0.0) >= self.consensus_threshold
            and detection.get("confidence", 0.0) >= self.consensus_threshold
        )
        return critic_agrees and verdicts_match and both_confident

    def analyze(self, sample: str, level: int = 0, system_prompt: str = None) -> dict:
        """
        Analyze a threat sample with the specified reflection level.

        Args:
            sample: Threat sample to analyze
            level: Reflection level (0=none, 1=single, 2=iterative)
            system_prompt: Optional domain-specific prompt

        Returns:
            dict with final_verdict, all intermediate steps, and metadata
        """
        if level == 0:
            return self._level_0(sample, system_prompt)
        elif level == 1:
            return self._level_1(sample, system_prompt)
        elif level == 2:
            return self._level_2(sample, system_prompt)
        else:
            raise ValueError(f"Invalid reflection level: {level}. Must be 0, 1, or 2.")

    def _level_0(self, sample: str, system_prompt: str = None) -> dict:
        """Level 0: Single-pass detection, no reflection."""
        start_time = time.time()

        detection, t_detect = self._timed_call(self.detector.analyze, sample, system_prompt)

        return {
            "level": 0,
            "final_verdict": detection.get("verdict", "benign"),
            "final_confidence": detection.get("confidence", 0.0),
            "final_reasoning": detection.get("reasoning", ""),
            "steps": [
                {"step": "detection", "result": detection, "latency_s": t_detect}
            ],
            "num_rounds": 0,
            "total_llm_calls": 1,
            "total_time": time.time() - start_time,
        }

    def _level_1(self, sample: str, system_prompt: str = None) -> dict:
        """Level 1: Detect -> Critic reviews -> Agent revises (always, using feedback)."""
        start_time = time.time()
        steps = []
        llm_call_count = 0

        # Step 1: Initial detection
        detection, t_detect = self._timed_call(self.detector.analyze, sample, system_prompt)
        llm_call_count += 1
        steps.append({"step": "initial_detection", "result": detection, "latency_s": t_detect})

        # Step 2: Critic reviews with domain context
        domain_context = self._get_domain_context()
        critique, t_critic = self._timed_call(self.critic.review, sample, detection, domain_context)
        llm_call_count += 1
        steps.append({"step": "critic_review", "result": critique, "latency_s": t_critic})

        # Step 3: ALWAYS revise — track whether it was forced (#4)
        revised, t_revise = self._timed_call(
            self._revise_analysis, sample, detection, critique, system_prompt
        )
        llm_call_count += 1

        verdict_changed = (
            str(detection.get("verdict", "")).lower()
            != str(revised.get("verdict", "")).lower()
        )
        confidence_delta = revised.get("confidence", 0.0) - detection.get("confidence", 0.0)

        steps.append({
            "step": "revision",
            "result": revised,
            "latency_s": t_revise,
            "revision_was_forced": critique.get("agree", False),  # #4
            "verdict_changed": verdict_changed,  # #12
            "confidence_delta": round(confidence_delta, 4),  # #12
        })

        final = revised

        return {
            "level": 1,
            "final_verdict": final.get("verdict", "benign"),
            "final_confidence": final.get("confidence", 0.0),
            "final_reasoning": final.get("reasoning", ""),
            "steps": steps,
            "num_rounds": 1,
            "total_llm_calls": llm_call_count,  # #6
            "critic_agreed": critique.get("agree", True),
            "verdict_changed": verdict_changed,  # #12
            "total_time": time.time() - start_time,
        }

    def _level_2(self, sample: str, system_prompt: str = None) -> dict:
        """Level 2: Iterative reflection until consensus or max rounds."""
        start_time = time.time()
        steps = []
        llm_call_count = 0

        # Initial detection
        current_detection, t_detect = self._timed_call(
            self.detector.analyze, sample, system_prompt
        )
        llm_call_count += 1
        steps.append({
            "step": "initial_detection", "round": 0,
            "result": current_detection, "latency_s": t_detect,
        })

        domain_context = self._get_domain_context()
        initial_verdict = str(current_detection.get("verdict", "")).lower()

        consensus_reached = False
        rounds = 0

        for round_num in range(1, self.max_rounds + 1):
            rounds = round_num

            # Critic reviews current detection
            critique, t_critic = self._timed_call(
                self.critic.review, sample, current_detection, domain_context
            )
            llm_call_count += 1

            # Check for true consensus (#8) — log before breaking (#5)
            if self._is_consensus(current_detection, critique):
                steps.append({
                    "step": "critic_review", "round": round_num,
                    "result": critique, "latency_s": t_critic,
                    "consensus_triggered": True,  # #5
                })
                # Blend confidence on consensus (#9)
                blended_confidence = (
                    current_detection.get("confidence", 0.0)
                    + critique.get("revised_confidence", 0.0)
                ) / 2
                current_detection = {
                    **current_detection,
                    "confidence": round(blended_confidence, 4),
                }
                consensus_reached = True
                break

            steps.append({
                "step": "critic_review", "round": round_num,
                "result": critique, "latency_s": t_critic,
                "consensus_triggered": False,
            })

            # Revise based on critique
            prev_verdict = str(current_detection.get("verdict", "")).lower()
            revised, t_revise = self._timed_call(
                self._revise_analysis, sample, current_detection, critique, system_prompt
            )
            llm_call_count += 1

            verdict_changed = (
                prev_verdict != str(revised.get("verdict", "")).lower()
            )
            confidence_delta = revised.get("confidence", 0.0) - current_detection.get("confidence", 0.0)

            steps.append({
                "step": "revision", "round": round_num,
                "result": revised, "latency_s": t_revise,
                "verdict_changed": verdict_changed,  # #12
                "confidence_delta": round(confidence_delta, 4),  # #12
            })
            current_detection = revised

        final_verdict = str(current_detection.get("verdict", "benign")).lower()

        return {
            "level": 2,
            "final_verdict": final_verdict,
            "final_confidence": current_detection.get("confidence", 0.0),
            "final_reasoning": current_detection.get("reasoning", ""),
            "steps": steps,
            "num_rounds": rounds,
            "total_llm_calls": llm_call_count,  # #6
            "consensus_reached": consensus_reached,
            "verdict_changed_from_initial": final_verdict != initial_verdict,  # #12
            "total_time": time.time() - start_time,
        }

    def _revise_analysis(self, sample: str, detection: dict, critique: dict,
                         system_prompt: str = None) -> dict:
        """Revise the detection based on critic feedback, retaining domain expertise."""
        # Resolve domain-specific prompt
        if system_prompt is None and self.domain_prompts:
            system_prompt = self.domain_prompts.get_detection_prompt()
        elif system_prompt is None:
            system_prompt = "You are an expert cybersecurity threat analyst."

        # Normalize verdicts for comparison (#3)
        critic_agrees = critique.get("agree", True)
        reviewer_verdict = str(critique.get("revised_verdict", "unknown")).lower().strip()
        prev_verdict = str(detection.get("verdict", "unknown")).lower().strip()

        # Context-aware revision instructions
        if critic_agrees:
            revision_instruction = f"""The peer reviewer AGREED with your verdict of "{prev_verdict}".
They may have additional suggestions to refine your analysis.
Your task: Keep your verdict, but incorporate any valid additional indicators or
improve your reasoning based on the feedback. Adjust confidence if warranted."""
        elif reviewer_verdict == prev_verdict:
            revision_instruction = f"""The peer reviewer suggested improvements to your reasoning but
reached the same verdict of "{prev_verdict}".
Your task: Improve your reasoning and address the feedback points while keeping your verdict."""
        else:
            revision_instruction = f"""The peer reviewer DISAGREED with your verdict.
You said "{prev_verdict}", they say "{reviewer_verdict}".

IMPORTANT: Do NOT automatically adopt the reviewer's verdict. Instead:
1. First, list the concrete evidence from the ORIGINAL SAMPLE that supports YOUR verdict ("{prev_verdict}")
2. Then, list the concrete evidence the reviewer cited for their verdict ("{reviewer_verdict}")
3. Compare: which side has stronger evidence from the actual sample?
4. Only change your verdict if the reviewer pointed to specific evidence IN THE SAMPLE
   that you missed. Vague concerns or hypothetical scenarios are NOT sufficient to change.
5. If your original evidence is stronger, KEEP your verdict of "{prev_verdict}"."""

        revision_prompt = ChatPromptTemplate.from_messages([
            ("human", f"""{system_prompt}

You are REVISING your analysis based on peer review feedback.

ORIGINAL THREAT SAMPLE:
{{sample}}

PEER REVIEW FEEDBACK (consider but do not blindly follow):
- Reviewer Agrees: {{reviewer_agrees}}
- Errors Found: {{errors}}
- Overlooked Indicators: {{overlooked}}
- Suggestions: {{suggestions}}
- Reviewer's Verdict: {{reviewer_verdict}}
- Reviewer's Confidence: {{reviewer_confidence}}

YOUR PREVIOUS ANALYSIS (this is YOUR assessment — you own it):
- Verdict: {{prev_verdict}}
- Confidence: {{prev_confidence}}
- Reasoning: {{prev_reasoning}}
- Indicators: {{prev_indicators}}

{revision_instruction}

Respond ONLY with a valid JSON object:
{{{{
  "verdict": "malicious" or "benign",
  "confidence": float between 0.0 and 1.0,
  "reasoning": "your revised step-by-step analysis addressing the feedback",
  "indicators": ["updated", "list", "of", "key", "indicators"],
  "threat_type": "specific threat category if malicious, or null if benign"
}}}}""")
        ])

        chain = revision_prompt | self.llm

        response = chain.invoke({
            "sample": sample,
            "prev_verdict": prev_verdict,
            "prev_confidence": detection.get("confidence", 0.0),
            "prev_reasoning": detection.get("reasoning", ""),
            "prev_indicators": ", ".join(detection.get("indicators", [])),
            "reviewer_agrees": str(critic_agrees),
            "errors": "; ".join(critique.get("errors_found", [])) or "None identified",
            "overlooked": "; ".join(critique.get("overlooked_indicators", [])) or "None identified",
            "suggestions": critique.get("suggestions", "No specific suggestions"),
            "reviewer_verdict": reviewer_verdict,
            "reviewer_confidence": critique.get("revised_confidence", 0.0),
        })

        try:
            content = response.content
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            result = json.loads(content.strip())

            # Validate required fields (#1)
            required = ["verdict", "confidence", "reasoning", "indicators", "threat_type"]
            for field in required:
                if field not in result:
                    raise ValueError(f"Missing field: {field}")

            # Normalize verdict (#2, #3)
            result["verdict"] = str(result["verdict"]).lower().strip()
            if result["verdict"] not in ("malicious", "benign"):
                logger.warning(f"Invalid verdict '{result['verdict']}', falling back to original")
                return {**detection, "revision_failed": True}

            # Clamp confidence (#2)
            result["confidence"] = max(0.0, min(1.0, float(result["confidence"])))

            # Ensure indicators is a list
            if not isinstance(result.get("indicators"), list):
                result["indicators"] = detection.get("indicators", [])

            return result

        except (json.JSONDecodeError, ValueError, KeyError, IndexError) as e:
            logger.warning(f"Failed to parse revision response: {e}. Raw: {response.content[:300]}")
            return {**detection, "revision_failed": True}  # #1
