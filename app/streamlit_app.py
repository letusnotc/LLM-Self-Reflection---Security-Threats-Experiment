"""
Streamlit Interactive Demo — Self-Reflection in Threat Detection

Run with: streamlit run app/streamlit_app.py
"""

import sys
import os
import json
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

from src.config import get_llm
from src.agents.reflective_agent import ReflectiveAgent
from src.threats import THREAT_DOMAINS

# --- Page Config ---
st.set_page_config(
    page_title="Self-Reflection Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Custom CSS ---
st.markdown("""
<style>
    .verdict-malicious { color: #e74c3c; font-size: 28px; font-weight: bold; }
    .verdict-benign { color: #27ae60; font-size: 28px; font-weight: bold; }
    .step-card {
        background: #f8f9fa; border-radius: 10px; padding: 15px;
        margin: 10px 0; border-left: 4px solid #3498db;
    }
    .metric-card {
        background: #ffffff; border-radius: 8px; padding: 20px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center;
    }
</style>
""", unsafe_allow_html=True)


# --- Sample Data for Quick Testing ---
SAMPLE_THREATS = {
    "phishing": {
        "Phishing Email (Malicious)": """Subject: URGENT: Your account has been compromised!
From: security@paypa1.com

Dear Customer,
We detected unusual activity on your account. Click here immediately to verify your identity: http://paypa1-secure.tk/verify
Failure to act within 24 hours will result in permanent account suspension.
PayPal Security Team""",
        "Newsletter (Benign)": """Subject: Weekly Tech Newsletter - March Edition
From: newsletter@techcrunch.com

Hi Reader,
This week in tech: AI advances in healthcare, new chip designs from NVIDIA, and the future of remote work.
Read more at techcrunch.com/weekly
Unsubscribe: techcrunch.com/unsubscribe""",
    },
    "network_intrusion": {
        "SYN Flood Attack": """Network Connection Features:
  duration: 0, protocol_type: tcp, service: http, flag: S0
  src_bytes: 0, dst_bytes: 0, count: 511, srv_count: 511
  serror_rate: 1.0, same_srv_rate: 1.0
  dst_host_count: 255, dst_host_serror_rate: 1.0""",
        "Normal HTTP Traffic": """Network Connection Features:
  duration: 0, protocol_type: tcp, service: http, flag: SF
  src_bytes: 232, dst_bytes: 8153, count: 5, srv_count: 5
  serror_rate: 0.0, same_srv_rate: 1.0
  dst_host_count: 30, dst_host_serror_rate: 0.0""",
    },
}


def main():
    st.title("Self-Reflection in Agent-Based Threat Detection")
    st.markdown("*Fully local inference via Ollama (gemma4:e2b) — evaluating how self-reflection improves threat detection*")

    # --- Sidebar ---
    with st.sidebar:
        st.header("Configuration")

        domain = st.selectbox(
            "Threat Domain",
            list(THREAT_DOMAINS.keys()),
            format_func=lambda x: x.replace("_", " ").title()
        )

        level = st.radio(
            "Reflection Level",
            [0, 1, 2],
            format_func=lambda x: {
                0: "Level 0 — No Reflection",
                1: "Level 1 — Single Reflection",
                2: "Level 2 — Iterative Reflection"
            }[x]
        )

        st.divider()
        st.header("Quick Samples")
        sample_choice = st.selectbox(
            "Load a sample:",
            ["Custom Input"] + list(SAMPLE_THREATS.get(domain, {}).keys())
        )

        st.divider()
        compare_mode = st.checkbox("Compare All Levels", value=False)

        st.divider()
        st.markdown("### Architecture")
        if level == 0:
            st.markdown("```\nSample → Agent → Verdict\n```")
        elif level == 1:
            st.markdown("```\nSample → Agent → Critic\n                  ↓\n           Revised Verdict\n```")
        else:
            st.markdown("```\nSample → Agent ↔ Critic\n         (loop max 3x)\n              ↓\n       Final Verdict\n```")

    # --- Main Content ---
    if sample_choice != "Custom Input" and sample_choice in SAMPLE_THREATS.get(domain, {}):
        sample_text = SAMPLE_THREATS[domain][sample_choice]
    else:
        sample_text = ""

    sample_input = st.text_area(
        "Enter threat sample to analyze:",
        value=sample_text,
        height=200,
        placeholder="Paste an email, network log, file features, or system log here..."
    )

    if st.button("Analyze Threat", type="primary", use_container_width=True):
        if not sample_input.strip():
            st.error("Please enter a threat sample to analyze.")
            return

        if compare_mode:
            _run_comparison(sample_input, domain)
        else:
            _run_single_analysis(sample_input, domain, level)


def _run_single_analysis(sample: str, domain: str, level: int):
    """Run analysis at a single reflection level with step-by-step display."""
    prompt_class = THREAT_DOMAINS[domain]()
    agent = ReflectiveAgent(domain_prompts=prompt_class)

    with st.spinner(f"Analyzing with Level {level} reflection..."):
        start = time.time()
        result = agent.analyze(
            sample=sample,
            level=level,
            system_prompt=prompt_class.get_detection_prompt()
        )
        elapsed = time.time() - start

    # --- Verdict Display ---
    col1, col2, col3 = st.columns(3)
    with col1:
        verdict = result["final_verdict"]
        css_class = "verdict-malicious" if verdict.lower() == "malicious" else "verdict-benign"
        st.markdown(f'<p class="{css_class}">{"MALICIOUS" if verdict.lower() == "malicious" else "BENIGN"}</p>',
                    unsafe_allow_html=True)
    with col2:
        st.metric("Confidence", f"{result.get('final_confidence', 0):.1%}")
    with col3:
        st.metric("Analysis Time", f"{elapsed:.1f}s")

    # --- Reasoning ---
    st.subheader("Final Reasoning")
    st.info(result.get("final_reasoning", "No reasoning available"))

    # --- Reflection Steps ---
    if result.get("steps"):
        st.subheader("Reasoning Chain")
        for i, step in enumerate(result["steps"]):
            step_name = step["step"].replace("_", " ").title()
            with st.expander(f"Step {i+1}: {step_name}", expanded=(i == 0)):
                step_result = step.get("result", {})

                if "verdict" in step_result:
                    st.write(f"**Verdict:** {step_result['verdict']} "
                             f"(confidence: {step_result.get('confidence', 'N/A')})")
                if "reasoning" in step_result:
                    st.write(f"**Reasoning:** {step_result['reasoning']}")
                if "indicators" in step_result:
                    st.write(f"**Indicators:** {', '.join(step_result['indicators'])}")
                if "agree" in step_result:
                    st.write(f"**Agrees with detection:** {'Yes' if step_result['agree'] else 'No'}")
                if "errors_found" in step_result and step_result["errors_found"]:
                    st.write(f"**Errors found:** {'; '.join(step_result['errors_found'])}")
                if "suggestions" in step_result:
                    st.write(f"**Suggestions:** {step_result['suggestions']}")

    # --- Raw JSON ---
    with st.expander("Raw JSON Output"):
        st.json(result)


def _run_comparison(sample: str, domain: str):
    """Run analysis at all 3 levels and compare results side-by-side."""
    prompt_class = THREAT_DOMAINS[domain]()

    results = {}
    progress = st.progress(0)

    for i, level in enumerate([0, 1, 2]):
        with st.spinner(f"Running Level {level}..."):
            agent = ReflectiveAgent(domain_prompts=prompt_class)
            start = time.time()
            result = agent.analyze(
                sample=sample,
                level=level,
                system_prompt=prompt_class.get_detection_prompt()
            )
            result["elapsed"] = time.time() - start
            results[level] = result
        progress.progress((i + 1) / 3)

    progress.empty()

    # --- Side-by-side comparison ---
    st.subheader("Comparison Across Reflection Levels")

    cols = st.columns(3)
    level_names = {0: "No Reflection", 1: "Single Reflection", 2: "Iterative"}

    for col, level in zip(cols, [0, 1, 2]):
        r = results[level]
        with col:
            st.markdown(f"### Level {level}: {level_names[level]}")

            verdict = r["final_verdict"]
            color = "#e74c3c" if verdict.lower() == "malicious" else "#27ae60"
            st.markdown(f"**Verdict:** <span style='color:{color};font-weight:bold'>"
                        f"{verdict.upper()}</span>", unsafe_allow_html=True)

            st.metric("Confidence", f"{r.get('final_confidence', 0):.1%}")
            st.metric("Time", f"{r.get('elapsed', 0):.1f}s")
            st.metric("Steps", len(r.get("steps", [])))

            with st.expander("Reasoning"):
                st.write(r.get("final_reasoning", "N/A"))

    # --- Comparison Chart ---
    fig = go.Figure()
    confidences = [results[l].get("final_confidence", 0) for l in [0, 1, 2]]
    times = [results[l].get("elapsed", 0) for l in [0, 1, 2]]
    level_labels = [f"Level {l}" for l in [0, 1, 2]]

    fig.add_trace(go.Bar(name="Confidence", x=level_labels, y=confidences,
                         marker_color=["#e74c3c", "#f39c12", "#27ae60"]))
    fig.update_layout(title="Confidence Comparison", yaxis_title="Confidence",
                      yaxis_range=[0, 1.1])
    st.plotly_chart(fig, use_container_width=True)

    # Time comparison
    fig2 = go.Figure()
    fig2.add_trace(go.Bar(name="Analysis Time", x=level_labels, y=times,
                          marker_color=["#e74c3c", "#f39c12", "#27ae60"]))
    fig2.update_layout(title="Analysis Time Comparison", yaxis_title="Seconds")
    st.plotly_chart(fig2, use_container_width=True)


if __name__ == "__main__":
    main()
