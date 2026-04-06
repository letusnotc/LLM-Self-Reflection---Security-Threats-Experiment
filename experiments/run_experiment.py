"""
Experiment Runner — Systematically evaluates all domain x level combinations.

Usage:
    python -m experiments.run_experiment                    # Run all experiments
    python -m experiments.run_experiment --domain phishing  # Run one domain
    python -m experiments.run_experiment --level 0          # Run one level
    python -m experiments.run_experiment --samples 10       # Quick test run
"""

import os
import sys
import json
import argparse
import logging
import time
from datetime import datetime
from tqdm import tqdm

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import RESULTS_DIR, SAMPLES_PER_DOMAIN, get_llm
from src.agents.reflective_agent import ReflectiveAgent
from src.threats import THREAT_DOMAINS
from src.data.loader import DataLoader
from src.evaluation.metrics import compute_metrics, mcnemar_test
from src.evaluation.cost_tracker import CostTracker, TokenCountingCallback

logging.basicConfig(level=logging.WARNING, format="%(name)s — %(message)s")


def run_single_experiment(domain: str, level: int, samples: list,
                          cost_tracker: CostTracker) -> dict:
    """
    Run experiment for a single domain-level combination.

    Returns:
        dict with predictions, metrics, and cost data
    """
    prompt_class = THREAT_DOMAINS[domain]()

    # Wire up token counting callback so cost tracker records actual usage
    callback = TokenCountingCallback(cost_tracker)
    llm = get_llm(callbacks=[callback])
    agent = ReflectiveAgent(domain_prompts=prompt_class, llm=llm)

    y_true = []
    y_pred = []
    y_prob = []
    all_results = []

    desc = f"{domain} | Level {level}"
    for i, sample in enumerate(tqdm(samples, desc=desc)):
        cost_tracker.start(domain=domain, level=level, sample_index=i)

        result = None
        try:
            result = agent.analyze(
                sample=sample["text"],
                level=level,
                system_prompt=prompt_class.get_detection_prompt()
            )

            pred = 1 if result["final_verdict"].lower() == "malicious" else 0
            conf = result.get("final_confidence", 0.5)

            y_true.append(sample["label"])
            y_pred.append(pred)
            y_prob.append(conf if pred == 1 else 1 - conf)

            all_results.append({
                "sample_index": i,
                "true_label": sample["label"],
                "predicted": pred,
                "confidence": conf,
                "verdict": result["final_verdict"],
                "num_rounds": result.get("num_rounds", 0),
                "total_llm_calls": result.get("total_llm_calls", 1),
                "verdict_changed": result.get("verdict_changed", False),
                "consensus_reached": result.get("consensus_reached", None),
                "time": result.get("total_time", 0),
            })

        except Exception as e:
            print(f"\n  Error on sample {i}: {e}")
            y_true.append(sample["label"])
            y_pred.append(0)
            y_prob.append(0.5)
            all_results.append({
                "sample_index": i,
                "true_label": sample["label"],
                "predicted": 0,
                "confidence": 0.0,
                "error": str(e),
            })

        num_rounds = result.get("num_rounds", 0) if result else 0
        cost_tracker.finish(num_rounds=num_rounds)

        # Rate limiting — be kind to the API
        time.sleep(1)

    metrics = compute_metrics(y_true, y_pred, y_prob)

    return {
        "domain": domain,
        "level": level,
        "metrics": metrics,
        "predictions": all_results,
        "y_true": y_true,
        "y_pred": y_pred,
        "y_prob": y_prob,
    }


def run_all_experiments(domains: list = None, levels: list = None,
                        samples_per_domain: int = None) -> dict:
    """
    Run experiments across all specified domain-level combinations.
    """
    domains = domains or list(THREAT_DOMAINS.keys())
    levels = levels or [0, 1, 2]
    samples_per_domain = samples_per_domain or SAMPLES_PER_DOMAIN

    loader = DataLoader(samples_per_domain=samples_per_domain)
    cost_tracker = CostTracker()

    all_results = {}
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    print("=" * 60)
    print("EXPERIMENT: Self-Reflection in Threat Detection")
    print(f"Domains: {domains}")
    print(f"Levels: {levels}")
    print(f"Samples per domain: {samples_per_domain}")
    print(f"Timestamp: {timestamp}")
    print("=" * 60)

    for domain in domains:
        print(f"\n{'='*40}")
        print(f"DOMAIN: {domain}")
        print(f"{'='*40}")

        data = loader.load(domain)
        print(f"Loaded {len(data)} samples ({sum(1 for d in data if d['label']==1)} malicious, "
              f"{sum(1 for d in data if d['label']==0)} benign)")

        all_results[domain] = {}

        for level in levels:
            print(f"\n--- Level {level} ---")
            result = run_single_experiment(domain, level, data, cost_tracker)
            all_results[domain][level] = result

            # Print metrics
            m = result["metrics"]
            print(f"  Accuracy:  {m['accuracy']:.4f}")
            print(f"  Precision: {m['precision']:.4f}")
            print(f"  Recall:    {m['recall']:.4f}")
            print(f"  F1 Score:  {m['f1_score']:.4f}")
            print(f"  FPR:       {m['false_positive_rate']:.4f}")
            print(f"  FNR:       {m['false_negative_rate']:.4f}")

    # Statistical significance tests
    significance_results = {}
    for domain in domains:
        if 0 in all_results[domain] and 2 in all_results[domain]:
            test = mcnemar_test(
                all_results[domain][0]["y_true"],
                all_results[domain][0]["y_pred"],
                all_results[domain][2]["y_pred"],
            )
            significance_results[domain] = test

    # Cost summary
    cost_summary = cost_tracker.get_summary()

    # ============================================================
    # FINAL CONSOLIDATED RESULTS TABLE
    # ============================================================
    print(f"\n\n{'='*80}")
    print("                    FINAL RESULTS SUMMARY")
    print(f"{'='*80}")

    # Header
    header = f"{'Domain':<22} {'Level':<8} {'Accuracy':>9} {'Precision':>10} {'Recall':>8} {'F1':>8} {'FPR':>7} {'FNR':>7}"
    print(f"\n{header}")
    print("-" * 80)

    for domain in domains:
        for level in levels:
            if level in all_results[domain]:
                m = all_results[domain][level]["metrics"]
                label = domain if level == levels[0] else ""
                print(f"{label:<22} L{level:<7} {m['accuracy']:>8.4f} {m['precision']:>10.4f} {m['recall']:>8.4f} {m['f1_score']:>8.4f} {m['false_positive_rate']:>7.4f} {m['false_negative_rate']:>7.4f}")
        print("-" * 80)

    # Improvement table: Level 0 vs Level 2
    if 0 in levels and 2 in levels:
        print(f"\n{'='*80}")
        print("         REFLECTION IMPACT (Level 0 → Level 2)")
        print(f"{'='*80}")
        print(f"{'Domain':<22} {'L0 Acc':>8} {'L2 Acc':>8} {'Change':>9} {'L0 F1':>8} {'L2 F1':>8} {'Change':>9}")
        print("-" * 80)
        for domain in domains:
            if 0 in all_results[domain] and 2 in all_results[domain]:
                m0 = all_results[domain][0]["metrics"]
                m2 = all_results[domain][2]["metrics"]
                acc_diff = m2["accuracy"] - m0["accuracy"]
                f1_diff = m2["f1_score"] - m0["f1_score"]
                acc_arrow = "↑" if acc_diff > 0 else ("↓" if acc_diff < 0 else "=")
                f1_arrow = "↑" if f1_diff > 0 else ("↓" if f1_diff < 0 else "=")
                print(f"{domain:<22} {m0['accuracy']:>8.4f} {m2['accuracy']:>8.4f} {acc_arrow}{abs(acc_diff):>7.4f} {m0['f1_score']:>8.4f} {m2['f1_score']:>8.4f} {f1_arrow}{abs(f1_diff):>7.4f}")
        print("-" * 80)

    # Statistical significance
    print(f"\n{'='*80}")
    print("         STATISTICAL SIGNIFICANCE (McNemar's Test: Level 0 vs Level 2)")
    print(f"{'='*80}")
    for domain in domains:
        if domain in significance_results:
            test = significance_results[domain]
            sig = "YES ***" if test["significant"] else "NO"
            print(f"  {domain:<22} p={test['p_value']:.4f}  Significant: {sig}")
    if not significance_results:
        print("  No tests performed (need both Level 0 and Level 2)")

    # Cost summary
    print(f"\n{'='*80}")
    print("         COST SUMMARY BY LEVEL")
    print(f"{'='*80}")
    print(f"{'Level':<12} {'Avg Tokens':>12} {'Avg API Calls':>15} {'Avg Latency':>14} {'Total Time':>12}")
    print("-" * 70)
    for level_key, costs in cost_summary.items():
        print(f"  {level_key:<10} {costs['avg_tokens_per_sample']:>10.0f} {costs['avg_api_calls_per_sample']:>13.1f} {costs['avg_wall_time_seconds']:>12.2f}s {costs['total_wall_time_seconds']:>10.1f}s")
    print("-" * 70)

    print(f"\n{'='*80}")

    # Save results
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # Save detailed results
    save_data = {
        "timestamp": timestamp,
        "config": {
            "domains": domains,
            "levels": levels,
            "samples_per_domain": samples_per_domain,
        },
        "results": {},
        "cost_summary": cost_summary,
        "significance_tests": significance_results,
    }

    for domain in domains:
        save_data["results"][domain] = {}
        for level in levels:
            if level in all_results[domain]:
                r = all_results[domain][level]
                save_data["results"][domain][str(level)] = {
                    "metrics": r["metrics"],
                    "predictions": r["predictions"],
                }

    results_path = os.path.join(RESULTS_DIR, f"experiment_{timestamp}.json")
    with open(results_path, "w") as f:
        json.dump(save_data, f, indent=2, default=str)
    print(f"\nResults saved to: {results_path}")

    # Save cost data
    cost_df = cost_tracker.to_dataframe()
    cost_path = os.path.join(RESULTS_DIR, f"costs_{timestamp}.csv")
    cost_df.to_csv(cost_path, index=False)
    print(f"Cost data saved to: {cost_path}")

    return all_results


def main():
    parser = argparse.ArgumentParser(description="Run threat detection experiments")
    parser.add_argument("--domain", type=str, default=None,
                        help="Specific domain to test (phishing, network_intrusion, malware, log_analysis)")
    parser.add_argument("--level", type=int, default=None,
                        help="Specific reflection level (0, 1, 2)")
    parser.add_argument("--samples", type=int, default=None,
                        help="Number of samples per domain")
    args = parser.parse_args()

    domains = [args.domain] if args.domain else None
    levels = [args.level] if args.level is not None else None

    run_all_experiments(
        domains=domains,
        levels=levels,
        samples_per_domain=args.samples,
    )


if __name__ == "__main__":
    main()
