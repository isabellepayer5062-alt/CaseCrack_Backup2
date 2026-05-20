"""Final validation: Monte Carlo + divergence audit."""
import sys
import json
import logging

logging.basicConfig(level=logging.WARNING, format="%(name)s: %(message)s")

sys.path.insert(0, ".")
from tests.scenarios.run_all_scenarios import run_all_scenarios, divergence_audit

# Monte Carlo
print("=== MONTE CARLO (50 seeds) ===")
mc = run_all_scenarios(seeds=range(1, 51), verbose=False)
print(f"Status: {mc['suite_status']} | Runs: {mc['total_runs']} | Pass: {mc['total_passes']} | Fail: {mc['total_fails']} | Warn: {mc['total_warns']}")

# Divergence
print("\n=== DIVERGENCE AUDIT (20 seeds) ===")
div = divergence_audit(seeds=range(1, 21), verbose=False)
print(f"Pairs: {div['total_pairs']} | Identical: {div['identical']} | Divergent: {div['divergent']} | Determinism: {div['determinism_rate']:.0%}")
