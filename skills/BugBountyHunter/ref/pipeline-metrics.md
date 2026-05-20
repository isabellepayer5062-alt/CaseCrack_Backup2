## Pipeline Effectiveness Metrics

Structured metrics are collected after each run and written to `pipeline-metrics.json`.

### Conversion Funnel KPIs

| Metric | Definition | Target |
|--------|-----------|--------|
| `recon_to_triage_rate` | Triage findings / ReconAnalyzer live hosts | > 15% |
| `triage_to_poc_rate` | PoCForge inputs / high-confidence triage findings | > 50% |
| `poc_to_validated_rate` | ExecutorValidator confirmed / PoCForge attempts | > 40% |
| `validated_to_submitted_rate` | ReportWizard submitted / validated findings | > 80% |
| `overall_yield` | Confirmed findings / total live hosts scanned | tracked |

### Cost Efficiency Metrics

| Metric | Definition |
|--------|-----------|
| `cost_per_finding_usd` | Total LLM cost / confirmed findings |
| `tokens_per_finding` | Total tokens / confirmed findings |
| `avg_phase_token_utilization` | Actual tokens used / phase budget |

### Quality Metrics

| Metric | Definition |
|--------|-----------|
| `false_positive_rate` | Rejected findings / total promoted to `status: finding` |
| `high_confidence_accuracy` | Confirmed high-band findings / total high-band findings |
| `chain_success_rate` | Validated chain PoCs / total ChainHunter chains |

Metrics accumulate in the KG across runs to enable trend analysis and automatic
threshold tuning via LearnerReflector.

