# Archived pipeline stages

These stage modules were part of the original linear pipeline and have been
superseded by the current LLMCloudHunter-inspired pipeline:

```
preprocess → web_enrich → poc_analysis → attack_vector → analysis → generate → review
```

| Archived file        | Replaced by                                              |
|----------------------|----------------------------------------------------------|
| `stage_extract.py`   | Indicator extraction folded into `stage_preprocess.py`   |
| `stage_ttp_map.py`   | MITRE TTP mapping folded into `stage_attack_vector.py`   |
| `stage_logsource.py` | Logsource selection folded into `stage_analysis.py` / `stage_generate.py` |
| `stage_validate.py`  | Validation folded into `stage_review.py` (deterministic syntax check + LLM semantic review) |
| `stage_optimize.py`  | Optimization folded into `stage_review.py` (combined review + optimize pass) |

The orchestrator at `backend/pipeline/orchestrator.py` does not import any
file in this directory. The files are kept here as historical reference and
are safe to delete if you no longer need to consult them.
