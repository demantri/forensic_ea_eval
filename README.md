# forensic-ea-eval

Reproduction package for *Executable Evidence Traceability in Enterprise Architecture for Digital Forensic
Readiness: Design and Synthetic Evaluation of a Web Information System Prototype*.

Requires Python 3.9+ (standard library only).

```
python run_experiments.py
```

Writes `results/results.json` (all tables) and `results/reference_model.xml` (ArchiMate exchange format).

| File | Content |
|---|---|
| `prototype.py` | Localhost HTTP + SQLite prototype, five configurations, seeded synthetic workload, ground truth |
| `integrity.py` | Canonical JSON, hash chain (Eq. 2), HMAC checkpoint (Eq. 3), periodic checkpoints, export/retention controls |
| `model_checker.py` | Reference ArchiMate model (32 elements, 72 relationships), requirement catalogue, structural/semantic/conformance checker, five fault classes |
| `run_experiments.py` | Context availability (Eq. 4), scoped satisfaction (Eq. 5), detection (Eq. 6), per-seed results, storage, boundary scenarios B1–B5, checker fault injection |

Experimental parameters: seeds 17, 29, 41, 53, 67; 20 repetitions x 6 activities = 120 requests per seed and
configuration; configuration order rotated per seed; fresh in-memory database per run; periodic checkpoint
interval 20 events; one manipulation per type per seed.

Security note: `SYNTHETIC_KEY` is public by design for reproducibility and must not be used in deployment.

To check your own model, export it from Archi as Open Exchange Format and load it with
`model_checker.read_exchange_xml(path)`, adjusting `CATALOGUE` to your element identifiers.
# forensic_ea_eval
