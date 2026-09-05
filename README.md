# SentinelTwin -- Phase 1-5 working prototype

A passive-only, hybrid (rules + Isolation Forest + graph correlation) threat
detection pipeline, built against `SentinelTwin_Claude_Project_Brief.pdf`.
This is the MVP slice of the brief: it proves the architecture end-to-end
on synthetic replayed traffic, with every performance claim backed by a
number this code actually produced -- not an assumed target.

## What's here

```
sentineltwin/
  schema/alert_schema.py       standardized alert (confidence vs severity, separated)
  simulate/flow_generator.py   passive replay simulator: benign + 5 attack scenarios
  detect/features.py           streaming feature engine (bounded sliding windows)
  detect/rules.py              deterministic detectors (DDoS, scan, DNS tunnel, C2, exfil)
  detect/iforest_model.py      Isolation Forest anomaly layer (unsupervised, streaming)
  detect/pipeline.py           wires feature engine + rules + IF + alerts together
  alerts/alert_manager.py      merges rule + model output into Alert objects
  alerts/graph_correlator.py   Threat Behavior Graph (NetworkX), incident merging
  api/main.py                  FastAPI backend (session run, alerts, graph, incidents)
  benchmark/run_benchmark.py   throughput/latency measurement (Phase 5)
  run_demo.py                  one-command console demo (Phase 6-lite)
```

No dashboard UI (React/Cytoscape.js) is built yet -- `/graph` already
returns Cytoscape-ready JSON, so that's the next piece to wire up, not a
redesign.

## Quickstart

```bash
pip install -r requirements.txt
python3 run_demo.py --duration 180 --seed 42
```

This trains the Isolation Forest on a benign-only corpus, replays a mixed
session (benign background + injected DDoS, port scan, DNS tunneling, C2
beaconing, and data exfiltration), prints a sample of alerts, then reports
ground-truth recall, false-positive rate on benign traffic, latency
percentiles, and shared-destination correlations.

For the API:

```bash
uvicorn api.main:app --reload --port 8000
# POST /session/run  {"duration_s": 120, "seed": 42, "speed_factor": 500}
# GET  /alerts
# GET  /graph
```

For the throughput benchmark:

```bash
python3 -m benchmark.run_benchmark --flows 20000
```

## What's actually true about this prototype right now (measured, not assumed)

- **Detection recall**: on a 180s synthetic session (seed 42), all 5
  labeled attack categories (volumetric DDoS, port scan, DNS tunneling,
  C2 beaconing, data exfiltration) were recalled by at least one alert.
  This is one seed, one synthetic generator -- not a claim about real
  attack traffic or a proper precision/recall/F1 sweep across seeds.
- **False positive rate**: ~4% of benign flows produced at least one
  alert in the same run, almost entirely from the unsupervised
  Isolation Forest catch-all category (`encrypted_malware`, fired when
  no deterministic rule matches). That's the honest number after fixing
  an initial calibration bug (see below) -- it is not yet tuned to a
  target FP rate, and 4% is too high for a real SOC without further
  tuning or a supervised second stage.
- **Latency**: p50 ~11ms, p95 ~14ms per flow, single-flow synchronous
  processing, unbatched. Comfortably under the brief's 2000ms p95
  target.
- **Throughput**: ~85-300 flows/sec sustained, single-flow-at-a-time,
  measured with `benchmark/run_benchmark.py`. This is **well under**
  the brief's 10,000 flows/sec target. Root cause: scikit-learn's
  `IsolationForest.decision_function` has fixed per-call overhead that
  doesn't amortize when scoring one row at a time -- confirmed by
  testing the same model in batched mode, which scored 15,000 flows at
  ~336,000 flows/sec. **The fix is micro-batching** (buffer N flows in
  a short window, score as one batch, then fan the results back out per
  flow) rather than a different model. Not yet implemented here --
  that's the next concrete task, and this measurement is what justifies
  prioritizing it over other changes.

## Design decisions worth knowing about if you extend this

- **Confidence vs severity are computed separately** (`schema/alert_schema.py`):
  confidence is evidence strength (from rule thresholds and/or IF anomaly
  score), severity is threat-class ceiling scaled by that confidence.
  Neither is a calibrated probability -- there's no labeled ground truth
  to calibrate against yet, and the alert schema says so in `detector_source`
  rather than in a fake percentage.
- **Isolation Forest scoring is squashed with a logistic function around
  the model's contamination-implied decision boundary**, not min/max
  percentile normalization. The first version used percentile
  normalization from training data and produced a 22.5% false-positive
  rate on held-out benign traffic -- narrow percentile bounds don't
  generalize to fresh data's natural variance. The logistic squash
  fixed that down to ~4%. This is exactly the kind of thing the brief
  asks to be measured, not assumed, and it's worth re-checking if you
  change the feature set or training corpus size.
- **Shared-destination graph correlation excludes volumetric DDoS edges**
  on purpose. A flood victim naturally has thousands of distinct (often
  spoofed) attacking sources, which triggers "shared destination" logic
  trivially and drowns out the genuinely interesting signal: multiple
  *internal* hosts talking to the same external destination, which is
  what suggests coordinated compromise.
- **C2 beacon detection needs >= 4 samples** of a host talking to the
  same destination within a 15-minute window before it can compute a
  periodicity score. Short demo sessions need the synthetic generator to
  deliberately compress the beacon period to guarantee enough samples
  land inside the window -- this is a demo-generator concession, and a
  real deployment would need a correspondingly patient evaluation window
  before it can catch beaconing at all.

## Known gaps against the full brief (by design, for MVP scope)

- No Kafka/streaming-queue integration -- single-process, synchronous.
- No supervised second-stage model (XGBoost) -- brief recommends adding
  this only once labeled data exists, which it doesn't yet here.
- No dashboard UI -- API returns dashboard-ready JSON but no React/Cytoscape
  frontend has been built.
- No Docker packaging.
- Synthetic traffic only -- no real PCAP/NetFlow replay validated against
  this pipeline yet.
- Throughput does not yet meet the stated 10,000 flows/sec target (see above).

## Suggested next steps, in priority order

1. Micro-batch the Isolation Forest scoring path -- biggest lever on the
   throughput gap, and already measured to close it.
2. Wire the dashboard (`/graph`, `/alerts`, `/incident/{id}` are ready).
3. Run a proper precision/recall/F1 sweep across multiple seeds and
   traffic-rate configurations, not just the one session reported above.
4. Add the JA3/JA4-rarity-based encrypted-malware rule explicitly rather
   than leaning entirely on the IF catch-all for that category.
