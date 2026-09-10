# NOSY

A nosy neighbor for your network: it watches every conversation crossing the wire and tells you exactly who's acting suspicious, without ever being able to knock on their door.

---

## 1. Project Information

- **Project Title:** CropGuard – AI Crop Disease Detection
- **PS ID:** SIH26145
- **PS Title:** NOSY-AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
- **Category:** Software
- **Theme:** Blockchain & Cybersecurity

---

## 2. Problem Statement

Critical-infrastructure operators observe their gateway and peering links using passive mirroring or hardware data diodes that copy traffic into a monitoring enclave in one direction only. The enclave can see everything crossing the link but has no physical or protocol-level path back into the production network — it cannot probe, complete handshakes, or push mitigation commands back.

The objective is to design and build an AI/ML pipeline that ingests a one-directional stream of IP traffic and detects, classifies, and scores cyber-security threats in near real time, using only passively collected data — with output delivered as labelled alerts, confidence scores, and supporting evidence on a visualisation dashboard.

The system must detect six classes of threats:
- Volumetric / protocol DDoS
- Botnet C2 beaconing
- DGA domains and DNS tunnelling
- Malware inside encrypted sessions (metadata-only analysis)
- Reconnaissance and port scanning
- Data exfiltration

---

## 3. Proposed Solution

NOSY is a fully self-contained AI/ML pipeline and live dashboard that operates entirely within the one-way constraint of the problem statement. Since a real diode-fed production network isn't available for a hackathon prototype, NOSY uses a continuously running **synthetic traffic generator** (explicitly permitted by the problem statement's "simulated IP traffic" framing) to produce realistic flow data, including randomly injected attack patterns.

This traffic flows through a streaming pipeline: raw flows are aggregated into time-windowed features (entropy, fan-out, timing, byte ratios, JA3 fingerprints), scored by a combination of unsupervised (Isolation Forest) and supervised (Random Forest / XGBoost) models plus rule-based detectors, and any high-confidence detection is written as a structured, evidence-backed alert to a database. A live, auto-refreshing dashboard displays these alerts in real time — fully functional when deployed, with no pre-fetched or static data.

---

## 4. Key Features

- Detection across all 6 required threat classes: DDoS, port scanning/recon, C2 beaconing, DGA/DNS tunnelling, encrypted-session malware, and data exfiltration.
- Streaming, not batch — flows are processed incrementally with bounded alert latency.
- Structured alert schema: timestamp, flow identifier, threat class, confidence score, severity, and supporting evidence feature values.
- Hybrid detection approach: unsupervised anomaly detection (Isolation Forest) for novel/unlabeled threats, supervised classifiers (Random Forest/XGBoost) for well-labeled threats like DGA, and threshold rules for beaconing/exfiltration/JA3-blocklist matching.
- Live dashboard with severity-coded alerts, confidence visualization, click-to-inspect evidence, severity breakdown, and top-offending-source tracking.
- Fully live when deployed — the traffic simulator and detection pipeline run continuously inside the deployed app itself, not from a static results file.
- Strict adherence to architectural constraints: read-only ingest, no payload decryption, no active probing or mitigation, stated and measured throughput.

---

## 5. Technology Stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| Traffic simulation | Custom Python generator (`random`, `numpy`) |
| Data handling | pandas |
| ML — unsupervised | scikit-learn (Isolation Forest) |
| ML — supervised | scikit-learn / XGBoost (Random Forest, DGA classification) |
| Storage | SQLite |
| Concurrency | Python `threading` (background pipeline thread) |
| Dashboard / UI | Streamlit |
| Visualization | Plotly, custom HTML/CSS (via Streamlit) |
| Version control | Git + GitHub |
| Deployment | Streamlit Community Cloud |

---

## 6. Architecture

```
┌─────────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Traffic Simulator   │ --> │ Feature Extractor │ --> │  Inference Engine │
│  (synthetic flows,   │     │ (per-window stats, │     │ (Isolation Forest,│
│   injected attacks)  │     │  entropy, JA3, etc)│     │  RandomForest,    │
└─────────────────────┘     └──────────────────┘     │  threshold rules)  │
                                                        └────────┬──────────┘
                                                                 │
                                                                 v
                                                        ┌──────────────────┐
                                                        │  Alert Store      │
                                                        │  (SQLite)         │
                                                        └────────┬──────────┘
                                                                 │
                                                                 v
                                                        ┌──────────────────┐
                                                        │  Dashboard (UI)   │
                                                        │  (Streamlit,      │
                                                        │  auto-refresh)    │
                                                        └──────────────────┘
```

The traffic simulator, feature extractor, and inference engine run as a background thread inside the deployed Streamlit app; the dashboard reads from the same SQLite database in the main thread. This keeps the entire system self-contained in a single deployable process while satisfying the read-only, one-way ingest constraint at the software level — no component ever writes back toward a "traffic source."

Full details: see `PRD.md` and `TRD.md` in this repository.

---

## 7. Repository Structure

```
nosy/
├── README.md
├── PRD.md
├── TRD.md
├── UI_UX_DESIGN.md
├── BACKEND_SCHEMA.md
├── requirements.txt
├── schema.sql
├── schema_models.py
├── simulator.py
├── features.py
├── models.py
├── pipeline.py
├── app.py
├── train_models.py
├── data/
│   ├── ja3_blocklist.csv
│   └── dga_reference_words.csv
├── dashboard_mockup.html
└── tests/
```

---

## 8. Final Presentation

[Link to presentation slides to be added]

---

## 9. Demo Video

[Link to demo video to be added]

---

## 10. Screenshots / Prototype Photos

[Screenshots of the live dashboard to be added]

---

## 11. Installation

1. Clone the repository:
   ```
   git clone https://github.com/addhyan33/nosy-app.git
   cd nosy
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Initialize the database:
   ```
   sqlite3 threat_detection.db < schema.sql
   ```

4. Run the app locally:
   ```
   streamlit run app.py
   ```

5. Open the local URL shown in the terminal (typically `http://localhost:8501`) — the traffic simulator and detection pipeline start automatically in the background.

**Live deployment:** https://nosy-byteme.streamlit.app/

---

## 13. Future Scope

- Nicer Streamlit theming + network graph visualization (frontend polish — enhance the visual look if time permits).
- Hash-chained tamper-evident alert logging, so alert records cannot be silently modified after the fact — supporting forensic chain-of-custody use cases.
- RAG-based plain-English alert explanations — a retrieval-augmented generation layer that looks up relevant threat-intelligence reference material (e.g., MITRE ATT&CK technique summaries, known malware-family notes) before generating a human-readable explanation of why a given alert was raised.
