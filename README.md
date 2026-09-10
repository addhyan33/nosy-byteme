# NOSY

> A nosy neighbor for your network: it watches every conversation crossing the wire and tells you exactly who's acting suspicious, without ever being able to knock on their door.

NOSY is a streaming, passive network-threat-detection prototype for a one-way monitoring environment. It continuously generates synthetic network metadata, analyzes rolling time windows, and presents evidence-backed alerts in a live dashboard.

The application has no traffic-source client, no active probing, no packet injection, no mitigation capability, and no TLS or QUIC payload decryption. It only works with simulated flow metadata and visible handshake indicators.

## Detection coverage

- Volumetric and protocol DDoS
- Botnet command-and-control beaconing
- DGA domains and DNS tunnelling
- Malware indicated by encrypted-session fingerprint metadata
- Reconnaissance and port scanning
- Possible data exfiltration based on anomalous outbound volume

Each alert includes a confidence score, severity, originating flow context, detector used, and human-readable evidence.

## Architecture

```text
Synthetic traffic simulator -> rolling feature extraction -> ML/rule inference -> SQLite -> NOSY dashboard
```

- `backend/` contains the simulator, feature extraction, models, SQLite schema, and background pipeline.
- `frontend/` contains the Streamlit dashboard and its NOSY visual design.
- `data/` contains the small, local JA3 and DGA reference sets.
- `tests/` contains detector and feature sanity tests.

## Deploy on Streamlit Community Cloud

1. Push this project to GitHub, including `requirements.txt` and `app.py` at the repository root.
2. Open [Streamlit Community Cloud](https://share.streamlit.io/) and sign in with GitHub.
3. Select **Create app**.
4. Select the repository `addhyan33/NOSY`.
5. Choose the `main` branch.
6. Set the main file path to `app.py`.
7. Click **Deploy**.

Streamlit installs the packages listed in `requirements.txt` automatically. Once deployed, the background pipeline starts with the app and the dashboard begins producing live synthetic traffic and alerts without needing any setup step from the viewer.

## Demo behaviour and limitations

- The target ingestion rate is 60 synthetic flows per second.
- The dashboard refreshes every two seconds.
- SQLite uses a local file in the deployed container. Streamlit Community Cloud may restart or sleep an app, which clears transient app state; that is acceptable for this prototype. A production deployment would use persistent storage and a dedicated streaming service.
- Alert counts and model registry scores are prototype/demo values. Measure and report your own results for a formal evaluation.

## Safety boundary

NOSY intentionally cannot act on the monitored network. The interface repeatedly shows the ingest path - production network -> one-way gateway -> NOSY console - to make the core constraint explicit: **no return path exists**.
