# Working through the phases

Extract the project once and open the SENTINEL-UAV directory in VS Code.
Follow the root README for environment setup and the first Git commit.

| Work | Where it goes |
|---|---|
| SITL integration and telemetry recorder | simulator/ and backend/telemetry/ |
| UAV and GCS communication | gateways/ |
| Geolocation and authorization | security/ |
| Data preparation, training, and evaluation | ai_engine/ |
| Local datasets and recordings | datasets/ |
| Dashboard and pages | streamlit_app.py and app/ |
| Tests and benchmarks | tests/ and experiments/ |

For each phase, add files to the relevant directories in this workspace,
run the project's checks, update PROJECT_STATUS.md, and commit the changes.
Keep experiment decisions and results in RESEARCH_LOG.md. If you already
started from the Phase 1 package, continue in your existing folder and add
this guide there if useful.
