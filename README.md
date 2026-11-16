# SENTINEL UAV

Simulation-first research project on protected UAV–ground station communication,
location-aware mission authorization, and ML-based threat detection.

## Windows setup

Open the extracted folder in VS Code. Install Python 3.12, Git, and the VS Code
Python, Pylance, and Python Debugger extensions. GitLens, GitHub Pull Requests, and
Markdown All in One are optional editor tools.

```powershell
py -0p
py -3.12 --version
git --version
code --version
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe --version
.\.venv\Scripts\python.exe -m unittest -v security.sentinel_uav_policy
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m pytest -v
```

Select `.venv\Scripts\python.exe` as the VS Code Python interpreter. The commands
call it directly, so PowerShell activation is optional. Copy `.env.example`
to `.env` only when local configuration is needed. Set real secrets locally.

To preview the foundation screen after installing dependencies:

```powershell
.\.venv\Scripts\python.exe -m streamlit run streamlit_app.py
```

## First commit and GitHub

```powershell
git init -b main
git config user.name "Your Name"
git config user.email "your-github-email@example.com"
git add .
git status
git diff --cached --stat
git commit -m "Initial SENTINEL UAV project foundation"
```

Create an empty GitHub repository in your account. Copy its actual HTTPS URL,
then run `git remote add origin <repo-url>` and `git push -u origin main`.

Start with the [master specification](docs/MASTER_SPECIFICATION.md) and
[project status](docs/PROJECT_STATUS.md). Phase 2 begins with a read-only
ArduPilot SITL telemetry worker and a reproducible recording.

Keep using this workspace for each phase. The [phase workflow](docs/WORKFLOW.md)
shows where to add new files and how to record progress.
