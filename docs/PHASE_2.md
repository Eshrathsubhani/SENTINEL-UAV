# Phase 2 — ArduPilot SITL telemetry

## Add the files in VS Code

Extract into the existing repository root, the inner SENTINEL-UAV folder
that contains .git, README.md, and requirements.txt. The ZIP contains
relative simulator/, tests/, and docs/ paths. Preserve their nesting.
Merge these directories with the existing ones. Open the same repository
in VS Code using the WSL extension if you prefer WSL terminals in the editor.

## Set up WSL and ArduPilot

In Windows Command Prompt or PowerShell, check for an existing WSL2 Ubuntu:

```cmd
wsl --list --verbose
```

If it is missing, run `wsl --install -d Ubuntu-24.04` in an administrator
terminal, restart if requested, and open Ubuntu to finish account setup.
Confirm Ubuntu appears as version 2. Use the installed distribution's
actual name with `wsl -d <name>` when multiple distributions are present.

Run these once in Ubuntu. Keep ArduPilot in the Linux home directory.

```bash
sudo apt update
sudo apt install -y git python3-venv
cd ~
git clone --recurse-submodules https://github.com/ArduPilot/ardupilot.git
cd ~/ardupilot
Tools/environment_install/install-prereqs-ubuntu.sh -y
. ~/.profile
git rev-parse HEAD
```

Restart the Ubuntu shell if the installer changed its PATH. Keep the
printed revision with the recordings. See the official [WSL instructions][wsl],
[ArduPilot build setup][ardupilot], and [SITL guide][sitl].

## Start the simulator and capture a baseline

In Ubuntu terminal 1:

```bash
cd ~/ardupilot
Tools/autotest/sim_vehicle.py -v ArduCopter -f quad --out=127.0.0.1:14551
```

Leave MAVProxy running. In Ubuntu terminal 2, use the same distribution
and the existing Windows project files:

```bash
cd /mnt/c/Users/eshra/Downloads/SENTINEL-UAV/SENTINEL-UAV
python3 -m venv ~/.venvs/sentinel-uav-phase2
~/.venvs/sentinel-uav-phase2/bin/python -m pip install pymavlink
~/.venvs/sentinel-uav-phase2/bin/python -m unittest discover -s tests/unit -p 'test_phase2_telemetry.py' -v
MAVLINK20=1 ~/.venvs/sentinel-uav-phase2/bin/python -m simulator.telemetry_collector --scenario stationary --seconds 45 --simulator-revision "$(git -C ~/ardupilot rev-parse HEAD)"
```

Look for `heartbeat_received`. The final line gives a unique directory
under `datasets/sitl_generated/` with `telemetry.csv` and `run.json`.
Both processes use Ubuntu loopback. Your Phase 1 Windows interpreter
remains available for its existing tests.

## Record three scenarios and test link recovery

1. **Stationary.** Wait for GPS fix in MAVProxy. Capture at least 45 seconds at rest.
2. **Takeoff and hover.** Start a fresh capture with `--scenario takeoff_hover`.
   Use MAVProxy in the local simulator to change to GUIDED, arm, and take off
   to a low simulated altitude. Look for increasing relative altitude.
3. **Movement and landing.** Start another capture with `--scenario movement_landing`.
   Move the simulated vehicle using MAVProxy or a simulated waypoint, then
   land. Check that position or speed changes and that relative altitude
   decreases at landing. Finish each flight within its recording window.
4. **Link recovery.** Start `--scenario link_recovery --seconds 120` after
   the simulator is ready. Stop the simulator with Ctrl+C, wait longer than
   five seconds, and relaunch it in the first terminal. Verify both
   `heartbeat_lost` and `heartbeat_recovered` in the same run metadata.
   For an initial-timeout check, run the collector with no simulator and
   look for `heartbeat_timeout` and a nonzero exit status.

The recorder only receives telemetry. Flight scenario actions are carried out
through MAVProxy using the local simulator. The default receiver expects
system ID 1, autopilot component 1, and an ArduPilot quadrotor heartbeat.
For an unexpected timeout, confirm the simulator launched, the output port
matches, and both terminals use the same WSL distribution.

## Recording schema and acceptance

The CSV records a row per accepted parsed frame with run ID, scenario, UTC
receive time, monotonic elapsed seconds, system and component IDs, message
type, and MAVLink frame byte length. The length excludes IP/UDP overhead.
GPS data uses degrees, altitude uses metres (MSL and relative are distinct),
ground speed uses m/s, attitude uses radians, and battery uses volts and
percent. `sample_boot_ms` is boot-relative and may reset if SITL restarts.
Blank means the field was absent or unavailable. A field in an older row
does not imply a current reading. `run.json` contains counts, simulator
revision if supplied, start/end times, stop reason and link transitions.

Keep each run and its metadata together for later train/test splitting.
Retain input logs and recordings as collected and write transformations
elsewhere. The CSV keeps normalized telemetry and frame metadata.
MAVProxy's own telemetry logs can be retained separately if needed.

Close Phase 2 after the three scenario recordings and link recovery check
are verified on your machine. Confirm a heartbeat and position, altitude,
speed, heading and attitude rows. Check battery values where the simulator
publishes them. Generated recordings are ignored by Git.

From the Windows VS Code Command Prompt in the same Git repository:

```cmd
..\.venv\Scripts\python.exe -m pytest -v
git add docs/PHASE_2.md simulator/mavlink_adapter.py simulator/telemetry_collector.py tests/unit/test_phase2_telemetry.py
git diff --cached --stat
git commit -m "Add read-only SITL telemetry recording"
git push
```

Use `.\.venv\Scripts\python.exe` instead if you created an inner Windows
environment. Record the local SITL verification result in PROJECT_STATUS.md
after the run checks pass.

[wsl]: https://learn.microsoft.com/en-us/windows/wsl/install
[ardupilot]: https://ardupilot.org/dev/docs/building-setup-windows11.html
[sitl]: https://docs.ardupilot.org/dev/docs/using-sitl-for-ardupilot-testing.html

## Horizontal Movement and Return-to-Launch Validation

**Scenario** `return_to_launch`
**Run ID** `df9a6678ec334824966369511c7ea03e`
**Simulator** ArduPilot SITL
**Result** PASS

| Metric | Result |
|---|---:|
| Launch latitude | −35.3632620° |
| Launch longitude | 149.1652373° |
| Maximum distance from launch | 20.40 m |
| Approximate total horizontal path | 41.63 m |
| Initial groundspeed | 0.024 m/s |
| Peak groundspeed | 6.52 m/s |
| Final latitude | −35.3632622° |
| Final longitude | 149.1652375° |
| Final distance from launch | 0.029 m |
| Maximum relative altitude | 15.01 m |
| Final relative altitude | 0.004 m |

The simulated UAV returned within 2.9 cm of its initial position and descended to landing level. The path length was calculated from consecutive position samples.

Evidence files `telemetry.csv` and `run.json` are in `datasets/sitl_generated/df9a6678ec334824966369511c7ea03e/`.