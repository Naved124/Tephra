# Blind mode and file summaries, 5.15 (26 Nov 2026)

v0.2.0 item 5. c7i.2xlarge on-demand, ap-south-1, kernel 5.15.0-1121-aws, BPF LSM on. Sensor from the item5/blind-mode working tree (`v0.1.0-37-gd6659dd-dirty`). Agent with raw events, quiet connections and batched wake-ups on; blind mode on with its defaults.

| File | What |
|---|---|
| `kernel-tests.log` | Kernel tests, 43 pass, 1 skip |
| `agent-start-*.log` | Each agent's blind-mode lines at start |
| `planned-restart.json` | Loki query for R030, R031, R038 after a rollout restart: none |
| `E07`, `E14`, `E19-1`, `E19-2`, `E23-1`, `E23-2` | Evasion reports, each with a fresh agent pod first |
| `attacks/`, `attacks.log` | All 22 attacks, 22 detected |
| `fp/`, `fp.log`, `fp-r038.json` | 30-minute false-positive run; no R038 |
| `metrics.txt` | Blind-mode and file-summary metrics after each step |

The analysis is in the build log in `docs/design.md`, "Blind mode and file summaries".
