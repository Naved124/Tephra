# R030: a signal to the agent always raises an alert (26 Nov 2026)

Kernel 5.15.0-1121-aws, c7i.2xlarge, ap-south-1, kind. What changed and why is in the build log
(design.md, "R030 made reliable").

| Folder | Sensor | What it shows |
|---|---|---|
| `before-fix/` | tamper buffer and lost count, no table | E19 missed R030 in 2 of 2 rounds with nothing dropped: the kill record was taken by the dying agent's reader |
| `no-ordering/` | tamper buffer and table, no ordering with the main buffer | a planned rollout restart raised R030 and R031 on every node (`planned-restart.json`) |
| top level (`e19e23-*`, `kernel-tests.log`, `planned-restart.json`) | the fix | kernel tests 37 of 37; planned restart clean; E19 and E23 with real drops (67,000 to 564,000) all raised R030; later rounds ran while the agent was in the kubelet's crash back-off and are not results (see the build log) |
| `fresh/` | the fix, a fresh agent pod before each scenario | E19 and E23 raised R030 naming the attacker's pod in 8 of 8; E07 and E14 detected; attacks 22 of 22; `sigtrace.log` lists every SIGKILL and SIGTERM the kernel sent to the agent, `tamper.txt` the agent's tamper counters |
