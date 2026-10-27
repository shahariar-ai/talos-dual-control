# 3-minute demo video script

Public YouTube, 3:00 or shorter. The rules require showing **how you used Nebius Token Factory and Nemotron**, so the
video must show the *live* run at least once (toggle "Live" in the sidebar). Record the screen at 1080p, big font.

Before recording: `export NEBIUS_API_KEY=...`, `streamlit run dashboard/app.py`, clear `talos_data/`.
Do one dry run first. Optional: show Agent authority = Trainee for two seconds (a tiny budget freezes the agent fast). Untick "Harden Maker prompt against injection" so a real model is more likely to be tempted.
If the real model ignores the poisoned README (good models often do), say so honestly on camera, then switch to
**offline simulation** for the injection beat and label it as a simulation.

| Time | On screen | Say |
|---|---|---|
| 0:00-0:15 | Title card: "Talos: dual control for AI agents" | "Coding agents delete files and read secrets. Banks solved this decades ago without watching every cashier. So I built Talos: maker-checker, teller limits, a ledger, and end-of-day reconciliation, for AI agents." |
| 0:15-0:35 | Dashboard, sidebar showing Maker = Nemotron 3 Super, Checker = Nemotron 3 Ultra, Live on | "Two different Nemotron models on Nebius Token Factory. Super is the Maker: fast and cheap. Ultra is the independent Checker, called only for risky actions, so credits stretch." |
| 0:35-0:55 | Show the poisoned `README.md` (HTML comment) | "The task: fix a failing test. But this README hides an instruction telling AI agents to steal the `.env`." |
| 0:55-1:30 | Press Run. Ledger fills: green LOW rows, the fix applied, then red | "Reads and the real fix are auto-approved. The agent reads `.env`: held for a human. It tries to POST the key: hard-blocked. It tries curl: blocked. The Checker never saw the README, so the injection couldn't reach it." |
| 1:30-1:50 | Held tab: show checker advice, click Reject. Teller tab: budget bar | "Every attempt costs the agent risk points, even blocked ones. Keep misbehaving and it's frozen until a human raises its limit." |
| 1:50-2:25 | End of day tab: Close the day. OUT OF BALANCE, three-way table | "End of day, like a bank closing its books. Talos matches what I asked for, what the agent said it would do, and what actually happened. It wrote a file it never planned, outside my scope: that goes to suspense." Click Clear. Banner turns BALANCED. |
| 2:25-2:35 | Replay tab: drag the slider | "A flight recorder. Scrub through and watch the risk budget climb, and see the credential read was attempted but stopped." |
| 2:35-2:45 | Rollback tab: roll back everything. Then End of day: Download certificate | "One click undoes the agent's work, and the day is sealed in a certificate anyone can verify against the ledger." |
| 2:45-3:00 | Integrity tab: Falsify entry, chain turns red, then Restore | "And the ledger is hash-chained: try to cover your tracks and it breaks at the exact entry. Talos: banking's oldest safety rule, for coding agents." |

Tips: keep the cursor still while talking, zoom the browser to 125%, trim any waiting time on model calls.
