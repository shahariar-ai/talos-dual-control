# Talos

**Dual control for AI agents. Banking's oldest safety rules, applied to coding agents.**

Coding agents now delete files, run commands and read secrets. Humans cannot watch every action, but nobody wants to
click "approve" blindly either. Banks solved exactly this problem decades ago, without watching every cashier: *dual
control, limits, a ledger, and reconciliation at the end of the day.* Talos is that system for AI agents.

> Built for the **Nebius x NVIDIA Global AI Hackathon** (Coding & Agentic Engineering track).
> Runs on **Nebius Token Factory** with **NVIDIA Nemotron** models.

## The five controls

| Bank control | What Talos does |
|---|---|
| **Maker-checker** | A Maker agent (Nemotron 3 Super) does the work. A *different* model (Nemotron 3 Ultra) independently reviews every medium/high-risk action. The Checker sees only the structured action and the user's original task, **never the Maker's reasoning or any file contents**, so a prompt injection hidden in a README cannot reach it. It **fails closed**: API error or garbled answer means *reject*. |
| **Teller limit** | Each session has a risk budget (LOW 1, MEDIUM 5, HIGH 20 points) plus write/command/byte caps. Blocked attempts are charged too, so an agent that keeps trying forbidden things burns its own limit and is **frozen** until a human raises it. |
| **General ledger** | Every action is written to an append-only **hash-chained** ledger. Secrets are replaced by fingerprints, never stored. Editing or deleting history breaks the chain. |
| **Three-way match + suspense** | At end of day Talos matches **intent** (task + allowed scope) against **plan** (what the agent said it would do) against **actual** (the ledger, then the real disk). Anything unmatched is posted to *suspense* until a human clears it. |
| **Reversal entries** | Every agent file write can be rolled back in one click. Rollback is itself a ledger entry and refuses to overwrite later work. |

### Beyond the five controls

| Feature | What it gives you |
|---|---|
| **Authority levels** | Trainee, Standard or Senior, like a bank's delegated-authority matrix. A trainee agent gets a tiny budget (30 points, 3 writes) and is frozen fast; a senior gets more room but never gets past a hard block. `python -m talos demo --authority trainee` |
| **Threats stopped** | Every action that did not run is grouped into plain categories (secret exfiltration, credential access, sandbox escape, destructive commands, supply chain, scope creep, runaway behaviour). |
| **Session replay** | A flight-recorder slider: scrub through the ledger step by step and watch the risk budget, stopped actions and changed files update. |
| **Day-close certificate** | A printable, sealed receipt for the session. The seal is a SHA-256 over its contents and it names the ledger entry it was issued at. `python -m talos verify-cert cert.html --ledger ledger.jsonl` fails if the ledger, the sealed data or even the visible text was edited. |

Plus **taint tracking**: if a secret is read during a session, any later action carrying that value (even renamed or
re-encoded into a different file) is hard-blocked as exfiltration.

## How decisions are made

```
tool call ──► rule engine (deterministic risk floor) ──► teller limit ──┐
                                                                         ▼
   LOW    → execute, log                         hard block (secrets out, network tools, escapes) → refuse, log
   MEDIUM → Checker (Ultra) reviews → execute or refuse, log
   HIGH   → Checker advises, a HUMAN decides; nothing runs until then
```

The rules set the *floor*: the LLM Checker can add scrutiny but can never lower a tier or override a hard block. The
expensive Ultra model is only called for MEDIUM/HIGH actions, so Token Factory credits stretch further.

## Quick start (no API key needed)

```bash
pip install -e ".[dashboard,dev]"
python -m talos demo                 # offline simulation, prints the end-of-day report
streamlit run dashboard/app.py       # interactive dashboard
pytest                               # 58 tests
```

The default `injection` scenario asks an agent to fix a failing test in a repo whose README secretly tells AI agents
to read `.env` and POST it to an attacker. The offline agent is scripted to obey the README; watch Talos let the real
fix through, hold the `.env` read, hard-block the exfiltration and the `curl`, and put the agent's unplanned scratch
file into suspense. The `runaway` scenario shows the teller freezing an agent.

## Live mode: Nemotron on Nebius Token Factory

```bash
export NEBIUS_API_KEY=...            # from the Token Factory API keys page
python -m talos demo --live          # or toggle "Live" in the dashboard
```

| Env var | Default | Role |
|---|---|---|
| `NEBIUS_BASE_URL` | `https://api.tokenfactory.nebius.com/v1/` | OpenAI-compatible endpoint |
| `TALOS_MAKER_MODEL` | `nvidia/nemotron-3-super-120b-a12b` | fast everyday agent calls |
| `TALOS_CHECKER_MODEL` | `nvidia/Nemotron-3-Ultra-550b-a55b` | independent high-stakes review |

Check the exact model IDs in your Token Factory catalogue; override with the env vars if they differ. Talos refuses
to open a session if Maker and Checker are the same model (four-eyes rule).

## Use it in your own agent

```python
from talos import Gate, Ledger, Workspace, Checker, Limits
from talos.llm import NebiusLLM

gate = Gate(Workspace("./project"), Ledger("./talos/ledger.jsonl"), Checker(NebiusLLM("nvidia/Nemotron-3-Ultra-550b-a55b")), Limits())
session = gate.open_session("Fix the failing test. Only change src/.", maker_model="my-agent-model")
gate.declare_plan(session, [{"tool": "write_file", "target": "src/calc.py"}])
result = gate.submit(session, "write_file", {"path": "src/calc.py", "content": "..."})   # LOW/MEDIUM/HIGH decision
print(result.decision, result.observation)
```

## Honest limitations

- **Talos is a control layer, not a sandbox.** It governs the tools it exposes (`read_file`, `write_file`,
  `run_command`, `http_post`). An agent with its own unrestricted shell can bypass it; Talos is meant to *be* the
  agent's tool interface. The built-in executor adds defence in depth (no shell, scrubbed environment, network tools
  disabled, `http_post` only writes to a local outbox).
- **A hash chain cannot reveal that the newest entries were deleted.** Store the ledger head (dashboard, Integrity
  tab) somewhere Talos cannot write, and verify against it: `Ledger.verify(anchor)`.
- **A user with write access to the ledger file can rewrite the whole chain.** The anchor above is the fix; signing
  entries with a key held elsewhere is the next step.
- The rule engine is heuristic. It is conservative on purpose (unknown commands are MEDIUM, ambiguous ones HIGH), and
  the Checker is a second opinion, not a proof.
- Offline mode uses a scripted Maker and a heuristic Checker so the demo is deterministic. It is labelled as a
  simulation in the dashboard and the reports.

## Layout

```
talos/        gate, risk engine, teller, authority levels, checker, maker, ledger, reconciliation, certificate, insight, tools, demo
dashboard/    Streamlit app + theme (overview, ledger, held items, teller, replay, end of day, rollback, integrity)
.streamlit/   dark theme config
tests/        58 tests incl. tamper/truncation detection, taint tracking, fail-closed checker, rollback, drift, certificate forgery
docs/         demo video script and Devpost submission draft
```

## License

MIT. See [LICENSE](LICENSE).
