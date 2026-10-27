# Devpost submission copy

Near-final text. Items marked **YOU** need a fact only you know. Do not claim anything that did not happen,
especially in the live-mode and feedback sections.

**Track:** Coding and Agentic Engineering

## Project name
Talos: dual control for AI agents

## Tagline
Banking's oldest safety rules (maker-checker, teller limits, ledger, end-of-day reconciliation) for coding agents.

## Inspiration
Coding agents now delete files, read secrets and run commands. Humans cannot watch every step, and clicking "approve"
on everything defeats the purpose. Banks solved the same problem decades ago without watching every cashier: nobody
both makes and approves an entry, every teller has a limit, everything goes in an append-only ledger, and the books are
reconciled at the end of the day. Talos ports those controls to AI agents.

## What it does
Talos sits between a coding agent and its tools. Every action passes through a deterministic risk engine:
LOW actions run; MEDIUM actions are reviewed by an independent Checker model; HIGH actions wait for a human; hard
blocks never run. Everything is written to a tamper-evident hash-chained ledger. At the end of the day Talos
reconciles what you asked, what the agent planned and what actually happened, posts mismatches to suspense, can roll
back any write, and issues a sealed day-close certificate that anyone holding the ledger can verify.

Ten features: maker-checker with a context-isolated, fail-closed Checker; teller risk limits that freeze a misbehaving
agent; hash-chained ledger; three-way reconciliation with suspense; rollback; secret taint tracking; bank-style
authority levels (Trainee, Standard, Senior); a "threats stopped" view; a session replay slider; and the sealed
certificate.

## How it uses Nebius Token Factory and NVIDIA Nemotron
- **Maker:** Nemotron 3 Super runs the coding-agent loop (plan, read, write, run tests).
- **Checker:** a *different* Nemotron model (Ultra) reviews MEDIUM and HIGH actions. It sees only the structured action
  and the original task, never file contents or the Maker's reasoning, so a prompt injection hidden in a README cannot
  reach it. It fails closed: an API error or an unparseable answer means reject.
- Talos refuses to start a session if Maker and Checker are the same model (four-eyes rule).
- The large Checker model is only called for risky actions, so LOW actions cost no Checker tokens.
- Both models are called through Token Factory's OpenAI-compatible API (`https://api.tokenfactory.nebius.com/v1/`).

### Live-mode status (**YOU: keep exactly one of these two paragraphs and delete the other**)
**A. If you got access and ran it live:** I ran the full scenario live on Token Factory with
`<Maker model id>` and `<Checker model id>`. Results: `<what the real Maker did with the poisoned README, Checker
verdicts, latency, tokens used>`. The video shows this live run.

**B. If you did not get access:** The Nebius Token Factory integration is implemented and unit-tested against a fake
client, but I could not run it live: Bangladesh is not in the Token Factory billing country list, so I could not finish
onboarding or redeem the hackathon promo code. Nebius Support confirmed this is a provisioning limitation and pointed
me to Discord for case-by-case help (`<outcome>`). Because of this, the demo video and the hosted demo use the
offline simulation (a scripted agent and a heuristic Checker), and are labelled as such. Everything except the model
calls (risk engine, teller, ledger, reconciliation, rollback, certificate) is the real code path.

## How I built it
Python. Streamlit dashboard. Talos is a library plus a dashboard: the `Gate` wraps every tool call, the `RiskEngine`
classifies it, the `Teller` meters it, the `Checker` reviews it, and the `Ledger` records it. 58 automated tests cover
tamper and truncation detection, taint tracking, fail-closed behaviour, rollback conflicts, reconciliation drift and
certificate forgery. The agent's executor has no shell, a scrubbed environment and no network, as defence in depth.

## Challenges
- Making the Checker useful without letting an injected instruction reach it (solved by passing it only structured
  facts, never file contents).
- A hash chain alone cannot show that the newest entries were deleted, so the ledger exposes an anchor
  (`head()` / `verify(anchor)`) and the README states this limit.
- Blocked attempts had to cost budget too, otherwise a stubborn agent could probe forever for free.

## Accomplishments
In the demo, an agent hijacked by a poisoned README tries to steal a `.env` file: the credential read is held for a
human, the outbound POST carrying secret material is hard-blocked, and the `curl` fallback is blocked as a network
tool. The whole session can then be rolled back and sealed in a certificate that fails verification if the ledger, the
sealed data or even the visible text is edited.

## What's next
Plug Talos into real agents (Claude Code hooks, Cursor, Codex), per-team policy files, multi-session dashboards.

## Built with
Python, Streamlit, Nebius Token Factory (OpenAI-compatible API), NVIDIA Nemotron 3 Super and Ultra.

## Links (**YOU**)
- Public repo (MIT, license visible at the top): `https://github.com/shahriarsharif406/talos-dual-control` (check the real URL)
- Live demo URL (Streamlit Community Cloud): TODO
- YouTube demo (3 min or less, public): TODO

## Existing-project note (**YOU: verify every sentence is true before pasting**)
A private project also called Talos existed before the Submission Period: a planned commercial oversight product for
AI coding agents (FastAPI and Supabase backend, a Claude Code hook, private repository). **This hackathon submission is a
separate, new codebase** written for the Submission Period. It reuses the concept and the name, not the earlier code.
Everything in this repository is new in the Submission Period: the maker-checker gate, rule engine, teller limits,
authority levels, taint tracking, hash-chained ledger, three-way reconciliation, rollback, certificate, replay, the
Nebius Token Factory and Nemotron integration, the dashboard and the tests. (**YOU:** if you copied any code from the
earlier project, list it here.)

## Feedback on Nebius Token Factory, AI Cloud and NVIDIA tools (**YOU: edit to match your real experience**)
Based on what actually happened to me:
- **Billing country list is missing Bangladesh.** Billing setup (with a bank card) is mandatory during Token Factory
  onboarding, and the country of residence field has no Bangladesh entry, so a participant from a supported
  hackathon country cannot finish onboarding or redeem the hackathon promo code. Suggestion: show unsupported countries
  up front on the hackathon page, or provide a participant-credit path that does not need card billing.
- The promo code is applied inside the console (balance, Top up, With promo code), which is only reachable after
  onboarding, so the billing blocker also blocks the promo. Telling participants this before they start would help.
- Support responded and was clear and polite, but the only path offered was Discord with no guarantee of access.
  A named contact or a form for "country not supported" cases would be faster for a one-week hackathon.
- (**YOU**, only if you got in) Model IDs: did the IDs in the docs match the catalogue? JSON output quality of Super vs
  Ultra? Did `<think>` blocks break parsing? Latency and credit visibility?
