"""CLI: ``python -m talos demo`` | ``python -m talos verify <ledger.jsonl>``."""
from __future__ import annotations

import argparse
import os
import sys

from .authority import LEVELS
from .certificate import CertificateError, build_certificate, render_html, verify_certificate_html
from .demo import SCENARIOS, run_scenario
from .ledger import Ledger
from .reconcile import close_day


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="talos", description="Dual control for AI agents")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("demo", help="run a demo scenario and print the end-of-day report")
    d.add_argument("--scenario", choices=list(SCENARIOS), default="injection")
    d.add_argument("--live", action="store_true", help="use Nemotron on Nebius Token Factory (needs NEBIUS_API_KEY)")
    d.add_argument("--data", default="./talos_data", help="where the ledger and sandbox workspace are written")
    d.add_argument("--authority", choices=list(LEVELS), default="standard", help="agent authority level (risk limits)")
    d.add_argument("--certificate", metavar="FILE", help="also write the day-close certificate (HTML) to FILE")
    d.add_argument("--maker-model", default=os.environ.get("TALOS_MAKER_MODEL"))
    d.add_argument("--checker-model", default=os.environ.get("TALOS_CHECKER_MODEL"))

    v = sub.add_parser("verify", help="verify the hash chain of a ledger file")
    v.add_argument("ledger")

    vc = sub.add_parser("verify-cert", help="check a day-close certificate against its ledger")
    vc.add_argument("certificate")
    vc.add_argument("--ledger", required=True)

    args = ap.parse_args(argv)
    if args.cmd == "verify-cert":
        try:
            with open(args.certificate, encoding="utf-8") as fh:
                ok, msg = verify_certificate_html(fh.read(), Ledger(args.ledger))
        except (CertificateError, OSError, KeyError, ValueError) as ex:
            print(f"INVALID: {ex}")
            return 1
        print(("VALID: " if ok else "INVALID: ") + msg)
        return 0 if ok else 1
    if args.cmd == "verify":
        ok, seq, msg = Ledger(args.ledger).verify()
        print(("OK: " if ok else f"BROKEN at #{seq}: ") + msg)
        return 0 if ok else 1

    run = run_scenario(args.data, args.scenario, live=args.live, maker_model=args.maker_model,
                       checker_model=args.checker_model, authority=args.authority)
    report = close_day(run.gate, run.session)
    for e in run.gate.ledger.entries():
        if e["kind"] == "action":
            print(f"#{e['seq']:>2} {e['tier']:<6} {e['decision']:<16} {e['tool']:<11} {e['target'][:60]}")
    print()
    print(report.to_markdown())
    if args.certificate:
        cert = build_certificate(run.gate.ledger, run.session.id, report)
        with open(args.certificate, "w", encoding="utf-8") as fh:
            fh.write(render_html(cert))
        print(f"Certificate written to {args.certificate}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
