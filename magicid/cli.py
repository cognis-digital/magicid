"""Command-line interface for MAGICID.

Subcommand:
    scan PATH...    Identify true file types by magic bytes.

Global:
    --version
    --format {table,json,html}
    --recursive
    --out FILE      (write report instead of stdout)

Exit codes:
    0  no findings (all consistent / readable)
    1  findings present (mismatches, unknown types, or read errors)
    2  usage / runtime error
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from typing import Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import Identification, scan_paths


SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "ok": 3}
SEV_COLOR = {
    "high": "#b00020",
    "medium": "#c47f00",
    "low": "#5a5a5a",
    "ok": "#1b7e3c",
}


def _summarize(results: list[Identification]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0, "ok": 0}
    for r in results:
        counts[r.severity] += 1
    return counts


def render_table(results: list[Identification]) -> str:
    rows = []
    rows.append(f"{TOOL_NAME} {TOOL_VERSION} — true file types by magic bytes")
    rows.append("=" * 72)
    if not results:
        rows.append("(no files scanned)")
        return "\n".join(rows)

    header = f"{'SEV':<7}{'TRUE TYPE':<26}{'EXT':<8}{'PATH'}"
    rows.append(header)
    rows.append("-" * 72)
    for r in sorted(results, key=lambda x: SEV_ORDER[x.severity]):
        ext = r.declared_ext or "(none)"
        rows.append(f"{r.severity.upper():<7}{r.detected_name[:25]:<26}"
                    f"{ext:<8}{r.path}")
        for f in r.findings:
            rows.append(f"        ! {f}")

    counts = _summarize(results)
    rows.append("-" * 72)
    rows.append(f"summary: {len(results)} file(s) | "
                f"high={counts['high']} medium={counts['medium']} "
                f"low={counts['low']} ok={counts['ok']}")
    return "\n".join(rows)


def render_json(results: list[Identification]) -> str:
    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "summary": _summarize(results),
        "count": len(results),
        "results": [r.to_dict() for r in results],
    }
    return json.dumps(payload, indent=2)


def render_html(results: list[Identification]) -> str:
    counts = _summarize(results)
    esc = html.escape

    def badge(sev: str) -> str:
        return (f'<span class="badge" style="background:{SEV_COLOR[sev]}">'
                f'{sev.upper()}</span>')

    summary_cards = "".join(
        f'<div class="card" style="border-color:{SEV_COLOR[s]}">'
        f'<div class="num" style="color:{SEV_COLOR[s]}">{counts[s]}</div>'
        f'<div class="lbl">{s.upper()}</div></div>'
        for s in ("high", "medium", "low", "ok")
    )

    body_rows = []
    for r in sorted(results, key=lambda x: SEV_ORDER[x.severity]):
        findings = "<br>".join(esc(f) for f in r.findings) or "&mdash;"
        body_rows.append(
            "<tr>"
            f"<td>{badge(r.severity)}</td>"
            f"<td class='mono'>{esc(r.path or '')}</td>"
            f"<td>{esc(r.declared_ext or '(none)')}</td>"
            f"<td>{esc(r.detected_name)}</td>"
            f"<td class='mono'>{esc(r.detected_mime)}</td>"
            f"<td class='mono'>{esc(r.head_hex)}</td>"
            f"<td>{findings}</td>"
            "</tr>"
        )
    rows_html = "\n".join(body_rows) or "<tr><td colspan='7'>No files scanned.</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{TOOL_NAME} report</title>
<style>
  :root {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; }}
  body {{ margin: 0; background: #f4f5f7; color: #1c1c1c; }}
  header {{ background: #11161d; color: #fff; padding: 20px 28px; }}
  header h1 {{ margin: 0; font-size: 20px; letter-spacing: .5px; }}
  header .sub {{ opacity: .7; font-size: 13px; margin-top: 4px; }}
  .wrap {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
  .cards {{ display: flex; gap: 14px; margin-bottom: 22px; flex-wrap: wrap; }}
  .card {{ background: #fff; border-left: 6px solid; border-radius: 8px;
           padding: 14px 20px; min-width: 90px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  .card .num {{ font-size: 28px; font-weight: 700; }}
  .card .lbl {{ font-size: 12px; color: #555; letter-spacing: .5px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff;
           border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  th, td {{ text-align: left; padding: 10px 12px; font-size: 13px;
            border-bottom: 1px solid #ececed; vertical-align: top; }}
  th {{ background: #f0f1f3; text-transform: uppercase; font-size: 11px; letter-spacing: .5px; }}
  tr:last-child td {{ border-bottom: none; }}
  .badge {{ color: #fff; padding: 2px 9px; border-radius: 10px; font-size: 11px;
            font-weight: 700; letter-spacing: .5px; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; }}
  footer {{ text-align: center; color: #888; font-size: 12px; padding: 18px; }}
</style></head>
<body>
<header>
  <h1>{TOOL_NAME} &mdash; true file types by magic bytes</h1>
  <div class="sub">version {TOOL_VERSION} &middot; {len(results)} file(s) scanned &middot; know your bytes</div>
</header>
<div class="wrap">
  <div class="cards">{summary_cards}</div>
  <table>
    <thead><tr>
      <th>Severity</th><th>Path</th><th>Ext</th><th>True Type</th>
      <th>MIME</th><th>Head (hex)</th><th>Findings</th>
    </tr></thead>
    <tbody>
{rows_html}
    </tbody>
  </table>
</div>
<footer>Generated by {TOOL_NAME} {TOOL_VERSION}. Defensive forensics &mdash; analyze artifacts you own.</footer>
</body></html>"""


RENDERERS = {"table": render_table, "json": render_json, "html": render_html}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Identify true file types by magic bytes (beats extensions).",
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Identify true file types of PATH(s).")
    scan.add_argument("paths", nargs="+", help="Files or directories to scan.")
    scan.add_argument("-r", "--recursive", action="store_true",
                      help="Recurse into directories.")
    scan.add_argument("--format", choices=("table", "json", "html"),
                      default="table", help="Output format (default: table).")
    scan.add_argument("--out", help="Write report to FILE instead of stdout.")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 2

    try:
        results = scan_paths(args.paths, recursive=args.recursive)
    except Exception as exc:  # pragma: no cover - defensive
        print(f"{TOOL_NAME}: error: {exc}", file=sys.stderr)
        return 2

    report = RENDERERS[args.format](results)

    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(report)
        except OSError as exc:
            print(f"{TOOL_NAME}: cannot write {args.out}: {exc}", file=sys.stderr)
            return 2
        print(f"{TOOL_NAME}: wrote {args.format} report to {args.out}")
    else:
        print(report)

    # Non-zero exit when any finding exists (mismatch / unknown / unreadable).
    has_findings = any(r.findings for r in results)
    return 1 if has_findings else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
