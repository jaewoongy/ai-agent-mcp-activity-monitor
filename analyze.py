#!/usr/bin/env python3
"""
MCP Activity Monitor - Log Analyzer

Commands:
  list                          List all recorded sessions
  show   <session_id>           Detailed breakdown of one session
  compare <session_a> <session_b>   Side-by-side comparison of two sessions
  flags  [session_id]           All flagged (suspicious) entries; omit ID for all sessions
  export <session_id>           Export session to CSV

Usage examples:
  python analyze.py list
  python analyze.py show 20240101T120000_abc123
  python analyze.py compare 20240101T120000_abc123 20240101T130000_def456
  python analyze.py flags
  python analyze.py export 20240101T120000_abc123 > session.csv
"""

import sys
import json
import csv
import argparse
from pathlib import Path
from collections import defaultdict

LOGS_DIR = Path(__file__).parent / "logs"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_summaries() -> list[dict]:
    if not LOGS_DIR.exists():
        return []
    summaries = []
    for f in sorted(LOGS_DIR.glob("*_summary.json")):
        try:
            summaries.append(json.loads(f.read_text()))
        except Exception:
            pass
    return summaries


def load_jsonl(session_id: str) -> list[dict]:
    path = LOGS_DIR / f"{session_id}.jsonl"
    if not path.exists():
        print(f"[error] Log not found: {path}", file=sys.stderr)
        sys.exit(1)
    entries = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return entries


def resolve_session_id(partial: str, summaries: list[dict]) -> str:
    """Allow short prefixes."""
    matches = [s["session_id"] for s in summaries if s["session_id"].startswith(partial)]
    if len(matches) == 1:
        return matches[0]
    if len(matches) == 0:
        print(f"[error] No session matching '{partial}'", file=sys.stderr)
        sys.exit(1)
    print(f"[error] Ambiguous prefix '{partial}' matches: {matches}", file=sys.stderr)
    sys.exit(1)


def tool_entries(entries: list[dict]) -> list[dict]:
    return [e for e in entries if e.get("method") == "tools/call"]


def suspicious_entries(entries: list[dict]) -> list[dict]:
    return [e for e in entries if e.get("SUSPICIOUS")]


def sensitivity_color(sensitivity: str) -> str:
    return {"high": "\033[91m", "medium": "\033[93m", "low": "\033[92m"}.get(sensitivity, "")

RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
RED   = "\033[91m"
YEL   = "\033[93m"
GRN   = "\033[92m"
CYN   = "\033[96m"


def use_color() -> bool:
    return sys.stdout.isatty()


def c(code: str, text: str) -> str:
    if use_color():
        return f"{code}{text}{RESET}"
    return text


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_list(args):
    summaries = load_summaries()
    if not summaries:
        print("No sessions found. Run proxy.py first.")
        return

    header = f"{'SESSION ID':<28}  {'LABEL':<24}  {'STARTED':<22}  {'TOOLS':>5}  {'SUSP':>5}"
    print(c(BOLD, header))
    print("-" * len(header))

    for s in summaries:
        stats = s.get("stats", {})
        tc = stats.get("tool_calls", 0)
        sc = stats.get("suspicious_calls", 0)
        susp_str = c(RED, str(sc)) if sc > 0 else str(sc)
        print(
            f"{s['session_id']:<28}  {s['label']:<24}  {s['started_at'][:19]:<22}  "
            f"{tc:>5}  {susp_str:>5}"
        )


def bar(count: int, max_count: int, width: int = 30) -> str:
    filled = int(width * count / max_count) if max_count else 0
    return "█" * filled + "░" * (width - filled)


def extract_paths(arguments: dict) -> list:
    paths = []
    for v in arguments.values():
        if isinstance(v, str) and ("/" in v or v.startswith("~")):
            paths.append(v)
    return paths


def extract_urls(arguments: dict) -> list:
    import re
    urls = []
    for v in arguments.values():
        if isinstance(v, str):
            found = re.findall(r"https?://[^\s\"']+", v)
            urls.extend(found)
    return urls


WRITE_TOOLS = {"write_file", "edit_file"}
BROWSER_TOOLS = {
    "browser_navigate", "browser_click", "browser_type", "browser_screenshot",
    "browser_scroll", "browser_hover", "browser_select_option", "browser_evaluate",
    "browser_new_tab", "browser_close", "browser_wait",
}


def build_results_map(entries: list[dict]) -> dict:
    """Map jsonrpc_id -> result_snippet from tool_result entries."""
    return {
        e["jsonrpc_id"]: e.get("result_snippet", "")
        for e in entries
        if e.get("type") == "tool_result" and e.get("jsonrpc_id") is not None
    }


def cmd_show(args):
    summaries = load_summaries()
    session_id = resolve_session_id(args.session_id, summaries)
    entries = load_jsonl(session_id)
    summary = next((s for s in summaries if s["session_id"] == session_id), {})

    stats = summary.get("stats", {})
    print(c(BOLD, f"\n=== Session: {session_id} ==="))
    print(f"Label    : {summary.get('label', '—')}")
    print(f"Started  : {summary.get('started_at', '—')}")
    print(f"Ended    : {summary.get('ended_at', '—')}")
    print(f"Messages : {stats.get('total_messages', 0)}")
    print(f"Tool calls: {stats.get('tool_calls', 0)}")

    sc = stats.get("suspicious_calls", 0)
    print(f"Suspicious: {c(RED, str(sc)) if sc else str(sc)}")

    calls = tool_entries(entries)
    results_map = build_results_map(entries)

    # --- Tool call frequency histogram ---
    tool_counts = defaultdict(int)
    for e in calls:
        tool_counts[e.get("tool_name", "?")] += 1

    if tool_counts:
        print(c(BOLD, "\nTool call frequency:"))
        max_count = max(tool_counts.values())
        for tool, count in sorted(tool_counts.items(), key=lambda x: -x[1]):
            print(f"  {tool:<30} {bar(count, max_count)} {count}")

    # --- Sensitivity breakdown ---
    sens_counts = defaultdict(int)
    for e in calls:
        s = e.get("classification", {}).get("sensitivity", "unknown")
        sens_counts[s] += 1

    if sens_counts:
        print(c(BOLD, "\nSensitivity breakdown:"))
        total = sum(sens_counts.values())
        order = ["high", "medium", "low", "unknown"]
        colors = {"high": RED, "medium": YEL, "low": GRN, "unknown": DIM}
        for level in order:
            count = sens_counts.get(level, 0)
            if count == 0:
                continue
            pct = int(100 * count / total)
            print(f"  {c(colors[level], f'{level:<8}')}  {bar(count, total, 20)} {count:>3} ({pct}%)")

    # --- Timeline: calls per minute ---
    minute_counts = defaultdict(int)
    for e in calls:
        ts = e.get("ts", "")
        minute = ts[11:16] if len(ts) >= 16 else "?"
        minute_counts[minute] += 1

    if len(minute_counts) > 1:
        print(c(BOLD, "\nActivity timeline (calls/minute):"))
        max_m = max(minute_counts.values())
        for minute in sorted(minute_counts):
            count = minute_counts[minute]
            print(f"  {minute}  {bar(count, max_m, 20)} {count}")

    # --- Top files accessed ---
    path_counts = defaultdict(int)
    for e in calls:
        for p in extract_paths(e.get("arguments", {})):
            path_counts[p] += 1

    if path_counts:
        print(c(BOLD, "\nTop files / paths accessed:"))
        for path, count in sorted(path_counts.items(), key=lambda x: -x[1])[:10]:
            print(f"  {count:>3}x  {path}")

    # --- URLs fetched ---
    url_counts = defaultdict(int)
    for e in calls:
        for url in extract_urls(e.get("arguments", {})):
            url_counts[url] += 1

    if url_counts:
        print(c(BOLD, "\nURLs fetched:"))
        for url, count in sorted(url_counts.items(), key=lambda x: -x[1])[:10]:
            print(f"  {count:>3}x  {url}")

    # --- Files written ---
    written = [(e, e["arguments"]) for e in calls if e.get("tool_name") in WRITE_TOOLS]
    if written:
        print(c(BOLD, "\nFiles written / edited:"))
        for e, args in written:
            path = args.get("path", "?")
            if e.get("tool_name") == "write_file":
                content = args.get("content", "")
                snippet = content[:200].replace("\n", "↵")
                print(f"  {e['ts'][11:19]}  {c(YEL, 'write')}  {path}")
                print(f"           {DIM}{snippet}{'…' if len(content) > 200 else ''}{RESET}")
            else:
                edits = args.get("edits", [])
                print(f"  {e['ts'][11:19]}  {c(YEL, 'edit ')}  {path}  ({len(edits)} edit(s))")
                for ed in edits[:3]:
                    old = ed.get("oldText", "")[:60].replace("\n", "↵")
                    new = ed.get("newText", "")[:60].replace("\n", "↵")
                    print(f"           {DIM}- {old}{RESET}")
                    print(f"           {c(GRN, f'+ {new}')}")

    # --- Browser activity ---
    browser_calls = [e for e in calls if e.get("tool_name") in BROWSER_TOOLS]
    if browser_calls:
        print(c(BOLD, "\nBrowser activity:"))
        for e in browser_calls:
            tool = e.get("tool_name", "?")
            args = e.get("arguments", {})
            result = results_map.get(e.get("jsonrpc_id"), "")
            if tool == "browser_navigate":
                print(f"  {e['ts'][11:19]}  navigate  {c(CYN, args.get('url', '?'))}")
            elif tool == "browser_click":
                target = args.get("element") or args.get("selector") or args.get("coordinate") or "?"
                print(f"  {e['ts'][11:19]}  click     {target}")
            elif tool == "browser_type":
                text = str(args.get("text", ""))[:80]
                print(f"  {e['ts'][11:19]}  type      {DIM}{text}{RESET}")
            elif tool == "browser_screenshot":
                print(f"  {e['ts'][11:19]}  {c(YEL, 'screenshot')}")
            elif tool == "browser_evaluate":
                expr = str(args.get("expression", ""))[:80]
                print(f"  {e['ts'][11:19]}  evaluate  {DIM}{expr}{RESET}")
            else:
                print(f"  {e['ts'][11:19]}  {tool.replace('browser_', ''):<12}  {str(args)[:80]}")
            if result:
                print(f"           {DIM}→ {result[:120]}{RESET}")

    # --- Suspicious flags ---
    flags = stats.get("flags", {})
    if flags:
        print(c(BOLD, "\nSuspicious flags triggered:"))
        max_f = max(flags.values())
        for flag, count in sorted(flags.items(), key=lambda x: -x[1]):
            print(f"  {c(RED, flag):<38} {bar(count, max_f, 15)} {count}")

    # --- Full call log ---
    if calls:
        print(c(BOLD, f"\nAll tool calls ({len(calls)}):"))
        for e in calls:
            cls = e.get("classification", {})
            sens = cls.get("sensitivity", "?")
            col = sensitivity_color(sens)
            flag_str = ""
            if e.get("SUSPICIOUS"):
                flag_str = c(RED, " [SUSPICIOUS: " + ", ".join(cls.get("flags", [])) + "]")
            args_preview = str(e.get("arguments", {}))[:80]
            print(
                f"  {e['ts'][11:19]}  {c(col, f'{sens:<6}')}  "
                f"{c(BOLD, e.get('tool_name','?')):<30}  {args_preview}{flag_str}"
            )
            result = results_map.get(e.get("jsonrpc_id"))
            if result:
                print(f"           {DIM}→ {result[:120]}{RESET}")


def _session_summary_block(session_id: str, summaries: list[dict]) -> dict:
    summary = next((s for s in summaries if s["session_id"] == session_id), {})
    entries = load_jsonl(session_id)
    calls = tool_entries(entries)
    susp = suspicious_entries(entries)
    return {
        "summary": summary,
        "entries": entries,
        "calls": calls,
        "suspicious": susp,
    }


def cmd_compare(args):
    summaries = load_summaries()
    id_a = resolve_session_id(args.session_a, summaries)
    id_b = resolve_session_id(args.session_b, summaries)

    a = _session_summary_block(id_a, summaries)
    b = _session_summary_block(id_b, summaries)

    def row(label, va, vb):
        a_str = str(va)
        b_str = str(vb)
        diff = ""
        if isinstance(va, int) and isinstance(vb, int) and va != vb:
            delta = vb - va
            diff = c(RED if delta > 0 else GRN, f"  ({'+' if delta > 0 else ''}{delta})")
        print(f"  {label:<28} {a_str:<20} {b_str:<20}{diff}")

    print(c(BOLD, "\n=== Session Comparison ===\n"))
    print(f"  {'METRIC':<28} {'SESSION A':<20} {'SESSION B':<20}")
    print(f"  {'------':<28} {'─' * 18:<20} {'─' * 18:<20}")

    row("Session ID", id_a[:20], id_b[:20])
    row("Label", a["summary"].get("label","?"), b["summary"].get("label","?"))
    row("Started", a["summary"].get("started_at","?")[:19], b["summary"].get("started_at","?")[:19])

    sa = a["summary"].get("stats", {})
    sb = b["summary"].get("stats", {})
    row("Total messages", sa.get("total_messages", 0), sb.get("total_messages", 0))
    row("Tool calls", sa.get("tool_calls", 0), sb.get("tool_calls", 0))
    row("Suspicious calls", sa.get("suspicious_calls", 0), sb.get("suspicious_calls", 0))

    # Per-category comparison
    all_cats = sorted(set(list(sa.get("categories", {}).keys()) + list(sb.get("categories", {}).keys())))
    if all_cats:
        print(c(BOLD, "\n  Categories:"))
        for cat in all_cats:
            ca = sa.get("categories", {}).get(cat, 0)
            cb = sb.get("categories", {}).get(cat, 0)
            row(f"  {cat}", ca, cb)

    # Per-flag comparison
    all_flags = sorted(set(list(sa.get("flags", {}).keys()) + list(sb.get("flags", {}).keys())))
    if all_flags:
        print(c(BOLD, "\n  Flags triggered:"))
        for flag in all_flags:
            fa = sa.get("flags", {}).get(flag, 0)
            fb = sb.get("flags", {}).get(flag, 0)
            row(f"  {flag}", fa, fb)

    # Unique tool calls in B not in A
    tools_a = {e.get("tool_name") for e in a["calls"]}
    tools_b = {e.get("tool_name") for e in b["calls"]}
    new_in_b = tools_b - tools_a
    if new_in_b:
        print(c(BOLD, f"\n  Tools in B but not A: ") + c(YEL, ", ".join(sorted(new_in_b))))
    new_in_a = tools_a - tools_b
    if new_in_a:
        print(c(BOLD, f"  Tools in A but not B: ") + c(YEL, ", ".join(sorted(new_in_a))))


def cmd_flags(args):
    summaries = load_summaries()
    if not summaries:
        print("No sessions found.")
        return

    if args.session_id:
        session_ids = [resolve_session_id(args.session_id, summaries)]
    else:
        session_ids = [s["session_id"] for s in summaries]

    total = 0
    for sid in session_ids:
        entries = load_jsonl(sid)
        susp = suspicious_entries(entries)
        if not susp:
            continue
        label = next((s["label"] for s in summaries if s["session_id"] == sid), "?")
        print(c(BOLD, f"\n[{sid}] label={label}  ({len(susp)} suspicious)"))
        for e in susp:
            cls = e.get("classification", {})
            flags = cls.get("flags", [])
            sens = cls.get("sensitivity", "?")
            col = sensitivity_color(sens)
            print(
                f"  {e['ts'][11:19]}  {c(col, sens):<14}  "
                f"{c(BOLD, e.get('tool_name','?')):<28}  "
                f"{c(RED, ','.join(flags))}"
            )
            args_str = json.dumps(e.get("arguments", {}), separators=(",", ":"))
            print(f"           {DIM}{args_str[:120]}{RESET}")
        total += len(susp)

    print(f"\nTotal suspicious entries: {c(RED, str(total)) if total else str(total)}")


def cmd_export(args):
    summaries = load_summaries()
    session_id = resolve_session_id(args.session_id, summaries)
    entries = load_jsonl(session_id)
    calls = tool_entries(entries)

    writer = csv.DictWriter(sys.stdout, fieldnames=[
        "session_id", "ts", "tool_name", "category", "sensitivity",
        "flags", "is_suspicious", "arguments_json",
    ])
    writer.writeheader()
    for e in calls:
        cls = e.get("classification", {})
        writer.writerow({
            "session_id": session_id,
            "ts": e.get("ts", ""),
            "tool_name": e.get("tool_name", ""),
            "category": cls.get("category", ""),
            "sensitivity": cls.get("sensitivity", ""),
            "flags": "|".join(cls.get("flags", [])),
            "is_suspicious": cls.get("is_suspicious", False),
            "arguments_json": json.dumps(e.get("arguments", {})),
        })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="MCP Activity Monitor - Log Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List all sessions")

    p_show = sub.add_parser("show", help="Detailed breakdown of one session")
    p_show.add_argument("session_id")

    p_compare = sub.add_parser("compare", help="Compare two sessions side by side")
    p_compare.add_argument("session_a")
    p_compare.add_argument("session_b")

    p_flags = sub.add_parser("flags", help="View all flagged entries")
    p_flags.add_argument("session_id", nargs="?", default=None)

    p_export = sub.add_parser("export", help="Export session tool calls to CSV")
    p_export.add_argument("session_id")

    args = parser.parse_args()

    {
        "list": cmd_list,
        "show": cmd_show,
        "compare": cmd_compare,
        "flags": cmd_flags,
        "export": cmd_export,
    }[args.command](args)


if __name__ == "__main__":
    main()
