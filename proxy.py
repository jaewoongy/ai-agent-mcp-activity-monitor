#!/usr/bin/env python3
"""
MCP Activity Monitor Proxy

Sits transparently between Claude Desktop and a real MCP server.
Intercepts every JSON-RPC message over STDIO, classifies tool calls,
flags suspicious activity, and writes structured JSONL logs per session.

Usage:
  python proxy.py [--label <label>] -- <real_server_cmd> [args...]
  python proxy.py --label baseline -- npx -y @modelcontextprotocol/server-filesystem /tmp/sandbox
"""

import sys
import json
import os
import subprocess
import threading
import time
import datetime
import uuid
import re
import signal
import argparse
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOGS_DIR = Path(__file__).parent / "logs"

# Tool name -> (category, base_sensitivity)
TOOL_CATEGORIES = {
    # Filesystem reads
    "read_file": ("filesystem_read", "low"),
    "read_multiple_files": ("filesystem_read", "low"),
    "list_directory": ("filesystem_read", "low"),
    "directory_tree": ("filesystem_read", "low"),
    "search_files": ("filesystem_read", "low"),
    "get_file_info": ("filesystem_read", "low"),
    # Filesystem writes
    "write_file": ("filesystem_write", "medium"),
    "create_directory": ("filesystem_write", "low"),
    "move_file": ("filesystem_write", "medium"),
    "delete_file": ("filesystem_write", "high"),
    "delete_directory": ("filesystem_write", "high"),
    "edit_file": ("filesystem_write", "medium"),
    # Shell execution
    "run_command": ("shell_execution", "high"),
    "execute_command": ("shell_execution", "high"),
    "bash": ("shell_execution", "high"),
    "shell": ("shell_execution", "high"),
    "run_terminal_cmd": ("shell_execution", "high"),
    "execute_bash": ("shell_execution", "high"),
    # Network
    "fetch": ("network", "medium"),
    "http_request": ("network", "medium"),
    "web_fetch": ("network", "medium"),
    "curl": ("network", "high"),
    "download": ("network", "medium"),
    # Database
    "query": ("database", "medium"),
    "execute_query": ("database", "high"),
    "db_query": ("database", "medium"),
    # Memory / state
    "remember": ("memory", "low"),
    "recall": ("memory", "low"),
    "store": ("memory", "low"),
    # Code execution
    "run_code": ("code_execution", "high"),
    "execute_python": ("code_execution", "high"),
    "execute_javascript": ("code_execution", "high"),
    "eval": ("code_execution", "high"),
}

# Patterns that escalate a call to "suspicious"
SUSPICIOUS_PATTERNS = [
    # Path traversal / escape from sandbox
    (r"\.\./\.\./", "path_traversal"),
    (r"/etc/passwd", "sensitive_file_access"),
    (r"/etc/shadow", "sensitive_file_access"),
    (r"~/.ssh", "ssh_key_access"),
    (r"\.ssh/id_", "ssh_key_access"),
    (r"\.env", "env_file_access"),
    (r"/proc/", "proc_access"),
    (r"/sys/", "sys_access"),
    # Credentials
    (r"password", "credential_keyword"),
    (r"api_key", "credential_keyword"),
    (r"secret", "credential_keyword"),
    (r"token", "credential_keyword"),
    (r"private_key", "credential_keyword"),
    # Shell tricks
    (r";\s*rm\s+-rf", "destructive_shell"),
    (r"\$\(", "command_substitution"),
    (r"`[^`]+`", "command_substitution"),
    (r">\s*/dev/null", "output_suppression"),
    (r"curl\s+.*\|\s*sh", "remote_code_execution"),
    (r"wget\s+.*\|\s*sh", "remote_code_execution"),
    # Network exfiltration indicators
    (r"https?://(?!localhost|127\.0\.0\.1)", "external_network_call"),
]


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def classify_tool_call(tool_name: str, arguments: dict) -> dict:
    """Return classification dict for a tools/call invocation."""
    name_lower = tool_name.lower()
    category, sensitivity = TOOL_CATEGORIES.get(name_lower, ("unknown", "unknown"))

    flags = []
    args_str = json.dumps(arguments)

    for pattern, flag_name in SUSPICIOUS_PATTERNS:
        if re.search(pattern, args_str, re.IGNORECASE):
            flags.append(flag_name)

    # Escalate sensitivity based on flags
    if flags:
        if sensitivity in ("low", "unknown"):
            sensitivity = "medium"
        if any(f in flags for f in ("destructive_shell", "remote_code_execution",
                                     "ssh_key_access", "sensitive_file_access")):
            sensitivity = "high"

    is_suspicious = len(flags) > 0 or sensitivity == "high"

    return {
        "category": category,
        "sensitivity": sensitivity,
        "flags": flags,
        "is_suspicious": is_suspicious,
    }


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

class Session:
    def __init__(self, label: Optional[str]):
        self.session_id = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S") + "_" + uuid.uuid4().hex[:6]
        self.label = label or "unlabeled"
        self.started_at = datetime.datetime.utcnow().isoformat() + "Z"
        self.ended_at: Optional[str] = None

        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        self.log_path = LOGS_DIR / f"{self.session_id}.jsonl"
        self.summary_path = LOGS_DIR / f"{self.session_id}_summary.json"

        self._lock = threading.Lock()
        self._log_file = open(self.log_path, "w", buffering=1)

        self.stats = {
            "total_messages": 0,
            "tool_calls": 0,
            "suspicious_calls": 0,
            "categories": {},
            "flags": {},
        }

        # Write session header as first line
        self._write_entry({
            "type": "session_start",
            "session_id": self.session_id,
            "label": self.label,
            "started_at": self.started_at,
        })

    def _write_entry(self, entry: dict):
        with self._lock:
            self._log_file.write(json.dumps(entry) + "\n")

    def log_message(self, direction: str, msg: dict):
        """Log a raw JSON-RPC message. direction: 'client->server' or 'server->client'"""
        method = msg.get("method", "")
        entry = {
            "type": "message",
            "ts": datetime.datetime.utcnow().isoformat() + "Z",
            "direction": direction,
            "jsonrpc_id": msg.get("id"),
            "method": method,
        }

        self.stats["total_messages"] += 1

        if method == "tools/call":
            params = msg.get("params", {})
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            classification = classify_tool_call(tool_name, arguments)

            entry.update({
                "tool_name": tool_name,
                "arguments": arguments,
                "classification": classification,
            })

            self.stats["tool_calls"] += 1
            cat = classification["category"]
            self.stats["categories"][cat] = self.stats["categories"].get(cat, 0) + 1

            if classification["is_suspicious"]:
                self.stats["suspicious_calls"] += 1
                for flag in classification["flags"]:
                    self.stats["flags"][flag] = self.stats["flags"].get(flag, 0) + 1
                entry["SUSPICIOUS"] = True

        self._write_entry(entry)

    def log_tool_result(self, msg_id, result_content):
        """Log a tools/call response."""
        entry = {
            "type": "tool_result",
            "ts": datetime.datetime.utcnow().isoformat() + "Z",
            "jsonrpc_id": msg_id,
            "result_snippet": str(result_content)[:500],
        }
        self._write_entry(entry)

    def close(self):
        self.ended_at = datetime.datetime.utcnow().isoformat() + "Z"

        summary = {
            "session_id": self.session_id,
            "label": self.label,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "log_file": str(self.log_path),
            "stats": self.stats,
        }

        self._write_entry({"type": "session_end", **summary})
        self._log_file.flush()
        self._log_file.close()

        with open(self.summary_path, "w") as f:
            json.dump(summary, f, indent=2)

        print(f"\n[proxy] Session ended: {self.session_id}", file=sys.stderr)
        print(f"[proxy] Log:     {self.log_path}", file=sys.stderr)
        print(f"[proxy] Summary: {self.summary_path}", file=sys.stderr)
        print(f"[proxy] Stats:   {json.dumps(self.stats)}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Pending tool calls tracker (to correlate responses)
# ---------------------------------------------------------------------------

class PendingCalls:
    def __init__(self):
        self._lock = threading.Lock()
        self._pending: dict = {}  # id -> tool_name

    def register(self, msg_id, tool_name: str):
        with self._lock:
            self._pending[msg_id] = tool_name

    def pop(self, msg_id) -> Optional[str]:
        with self._lock:
            return self._pending.pop(msg_id, None)


# ---------------------------------------------------------------------------
# STDIO proxy loop
# ---------------------------------------------------------------------------

def forward_server_to_client(server_proc, session: Session, pending: PendingCalls):
    """Background thread: read server stdout, log responses, write to Claude."""
    for raw_line in server_proc.stdout:
        try:
            sys.stdout.buffer.write(raw_line)
            sys.stdout.buffer.flush()
        except BrokenPipeError:
            break

        line = raw_line.decode("utf-8", errors="replace").strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        msg_id = msg.get("id")
        if msg_id is not None and pending.pop(msg_id):
            result = msg.get("result", {})
            content = result.get("content", result)
            session.log_tool_result(msg_id, content)


def forward_stderr(server_proc):
    """Forward server stderr to our stderr."""
    for line in server_proc.stderr:
        sys.stderr.buffer.write(line)
        sys.stderr.buffer.flush()


def run_proxy(server_cmd: list, label: Optional[str]):
    session = Session(label)
    pending = PendingCalls()

    print(f"[proxy] Starting session {session.session_id} (label={session.label})", file=sys.stderr)
    print(f"[proxy] Real server: {' '.join(server_cmd)}", file=sys.stderr)
    print(f"[proxy] Log: {session.log_path}", file=sys.stderr)

    try:
        server_proc = subprocess.Popen(
            server_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as e:
        print(f"[proxy] ERROR: Could not start server: {e}", file=sys.stderr)
        session.close()
        sys.exit(1)

    t_stdout = threading.Thread(
        target=forward_server_to_client,
        args=(server_proc, session, pending),
        daemon=True,
    )
    t_stderr = threading.Thread(
        target=forward_stderr,
        args=(server_proc,),
        daemon=True,
    )
    t_stdout.start()
    t_stderr.start()

    def _shutdown(signum=None, frame=None):
        server_proc.terminate()
        try:
            server_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            server_proc.kill()
        session.close()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    # Main loop: read Claude's messages from stdin, log, forward to server
    try:
        for raw_line in sys.stdin.buffer:
            # Forward immediately to keep latency low
            try:
                server_proc.stdin.write(raw_line)
                server_proc.stdin.flush()
            except BrokenPipeError:
                break

            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue

            session.log_message("client->server", msg)

            # Register pending tool call so we can correlate the response
            if msg.get("method") == "tools/call":
                tool_name = msg.get("params", {}).get("name", "")
                pending.register(msg.get("id"), tool_name)

    except KeyboardInterrupt:
        pass
    finally:
        _shutdown()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="MCP Activity Monitor Proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--label", default=None, help="Session label (e.g. 'baseline', 'attack_prompt_injection')")
    parser.add_argument("server_cmd", nargs=argparse.REMAINDER, help="Real MCP server command (after --)")

    args = parser.parse_args()

    cmd = args.server_cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]

    if not cmd:
        parser.print_help()
        sys.exit(1)

    run_proxy(cmd, args.label)


if __name__ == "__main__":
    main()
