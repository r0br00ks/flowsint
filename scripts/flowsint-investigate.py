#!/usr/bin/env python3
"""Investigate a target with Flowsint from the command line and print a Markdown report.

    export FLOWSINT_URL=http://100.93.251.35:2920
    export FLOWSINT_EMAIL=you@example.com FLOWSINT_PASSWORD=...      # or FLOWSINT_TOKEN=<jwt>
    python flowsint-investigate.py techbrooks.ca
    python flowsint-investigate.py 66.29.141.57 --out ip-report.md
    python flowsint-investigate.py someone@example.com --investigation <uuid> --sketch <uuid>

It detects what the target is (domain, IP, email, username), creates an investigation and sketch unless you name
existing ones, adds the target as a node, launches the matching machine (machine_domain_recon, machine_ip_recon,
machine_email_recon, machine_username_recon), waits for it, then reads the graph back and summarises it.
Machines are passive: nmap and wafw00f are never started from here. Only investigate targets you are authorised to.
Standard library only.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

MACHINES = {"Domain": "machine_domain_recon", "Ip": "machine_ip_recon", "Email": "machine_email_recon", "Username": "machine_username_recon"}
SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Api:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.token = ""

    def call(self, method: str, path: str, body=None, form=None):
        data, headers = None, {"Accept": "application/json"}
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            detail = e.read(400).decode(errors="replace")
            raise SystemExit(f"{method} {path} -> HTTP {e.code}: {detail}")

    def login(self):
        token = os.environ.get("FLOWSINT_TOKEN")
        if token:
            self.token = token
            return
        email, pw = os.environ.get("FLOWSINT_EMAIL"), os.environ.get("FLOWSINT_PASSWORD")
        if not (email and pw):
            raise SystemExit("set FLOWSINT_TOKEN, or FLOWSINT_EMAIL and FLOWSINT_PASSWORD")
        self.token = self.call("POST", "/api/auth/token", form={"username": email, "password": pw})["access_token"]


def summarise(graph: dict, target: str) -> str:
    nodes = graph.get("nds", [])
    rels = graph.get("rls", [])
    by_type = {}
    for n in nodes:
        by_type.setdefault(n.get("nodeType", "?"), []).append(n)

    def props(n):
        return n.get("nodeProperties") or {}

    lines = [f"# Flowsint report: {target}", "", f"{len(nodes)} entities and {len(rels)} relationships.", "", "## Entities by type", ""]
    for t, items in sorted(by_type.items(), key=lambda kv: -len(kv[1])):
        lines.append(f"- {t}: {len(items)}")

    findings = sorted(by_type.get("finding", []), key=lambda n: SEVERITY.get(str(props(n).get("severity", "")).lower(), 9))
    if findings:
        lines += ["", "## Findings", ""]
        for n in findings[:40]:
            p = props(n)
            lines.append(f"- [{p.get('severity', '?')}] {p.get('title') or n.get('nodeLabel')}")
    cves = sorted(by_type.get("cve", []), key=lambda n: -(props(n).get("cvss") or 0))
    if cves:
        lines += ["", "## CVEs (highest CVSS first)", ""]
        for n in cves[:25]:
            p = props(n)
            lines.append(f"- {p.get('cve_id')} (CVSS {p.get('cvss', '?')}) {p.get('name') or ''}".rstrip())
    for label, key, field in (("Domains and subdomains", "domain", "domain"), ("IP addresses", "ip", "address"), ("Open ports", "openport", "endpoint"), ("Technologies", "technology", "nodeLabel")):
        items = by_type.get(key, [])
        if items:
            lines += ["", f"## {label} ({len(items)})", ""]
            for n in items[:50]:
                lines.append(f"- {props(n).get(field) or n.get('nodeLabel')}")
    rep = by_type.get("reputationscore", [])
    if rep:
        lines += ["", "## Reputation", ""]
        for n in rep:
            p = props(n)
            lines.append(f"- {p.get('entity_id')}: {p.get('score_type')} score {p.get('score')} ({p.get('provider')})")
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target")
    ap.add_argument("--url", default=os.environ.get("FLOWSINT_URL", "http://100.93.251.35:2920"))
    ap.add_argument("--investigation", help="existing investigation id (needs --sketch too)")
    ap.add_argument("--sketch", help="existing sketch id")
    ap.add_argument("--wait", type=int, default=600, help="seconds to wait for the machine (default 600)")
    ap.add_argument("--out", help="also write the report to this file")
    ap.add_argument("--params", default="{}", help='machine parameters as JSON, e.g. {"max_depth":"2","include_spiderfoot":"yes"}')
    a = ap.parse_args()

    api = Api(a.url)
    api.login()
    det = api.call("POST", "/api/types/detect", {"text": a.target})
    ttype = det.get("type")
    machine = MACHINES.get(ttype)
    if not machine:
        raise SystemExit(f"'{a.target}' was detected as {ttype}; there is no machine for that type")
    primary = next((f["name"] for f in det.get("fields", []) if f.get("primary")), ttype.lower())
    print(f"target {a.target!r} is a {ttype}; machine {machine}", file=sys.stderr)

    if a.sketch:
        sketch_id = a.sketch
    else:
        inv = api.call("POST", "/api/investigations/create", {"name": a.target, "description": f"Automated investigation of {a.target}"})
        sk = api.call("POST", "/api/sketches/create", {"title": "Machine run", "description": machine, "investigation_id": inv["id"]})
        sketch_id = sk["id"]
        print(f"created investigation {inv['id']} and sketch {sketch_id}", file=sys.stderr)

    node = {"id": None, "nodeLabel": a.target, "nodeType": ttype.lower(), "nodeMetadata": {}, "nodeProperties": {primary: a.target}}
    node_id = api.call("POST", f"/api/sketches/{sketch_id}/nodes/add", node)["node"]["id"]
    task = api.call("POST", f"/api/enrichers/{machine}/launch", {"node_ids": [node_id], "sketch_id": sketch_id, "params": json.loads(a.params)})["id"]
    print(f"launched {machine} as task {task}; waiting up to {a.wait}s", file=sys.stderr)

    deadline = time.time() + a.wait
    status = ""
    while time.time() < deadline:
        time.sleep(5)
        status = str(api.call("GET", f"/api/scans/{task}").get("status", "")).lower()
        if status in ("completed", "failed", "error"):
            break
    print(f"machine status: {status or 'unknown'}", file=sys.stderr)

    report = summarise(api.call("GET", f"/api/sketches/{sketch_id}/graph"), a.target)
    print(report)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(report)


if __name__ == "__main__":
    main()
