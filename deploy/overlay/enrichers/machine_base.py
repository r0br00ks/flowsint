"""Machines: one enricher that runs a whole investigation, the way a Maltego machine does.

A machine starts from the node it is run on and applies a list of enrichers (ROOT_STEPS). Every entity those
produce is then fed to the enrichers listed for its type in RULES, level by level, until max_depth. Each sub-enricher
writes its own nodes and relationships to the graph exactly as if it had been run by hand, so a machine's result
is a normal graph.

Guard rails: a depth limit, a cap on how many new entities per type move to the next level, de-duplication, and an
optional filter that skips CDN (Cloudflare) addresses, which describe the CDN and not the target. Active
enrichers (nmap, wafw00f) are never in a machine's lists; they only run when someone sets authorized=yes by hand.
"""

import asyncio
import ipaddress
import json
from typing import Any, Dict, List, Optional, Tuple

from flowsint_core.core.logger import Logger
from flowsint_enrichers import osint_http as oh
from flowsint_enrichers.osint_base import ParamsEnricher
from flowsint_enrichers.registry import ENRICHER_REGISTRY

# Cloudflare's published ranges, used only if the live list cannot be fetched.
CLOUDFLARE_FALLBACK = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]

IP_STEPS = [
    "ip_to_asn_ripestat", "ip_to_organization_rdap", "ip_to_ports_internetdb", "ip_to_vulns_internetdb",
    "ip_to_technologies_internetdb", "ip_to_hostnames_internetdb", "ip_to_greynoise", "ip_to_otx",
    "ip_to_blacklist_abusebox", "ip_to_ports_shodan",
]
WEBSITE_STEPS = ["website_to_security_headers", "website_to_tls_sslscan", "website_to_technologies_whatweb", "website_to_wallets", "website_to_emails", "website_to_phones"]
SHARED_RULES: Dict[str, List[str]] = {
    "Ip": IP_STEPS,
    "Website": WEBSITE_STEPS,
    "Technology": ["technology_to_cves_hexbrain"],
    "Cve": ["cve_to_findings_defectdojo", "cve_to_epss_kev"],
    "Email": ["email_to_username", "email_to_gravatar", "email_to_github_accounts", "email_to_pgp_identities"],
}
# Outputs of these are leaves: not fed forward (archived URLs and code hits are not live targets).
NO_FOLLOW = {"domain_to_tld_variants", "domain_to_wayback_urls", "domain_to_github_code", "ip_to_ports_internetdb", "ip_to_ports_shodan"}


async def cdn_networks() -> List[Any]:
    nets: List[str] = []
    try:
        for ver in ("ips-v4", "ips-v6"):
            r = await oh.get(f"https://www.cloudflare.com/{ver}", timeout=10.0, retries=1)
            nets += [x.strip() for x in r.text.split() if "/" in x]
    except Exception:
        nets = []
    return [ipaddress.ip_network(n) for n in (nets or CLOUDFLARE_FALLBACK)]


class MachineEnricher(ParamsEnricher):
    """Not registered itself; concrete machines subclass it and add @flowsint_enricher."""

    ROOT_STEPS: List[str] = []
    RULES: Dict[str, List[str]] = {}
    # Per-step parameter overrides, e.g. keep archived-URL and code-search results small inside a machine.
    STEP_PARAMS: Dict[str, Dict[str, str]] = {}

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {"name": "max_depth", "type": "string", "description": "How many levels of enrichment to follow from the starting node. 4 reaches CVEs and your own findings for them.", "required": False, "default": "4"},
            {"name": "max_per_type", "type": "string", "description": "At most this many new entities of each type move on to the next level.", "required": False, "default": "12"},
            {
                "name": "skip_cdn_ips",
                "type": "select",
                "description": "Skip Cloudflare addresses: they describe the CDN, not the target.",
                "required": False,
                "default": "yes",
                "options": [{"label": "Yes", "value": "yes"}, {"label": "No", "value": "no"}],
            },
        ]

    def root_steps(self) -> List[str]:
        return list(self.ROOT_STEPS)

    def rules(self) -> Dict[str, List[str]]:
        return self.RULES

    @staticmethod
    def _key(obj: Any) -> str:
        return type(obj).__name__ + json.dumps(obj.model_dump(mode="json", exclude={"nodeLabel"}), sort_keys=True, default=str)

    async def _run_step(self, sem: asyncio.Semaphore, name: str, item: Any) -> Tuple[str, Any, List[Any]]:
        async with sem:
            try:
                sub = ENRICHER_REGISTRY.get_enricher(name, self.sketch_id, self.scan_id, vault=self.vault, params=dict(self.STEP_PARAMS.get(name, {})))
                raw = await sub.execute([item.model_dump(mode="json")])
            except Exception as e:  # a failing step must not stop the machine
                Logger.error(self.sketch_id, {"message": f"[machine] {name} failed: {e}"})
                return name, item, []
        out_cls = getattr(sub, "OutputType", None)
        outs: List[Any] = []
        for r in raw or []:
            if out_cls is not None and isinstance(r, out_cls):
                outs.append(r)
            elif isinstance(r, dict) and out_cls is not None:
                try:
                    outs.append(out_cls.model_validate(r))
                except Exception:
                    pass
        return name, item, outs

    async def run_machine(self, root: Any) -> Dict[str, Any]:
        max_depth = int(float(self.params.get("max_depth") or 4))
        cap = int(float(self.params.get("max_per_type") or 12))
        skip_cdn = str(self.params.get("skip_cdn_ips") or "yes") == "yes"
        nets = await cdn_networks() if skip_cdn else []
        sem = asyncio.Semaphore(4)
        rules = self.rules()
        visited = {self._key(root)}
        done_tasks = set()
        frontier: List[Tuple[Any, List[str]]] = [(root, self.root_steps())]
        stats = {"steps": 0, "entities": 0, "skipped_cdn": 0, "levels": 0}
        for depth in range(max_depth):
            tasks = []
            for item, names in frontier:
                for n in names:
                    tk = (n, self._key(item))
                    if tk not in done_tasks:
                        done_tasks.add(tk)
                        tasks.append(self._run_step(sem, n, item))
            if not tasks:
                break
            stats["levels"] = depth + 1
            results = await asyncio.gather(*tasks)
            stats["steps"] += len(results)
            fresh: Dict[str, List[Any]] = {}
            for name, item, outs in results:
                if name in NO_FOLLOW:
                    continue
                for o in outs:
                    k = self._key(o)
                    if k in visited:
                        continue
                    visited.add(k)
                    tname = type(o).__name__
                    if tname == "Ip" and nets:
                        try:
                            ip = ipaddress.ip_address(o.address)
                            if any(ip in n for n in nets):
                                stats["skipped_cdn"] += 1
                                continue
                        except ValueError:
                            continue
                    if len(fresh.setdefault(tname, [])) < cap:
                        fresh[tname].append(o)
            stats["entities"] += sum(len(v) for v in fresh.values())
            frontier = [(o, rules.get(t, [])) for t, items in fresh.items() for o in items if rules.get(t)]
        return stats

    async def scan(self, data: List[Any]) -> List[Dict[str, Any]]:
        out = []
        for root in data:
            stats = await self.run_machine(root)
            out.append({"item": root, "stats": stats})
        return out

    def postprocess(self, results: List[Dict[str, Any]], input_data: Optional[List[Any]] = None) -> List[Any]:
        for r in results:
            s = r["stats"]
            self.log_graph_message(
                f"Machine {self.name()} finished on {getattr(r['item'], 'nodeLabel', r['item'])}: {s['steps']} enrichers run over {s['levels']} level(s), "
                f"{s['entities']} entities followed, {s['skipped_cdn']} CDN address(es) skipped."
            )
        return []  # every sub-enricher already wrote its own nodes and relationships
