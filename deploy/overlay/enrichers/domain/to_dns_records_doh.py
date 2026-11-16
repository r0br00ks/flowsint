from typing import Any, Dict, List

from flowsint_enrichers import dns_doh
from flowsint_enrichers.osint_base import FetchEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.dns_record import DNSRecord
from flowsint_types.domain import Domain

RECORD_TYPES = ["A", "AAAA", "NS", "MX", "TXT", "CAA", "SOA", "CNAME"]


@flowsint_enricher
class DomainToDnsRecordsDoh(FetchEnricher):
    """[DNS over HTTPS] A, AAAA, NS, MX, TXT, CAA, SOA and CNAME records of a domain, no key needed."""

    InputType = Domain
    OutputType = DNSRecord
    RELATIONSHIP = "HAS_DNS_RECORD"
    SOURCE = "DNS"

    @classmethod
    def name(cls) -> str:
        return "domain_to_dns_records_doh"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    def label_of(self, item) -> str:
        return item.domain

    async def fetch(self, item) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for t in RECORD_TYPES:
            recs, _ = await dns_doh.query(item.domain, t)
            out.extend(r for r in recs if r["type"] == t)
        return out

    def build(self, item, data: List[Dict[str, Any]]) -> List[DNSRecord]:
        records = []
        for r in data:
            value = r["data"]
            priority = None
            if r["type"] == "MX":
                parts = value.split(None, 1)
                if len(parts) == 2 and parts[0].isdigit():
                    priority, value = int(parts[0]), parts[1]
            if r["type"] == "TXT":
                value = dns_doh.unquote_txt(value)
            records.append(
                DNSRecord(
                    value=f"{item.domain} {r['type']} {value}"[:500],
                    record_type=r["type"],
                    ttl=r.get("ttl"),
                    priority=priority,
                    source="Cloudflare DoH",
                    description=value[:500],
                )
            )
        return records


InputType = DomainToDnsRecordsDoh.InputType
OutputType = DomainToDnsRecordsDoh.OutputType
