"""PGP key-server pivots: Maltego's "To Email Addresses [PGP]" and "To Person [PGP]".

A PGP key lists the names and email addresses its owner attached to it. Searching a public key server by email, domain or
name therefore reveals other addresses and the real name behind an address. Two servers are asked and the results merged
(keyserver.ubuntu.com and pgpkeys.eu hold different key sets). Plain GET requests to public servers; the only thing sent is
the search term.
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, unquote

import httpx

from flowsint_core.core.logger import Logger
from flowsint_enrichers import osint_http as oh
from flowsint_enrichers.osint_base import ParamsEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.email import Email
from flowsint_types.individual import Individual

SERVERS = ["https://keyserver.ubuntu.com", "https://pgpkeys.eu"]
EMAIL_IN_UID = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}")


async def search(term: str) -> Dict[str, Any]:
    """Machine-readable index from each server. 404 means no key; a 5xx usually means too many keys matched the term."""
    keys: Dict[str, Dict[str, Any]] = {}
    notes: List[str] = []
    async with httpx.AsyncClient(timeout=40.0, follow_redirects=True, headers={"User-Agent": oh.USER_AGENT}) as c:
        for s in SERVERS:
            try:
                r = await c.get(f"{s}/pks/lookup?op=index&options=mr&search={quote(term)}")
            except httpx.HTTPError as e:
                notes.append(f"{s.split('//')[1]}: unreachable ({type(e).__name__})")
                continue
            if r.status_code == 404:
                continue
            if r.status_code != 200:
                notes.append(f"{s.split('//')[1]}: HTTP {r.status_code} (too many keys match this search, or the server failed)")
                continue
            cur: Optional[Dict[str, Any]] = None
            for line in r.text.splitlines():
                p = line.split(":")
                if p[0] == "pub" and len(p) >= 2:
                    flags = p[6] if len(p) > 6 else ""
                    cur = None if ("r" in flags or "d" in flags) else keys.setdefault(p[1].upper(), {"created": p[4] if len(p) > 4 else "", "uids": []})
                elif p[0] == "uid" and cur is not None and len(p) >= 2:
                    flags = p[4] if len(p) > 4 else ""
                    uid = unquote(p[1])
                    if "r" not in flags and uid not in cur["uids"]:
                        cur["uids"].append(uid)
    return {"keys": keys, "notes": notes}


def parse_uid(uid: str) -> Tuple[str, List[str]]:
    """(name, emails) from 'Name (comment) <a@b.c>' or 'a@b.c <Name>'."""
    emails = [e.lower() for e in EMAIL_IN_UID.findall(uid)]
    name = EMAIL_IN_UID.sub(" ", uid)
    name = re.sub(r"\([^)]*\)", " ", name).replace("<", " ").replace(">", " ")
    return re.sub(r"\s+", " ", name).strip(" \"'"), emails


class _Pgp(ParamsEnricher):
    RELATIONSHIP = "SAME_PGP_KEY"
    SOURCE = "PGP key servers"
    MAX_KEYS = 60

    def term_of(self, item) -> str:
        raise NotImplementedError

    def wanted(self, email: str, item) -> bool:
        return True

    def label_of(self, item) -> str:
        return self.term_of(item)

    async def scan(self, data: List[Any]) -> List[Dict[str, Any]]:
        out = []
        for item in data:
            if not self.term_of(item).strip():
                Logger.warn(self.sketch_id, {"message": "[PGP] nothing to search for on this node."})
                out.append({"item": item, "res": None, "ok": False})
                continue
            try:
                out.append({"item": item, "res": await search(self.term_of(item)), "ok": True})
            except Exception as e:
                Logger.error(self.sketch_id, {"message": f"[PGP] {self.label_of(item)} failed: {e}"})
                out.append({"item": item, "res": None, "ok": False})
        return out

    def postprocess(self, results: List[Dict[str, Any]], input_data: Optional[List[Any]] = None) -> List[Any]:
        output: List[Any] = []
        for r in results:
            if not r["ok"]:
                continue
            item, res = r["item"], r["res"]
            for n in res["notes"]:
                Logger.warn(self.sketch_id, {"message": f"[PGP] {self.label_of(item)}: {n}"})
            emails: Dict[str, Email] = {}
            people: Dict[str, Individual] = {}
            pairs: List[Tuple[Individual, Email]] = []
            for fp, key in list(res["keys"].items())[: self.MAX_KEYS]:
                key_people, key_emails = [], []
                for uid in key["uids"]:
                    name, addrs = parse_uid(uid)
                    for a in addrs:
                        if self.wanted(a, item) and a not in emails:
                            try:
                                emails[a] = Email(email=a)
                            except Exception:
                                continue
                        if a in emails:
                            key_emails.append(emails[a])
                    if name.lower() == self.term_of(item).lower():
                        continue  # the searched person themself
                    if len(name.split()) >= 2 and name.lower() not in people:
                        first, _, last = name.partition(" ")
                        people[name.lower()] = Individual(full_name=name, first_name=first, last_name=last, source="PGP key server", notes=f"Name on PGP key {fp} (created {key['created'] or 'unknown'}). Matched by the key's own text, so check it is the same person.")
                    if len(name.split()) >= 2:
                        key_people.append(people[name.lower()])
                pairs += [(p, e) for p in key_people for e in key_emails]
            self.create_node(item)
            made = 0
            for e in emails.values():
                if getattr(item, "email", None) and str(item.email).lower() == str(e.email).lower():
                    continue
                self.create_node(e)
                self.create_relationship(item, e, self.RELATIONSHIP)
                output.append(e)
                made += 1
            for p in people.values():
                self.create_node(p)
                self.create_relationship(item, p, "HAS_PGP_NAME")
                output.append(p)
            for p, e in {(p.nodeLabel, e.nodeLabel): (p, e) for p, e in pairs}.values():
                if not (getattr(item, "email", None) and str(item.email).lower() == str(e.email).lower()):
                    self.create_relationship(p, e, "HAS_EMAIL")
            self.log_graph_message(f"{self.label_of(item)} -> {made} email address(es) and {len(people)} name(s) from {len(res['keys'])} PGP key(s)." + (f" {len(res['notes'])} server(s) refused or failed the search (see the log), so the result may be incomplete." if res["notes"] else ""))
        return output


@flowsint_enricher
class EmailToPgpIdentities(_Pgp):
    """[PGP key servers] Other email addresses and the real name attached to the same PGP keys as this address (Maltego: To Email Addresses [PGP] / To Person [PGP]). Public key servers; only the address is sent."""

    InputType = Email
    OutputType = Email

    @classmethod
    def name(cls) -> str:
        return "email_to_pgp_identities"

    @classmethod
    def category(cls) -> str:
        return "Email"

    @classmethod
    def key(cls) -> str:
        return "email"

    def term_of(self, item) -> str:
        return str(item.email)


@flowsint_enricher
class DomainToEmailsPgp(_Pgp):
    """[PGP key servers] Email addresses and names on PGP keys that mention this domain (Maltego: To Email Addresses [PGP] from a domain). The key servers refuse the search when too many keys match, so very large domains return nothing."""

    InputType = Domain
    OutputType = Email

    @classmethod
    def name(cls) -> str:
        return "domain_to_emails_pgp"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    RELATIONSHIP = "HAS_PGP_EMAIL"

    def term_of(self, item) -> str:
        return item.domain

    def wanted(self, email: str, item) -> bool:
        d = item.domain.lower()
        host = email.split("@", 1)[1]
        return host == d or host.endswith("." + d)


@flowsint_enricher
class IndividualToEmailsPgp(_Pgp):
    """[PGP key servers] Email addresses on PGP keys carrying this person's name (Maltego: To Email Addresses [PGP] from a person). Matches by name only, so common names give other people's keys, and the key servers refuse a search when too many keys match."""

    InputType = Individual
    OutputType = Email
    RELATIONSHIP = "HAS_PGP_EMAIL"

    @classmethod
    def name(cls) -> str:
        return "individual_to_emails_pgp"

    @classmethod
    def category(cls) -> str:
        return "Individual"

    @classmethod
    def key(cls) -> str:
        return "full_name"

    def term_of(self, item) -> str:
        return item.full_name or f"{item.first_name or ''} {item.last_name or ''}".strip()


InputType = EmailToPgpIdentities.InputType
OutputType = EmailToPgpIdentities.OutputType
