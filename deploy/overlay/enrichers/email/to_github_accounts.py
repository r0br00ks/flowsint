from typing import Any, Dict, List

from flowsint_enrichers import osint_http as oh
from flowsint_enrichers.osint_base import FetchEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.email import Email
from flowsint_types.social_account import SocialAccount


@flowsint_enricher
class EmailToGithubAccounts(FetchEnricher):
    """[GitHub] GitHub accounts tied to an email address, from public profiles and from commits authored with it (needs GITHUB_TOKEN on the container)."""

    InputType = Email
    OutputType = SocialAccount
    RELATIONSHIP = "HAS_ACCOUNT"
    SOURCE = "GitHub"

    @classmethod
    def name(cls) -> str:
        return "email_to_github_accounts"

    @classmethod
    def category(cls) -> str:
        return "Email"

    @classmethod
    def key(cls) -> str:
        return "email"

    def label_of(self, item) -> str:
        return str(item.email)

    async def fetch(self, item) -> Dict[str, Dict[str, Any]]:
        token = oh.env("GITHUB_TOKEN")
        if not token:
            raise oh.SourceError("GITHUB_TOKEN is not set on this container")
        h = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
        email = str(item.email)
        found: Dict[str, Dict[str, Any]] = {}
        users = await oh.get_json("https://api.github.com/search/users", params={"q": f"{email} in:email", "per_page": "10"}, headers=h)
        for u in users.get("items", []):
            found[u["login"]] = {"url": u["html_url"], "avatar": u.get("avatar_url"), "via": "public email on profile"}
        commits = await oh.get_json("https://api.github.com/search/commits", params={"q": f"author-email:{email}", "per_page": "20"}, headers=h)
        for c in commits.get("items", []):
            a = c.get("author") or {}
            if a.get("login"):
                found.setdefault(a["login"], {"url": a["html_url"], "avatar": a.get("avatar_url"), "via": "commit author email"})
        return found

    def build(self, item, data: Dict[str, Dict[str, Any]]) -> List[SocialAccount]:
        return [
            SocialAccount(id=f"github:{login}", username=login, profile_url=v["url"], profile_picture_url=v.get("avatar"), platform="GitHub", bio=v["via"])
            for login, v in sorted(data.items())
        ]


InputType = EmailToGithubAccounts.InputType
OutputType = EmailToGithubAccounts.OutputType
