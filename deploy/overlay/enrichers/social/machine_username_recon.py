from typing import Any, Dict, List

from flowsint_enrichers.machine_base import MachineEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.username import Username


@flowsint_enricher
class MachineUsernameRecon(MachineEnricher):
    """[Machine] Recon of a username: infostealer exposure and, optionally, Maigret and Sherlock account searches across hundreds of sites (these take minutes and can be rate-limited)."""

    InputType = Username
    OutputType = Username
    ROOT_STEPS = ["username_to_device_hudsonrock"]
    RULES: Dict[str, List[str]] = {}

    @classmethod
    def name(cls) -> str:
        return "machine_username_recon"

    @classmethod
    def category(cls) -> str:
        return "Username"

    @classmethod
    def key(cls) -> str:
        return "value"

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return super().get_params_schema() + [
            {
                "name": "include_site_search",
                "type": "select",
                "description": "Run Maigret and Sherlock to find accounts on other sites. Slow, and the username is searched on many third-party sites.",
                "required": False,
                "default": "yes",
                "options": [{"label": "Yes", "value": "yes"}, {"label": "No", "value": "no"}],
            }
        ]

    def root_steps(self) -> List[str]:
        steps = list(self.ROOT_STEPS)
        if str(self.params.get("include_site_search") or "yes") == "yes":
            steps += ["username_to_socials_maigret", "username_to_socials_sherlock"]
        return steps


InputType = MachineUsernameRecon.InputType
OutputType = MachineUsernameRecon.OutputType
