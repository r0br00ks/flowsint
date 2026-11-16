"""Add the Cve and Finding types to the "Security & Access" group in the UI type picker.

Fails the build loudly if upstream changes the anchor line.
"""
import pathlib

p = pathlib.Path("/app/flowsint-core/src/flowsint_core/core/services/type_registry_service.py")
s = p.read_text()
anchor = '                    ("Weapon", "name", "weapon"),\n'
assert s.count(anchor) == 1, "upstream type_registry_service.py changed; review this patch"
add = anchor + '                    ("Cve", "cve_id", None),\n                    ("Finding", "title", None),\n'
p.write_text(s.replace(anchor, add))
print("patched", p)
