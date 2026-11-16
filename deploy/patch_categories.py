"""Add the Cve, Finding and Technology types to the "Security & Access" group in the UI type picker.

Technology is not insertable by hand upstream, so the technology enrichers could only run on nodes
another enricher had created. Fails the build loudly if upstream changes the anchor line.
"""
import pathlib

p = pathlib.Path("/app/flowsint-core/src/flowsint_core/core/services/type_registry_service.py")
s = p.read_text()
anchor = '                    ("Weapon", "name", "weapon"),\n'
assert s.count(anchor) == 1, "upstream type_registry_service.py changed; review this patch"
extra = (("Cve", "cve_id"), ("Finding", "title"), ("Technology", "name"))
add = anchor + "".join(f'                    ("{t}", "{k}", None),\n' for t, k in extra)
p.write_text(s.replace(anchor, add))
print("patched", p)
