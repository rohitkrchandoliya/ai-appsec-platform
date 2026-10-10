"""CycloneDX SBOM generation from exact-pinned Python dependencies."""

import json
import re
from pathlib import Path
from urllib.parse import quote

from appsec.models import Dependency


def _exact_version(specifier: str) -> str | None:
    value = specifier.strip()
    if not value.startswith("=="):
        return None
    version = value[2:].strip()
    if not version or "," in version or " " in version:
        return None
    return version


def _purl_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def cyclonedx_sbom(dependencies: list[Dependency], root: Path) -> dict[str, object]:
    """Build a CycloneDX 1.5 BOM; omit dependencies without exact versions."""
    components: list[dict[str, str]] = []
    references: list[str] = []
    seen: set[str] = set()

    for dependency in dependencies:
        version = _exact_version(dependency.specifier)
        if version is None:
            continue
        purl = f"pkg:pypi/{quote(_purl_name(dependency.name), safe='-')}@{quote(version, safe='.-_+')}"
        if purl in seen:
            continue
        seen.add(purl)
        references.append(purl)
        components.append(
            {
                "type": "library",
                "bom-ref": purl,
                "name": dependency.name,
                "version": version,
                "purl": purl,
            }
        )

    root_ref = "appsec-root"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": root.resolve().name or "application",
                "version": "0.1.0",
            }
        },
        "components": components,
        "dependencies": [
            {"ref": root_ref, "dependsOn": references},
            *({"ref": reference, "dependsOn": []} for reference in references),
        ],
    }


def sbom_json(dependencies: list[Dependency], root: Path) -> str:
    """Serialize a CycloneDX SBOM as stable, indented JSON."""
    return json.dumps(cyclonedx_sbom(dependencies, root), indent=2, sort_keys=True)
