from pathlib import Path

from appsec.models import Dependency
from appsec.sbom import cyclonedx_sbom, sbom_json


def test_cyclonedx_sbom_includes_only_exact_versions_and_deduplicates(tmp_path: Path) -> None:
    dependencies = [
        Dependency(name="Requests", specifier="==2.32.0", source="uv.lock"),
        Dependency(name="requests", specifier="==2.32.0", source="requirements.txt"),
        Dependency(name="flask", specifier=">=3.0", source="pyproject.toml"),
    ]

    bom = cyclonedx_sbom(dependencies, tmp_path)

    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    components = bom["components"]
    assert isinstance(components, list)
    assert len(components) == 1
    assert components[0]["purl"] == "pkg:pypi/requests@2.32.0"
    assert bom["dependencies"][0]["dependsOn"] == ["pkg:pypi/requests@2.32.0"]


def test_sbom_json_is_valid_json(tmp_path: Path) -> None:
    output = sbom_json(
        [Dependency(name="urllib3", specifier="==2.2.0", source="uv.lock")],
        tmp_path,
    )
    assert '"bomFormat": "CycloneDX"' in output
