"""Python dependency inventory parsing."""

from pathlib import Path

import re
import tomllib

from appsec.models import Dependency


_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*(.*)$")


def parse_requirements(path: Path) -> list[Dependency]:
    """Parse a requirements-style file without resolving or installing packages."""
    dependencies: list[Dependency] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return dependencies

    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-r ", "--", "git+", "http:", "https:")):
            continue
        match = _REQUIREMENT.match(line)
        if match:
            dependencies.append(
                Dependency(name=match.group(1), specifier=match.group(2).strip(), source=str(path))
            )
    return dependencies


def parse_pyproject(path: Path) -> list[Dependency]:
    """Parse PEP 621 project dependencies and optional dependency groups."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return []

    project = data.get("project", {})
    if not isinstance(project, dict):
        return []

    values: list[str] = []
    dependencies = project.get("dependencies", [])
    if isinstance(dependencies, list):
        values.extend(item for item in dependencies if isinstance(item, str))

    optional = project.get("optional-dependencies", {})
    if isinstance(optional, dict):
        for group in optional.values():
            if isinstance(group, list):
                values.extend(item for item in group if isinstance(item, str))

    return [_parse_requirement(value, path) for value in values if _parse_requirement(value, path)]


def _parse_requirement(value: str, path: Path) -> Dependency | None:
    match = _REQUIREMENT.match(value.strip())
    if not match:
        return None
    return Dependency(name=match.group(1), specifier=match.group(2).strip(), source=str(path))


def discover_dependencies(root: Path) -> list[Dependency]:
    """Discover supported Python dependency manifests below ROOT."""
    dependencies: list[Dependency] = []
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        dependencies.extend(parse_pyproject(pyproject))

    for filename in ("requirements.txt", "requirements-dev.txt", "requirements-test.txt"):
        path = root / filename
        if path.is_file():
            dependencies.extend(parse_requirements(path))

    return dependencies
