from pathlib import Path

from appsec.scanners.dependencies import discover_dependencies, parse_pyproject, parse_requirements


def test_parses_pep621_dependencies(tmp_path: Path) -> None:
    path = tmp_path / "pyproject.toml"
    path.write_text(
        """[project]
dependencies = ["requests>=2.31,<3", "pydantic>=2.9,<3"]

[project.optional-dependencies]
dev = ["pytest>=8,<9"]
""",
        encoding="utf-8",
    )
    dependencies = parse_pyproject(path)
    assert [(item.name, item.specifier) for item in dependencies] == [
        ("requests", ">=2.31,<3"),
        ("pydantic", ">=2.9,<3"),
        ("pytest", ">=8,<9"),
    ]


def test_parses_requirements_and_ignores_options(tmp_path: Path) -> None:
    path = tmp_path / "requirements.txt"
    path.write_text(
        """# comment
requests==2.32.0
-r base.txt
--index-url https://example.invalid/simple
urllib3>=2.0
""",
        encoding="utf-8",
    )
    dependencies = parse_requirements(path)
    assert [(item.name, item.specifier) for item in dependencies] == [
        ("requests", "==2.32.0"),
        ("urllib3", ">=2.0"),
    ]


def test_discovers_supported_manifests(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["requests>=2.0"]\n',
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("urllib3==2.2.0\n", encoding="utf-8")
    dependencies = discover_dependencies(tmp_path)
    assert {item.name for item in dependencies} == {"requests", "urllib3"}
