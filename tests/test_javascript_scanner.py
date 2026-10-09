from pathlib import Path

from appsec.models import Severity
from appsec.scanners.javascript import JavaScriptSecurityScanner


def write_source(tmp_path: Path, name: str, source: str) -> None:
    (tmp_path / name).write_text(source, encoding="utf-8")


def test_detects_eval_and_new_function(tmp_path: Path) -> None:
    write_source(
        tmp_path,
        "sample.ts",
        "const value = eval(input);\nconst fn = new Function(input);\n",
    )
    findings = JavaScriptSecurityScanner().scan(tmp_path)
    assert [finding.rule_id for finding in findings] == ["JSSEC-001", "JSSEC-002"]
    assert all(finding.severity is Severity.HIGH for finding in findings)


def test_detects_shell_and_dom_sinks(tmp_path: Path) -> None:
    write_source(tmp_path, "server.js", "exec(command);\nelement.innerHTML = html;\n")
    findings = JavaScriptSecurityScanner().scan(tmp_path)
    assert {finding.rule_id for finding in findings} == {"JSSEC-003", "JSSEC-004"}


def test_detects_react_dangerously_set_inner_html(tmp_path: Path) -> None:
    write_source(
        tmp_path,
        "component.jsx",
        "<div dangerouslySetInnerHTML={{{__html: value}}} />\n",
    )
    findings = JavaScriptSecurityScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule_id == "JSSEC-005"
    assert findings[0].cwe == "CWE-79"


def test_skips_node_modules(tmp_path: Path) -> None:
    dependency = tmp_path / "node_modules" / "third-party.js"
    dependency.parent.mkdir()
    dependency.write_text("eval(input)\n", encoding="utf-8")
    assert JavaScriptSecurityScanner().scan(tmp_path) == []
