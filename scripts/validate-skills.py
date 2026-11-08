#!/usr/bin/env python3
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
LINK_RE = re.compile(r"\[[^]]+\]\(([^)]+)\)")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    problems: list[str] = []
    skills = sorted((root / "skills").glob("*/SKILL.md"))
    expected = {
        "homelab-bootstrap",
        "homelab-borg-backup",
        "homelab-maintenance",
        "homelab-mcp-connector",
        "homelab-oauth-relay",
        "homelab-service-catalog",
        "homelab-service-ingress",
        "homelab-troubleshooter",
    }
    found = {path.parent.name for path in skills}
    if found != expected:
        problems.append(
            f"skill set mismatch: missing={sorted(expected - found)}, unexpected={sorted(found - expected)}"
        )
    with tempfile.TemporaryDirectory() as temp_dir:
        install_root = Path(temp_dir) / "skills"
        for skill_path in skills:
            folder = skill_path.parent
            text = skill_path.read_text()
            if len(text.splitlines()) > 500:
                problems.append(f"{skill_path}: exceeds 500 lines")
            if not text.startswith("---\n") or "\n---\n" not in text[4:]:
                problems.append(f"{skill_path}: invalid frontmatter delimiters")
                continue
            _, frontmatter, body = text.split("---\n", 2)
            metadata = yaml.safe_load(frontmatter)
            name = metadata.get("name", "")
            description = metadata.get("description", "")
            if name != folder.name or not NAME_RE.fullmatch(name) or len(name) > 64:
                problems.append(f"{skill_path}: invalid or mismatched name")
            if not description or len(description) > 1024 or "Use when" not in description:
                problems.append(f"{skill_path}: description lacks valid Use when trigger")
            if "## Gotchas" not in body or "Copy and track:" not in body or "## Validation loop" not in body:
                problems.append(f"{skill_path}: missing workflow quality section")
            linked = {target for target in LINK_RE.findall(body) if not target.startswith(("http://", "https://"))}
            for target in linked:
                if not (folder / target).is_file():
                    problems.append(f"{skill_path}: missing linked file {target}")
            for reference in folder.glob("references/*"):
                relative = reference.relative_to(folder).as_posix()
                if relative not in linked:
                    problems.append(f"{skill_path}: unlinked reference {relative}")
            for script in folder.glob("scripts/*"):
                if not script.stat().st_mode & 0o111:
                    problems.append(f"{skill_path}: script is not executable: {script.name}")
                command = (
                    [sys.executable, str(script), "--help"]
                    if script.suffix == ".py"
                    else ["sh", "-n", str(script)]
                )
                result = subprocess.run(command, check=False, capture_output=True, text=True)
                if result.returncode != 0:
                    problems.append(f"{skill_path}: script smoke failed: {script.name}")
            shutil.copytree(folder, install_root / folder.name)
            if not (install_root / folder.name / "SKILL.md").is_file():
                problems.append(f"{skill_path}: clean install smoke failed")
    if problems:
        print("Skill validation failed:")
        for problem in problems:
            print(f"- {problem}")
        return 1
    print(f"Skill validation passed: {len(skills)} skills")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
