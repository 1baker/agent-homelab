from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from agent_homelab.cli import main


def test_init_validate_render_and_service_upsert(tmp_path: Path) -> None:
    inventory = tmp_path / "homelab.yaml"
    rendered = tmp_path / "rendered"
    assert main(["init", str(inventory), "--topology", "relay"]) == 0
    assert main(["validate", "--inventory", str(inventory)]) == 0
    assert (
        main(
            [
                "service",
                "upsert",
                "wiki",
                "--inventory",
                str(inventory),
                "--upstream-node",
                "app-host",
                "--port",
                "3000",
                "--port-source",
                "compose.yaml ports 3000:3000",
                "--local-hostname",
                "wiki.localhost",
                "--public-hostname",
                "wiki.example.net",
                "--edge-node",
                "gateway",
                "--auth-policy",
                "one_factor",
            ]
        )
        == 0
    )
    assert main(["render", "--inventory", str(inventory), "--output", str(rendered)]) == 0
    data = yaml.safe_load(inventory.read_text())
    assert data["services"]["wiki"]["public"]["auth"]["policy"] == "one_factor"


def test_init_refuses_overwrite(tmp_path: Path) -> None:
    inventory = tmp_path / "homelab.yaml"
    assert main(["init", str(inventory)]) == 0
    assert main(["init", str(inventory)]) == 2


def test_recipe_catalog_commands(capsys) -> None:
    assert main(["recipe", "list"]) == 0
    assert "paperless-ngx" in capsys.readouterr().out
    assert main(["recipe", "show", "immich"]) == 0
    assert '"port": 2283' in capsys.readouterr().out
    assert main(["recipe", "policy"]) == 0
    assert "docker-compose-project-directories" in capsys.readouterr().out
    assert main(["recipe", "show", "missing-recipe"]) == 2


def test_validate_tailscale_inventory_does_not_load_a_secret(tmp_path: Path) -> None:
    inventory = tmp_path / "homelab.yaml"
    assert main(["init", str(inventory)]) == 0
    data = yaml.safe_load(inventory.read_text())
    data["tailscale"] = {
        "authority": "gitops",
        "credential_ref": {"file": "/nonexistent/private/reader.json"},
    }
    inventory.write_text(yaml.safe_dump(data))
    assert main(["validate", "--inventory", str(inventory)]) == 0


def test_tailscale_help_exposes_reader_and_guarded_transactions(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["tailscale-policy", "--help"])
    assert exc.value.code == 0
    text = capsys.readouterr().out
    assert all(command in text for command in ["enroll", "read", "plan", "apply", "rollback"])


def test_tailscale_rejects_argv_credentials(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(
            ["tailscale-policy", "enroll", "--credential-file", "/private/reader.json", "--client-secret", "synthetic"]
        )
    assert exc.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_tailscale_read_requires_inventory_integration(tmp_path: Path, capsys) -> None:
    inventory = tmp_path / "homelab.yaml"
    assert main(["init", str(inventory)]) == 0
    capsys.readouterr()
    assert (
        main(
            [
                "tailscale-policy",
                "read",
                "--inventory",
                str(inventory),
                "--snapshot-dir",
                str(tmp_path / "private-snapshot"),
            ]
        )
        == 2
    )
    result = capsys.readouterr()
    assert "error:" in result.err
    assert not (tmp_path / "private-snapshot").exists()
