from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from agent_homelab.model import InventoryError, load_inventory, topology_for, validate_inventory

FIXTURES = Path(__file__).parent / "fixtures"


def payload(name: str = "relay.yaml") -> dict:
    return yaml.safe_load((FIXTURES / name).read_text())


def test_direct_and_relay_topologies_validate() -> None:
    direct = load_inventory(FIXTURES / "direct.yaml")
    relay = load_inventory(FIXTURES / "relay.yaml")
    assert topology_for(direct.services["hello"]) == "direct"
    assert topology_for(relay.services["photos"]) == "relay"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda data: data["services"]["photos"]["upstream"].update(node="missing"), "unknown node"),
        (lambda data: data["services"]["photos"]["public"].update(edge_node="app-host"), "not an edge_gateway"),
        (lambda data: data["services"]["photos"]["upstream"].update(port=40000), "ephemeral range"),
        (lambda data: data["services"]["photos"].update(password="unsafe"), "Additional properties"),
    ],
)
def test_invalid_inventory_is_rejected(mutate, message: str) -> None:
    data = copy.deepcopy(payload())
    mutate(data)
    with pytest.raises(InventoryError, match=message):
        validate_inventory(data)


def test_inline_secret_key_is_rejected_even_in_extension_data() -> None:
    data = payload()
    data["site"]["authelia"]["session_secret"] = "unsafe"
    with pytest.raises(InventoryError, match="Additional properties"):
        validate_inventory(data)


def test_ephemeral_override_requires_explicit_flag() -> None:
    data = payload()
    upstream = data["services"]["photos"]["upstream"]
    upstream["port"] = 40000
    upstream["allow_ephemeral_port"] = True
    validate_inventory(data)


@pytest.mark.parametrize("authority", ["console", "gitops"])
@pytest.mark.parametrize("credential_ref", [{"env": "TAILSCALE_READER"}, {"file": "/private/reader.json"}])
def test_optional_tailscale_references_validate_without_loading_credentials(authority, credential_ref) -> None:
    data = payload()
    data["tailscale"] = {"authority": authority, "credential_ref": credential_ref}
    validate_inventory(data)
    data["tailscale"]["writer_credential_ref"] = {"file": "/private/writer.json"}
    validate_inventory(data)


@pytest.mark.parametrize(
    "integration",
    [
        {"credential_ref": {"env": "TAILSCALE_READER"}},
        {"authority": "console"},
        {"authority": "unknown", "credential_ref": {"env": "TAILSCALE_READER"}},
        {"authority": "console", "credential_ref": {"file": "relative.json"}},
        {"authority": "console", "credential_ref": {"file": "/private/reader.json", "env": "TAILSCALE_READER"}},
        {"authority": "console", "credential_ref": {"env": "lowercase"}},
        {"authority": "console", "credential_ref": {"client_id": "synthetic-id", "client_secret": "synthetic"}},
        {"authority": "console", "credential_ref": {"env": "TAILSCALE_READER"}, "client_id": "synthetic-id"},
        {"authority": "console", "credential_ref": {"env": "TAILSCALE_READER"}, "client_secret": "synthetic"},
        {
            "authority": "console",
            "credential_ref": {"env": "TAILSCALE_READER"},
            "writer_credential_ref": {"token": "synthetic"},
        },
    ],
)
def test_tailscale_configuration_rejects_ambiguous_or_inline_credentials(integration) -> None:
    data = payload()
    data["tailscale"] = integration
    with pytest.raises(InventoryError):
        validate_inventory(data)
