"""Small deterministic, deny-by-default policy engine."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    reason: str
    policy_id: str | None = None
    version: int | None = None


def validate_policy(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("policy document must be a YAML mapping")
    unknown_top_level = set(raw) - {"policy_id", "version", "rules"}
    if unknown_top_level:
        raise ValueError(f"unknown policy fields: {', '.join(sorted(map(str, unknown_top_level)))}")
    if not isinstance(raw.get("policy_id"), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", raw["policy_id"]):
        raise ValueError("policy_id must be 1-128 letters, digits, dots, underscores, or hyphens")
    if type(raw.get("version")) is not int or raw["version"] < 1:
        raise ValueError("version must be a positive integer")
    rules = raw.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("rules must be a non-empty list")
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ValueError(f"rules[{index}] must be a mapping")
        unknown = set(rule) - {"effect", "source_nodes", "source_roles", "services", "operations"}
        if unknown:
            raise ValueError(f"rules[{index}] has unknown fields: {', '.join(sorted(map(str, unknown)))}")
        if rule.get("effect") not in {"allow", "deny"}:
            raise ValueError(f"rules[{index}].effect must be allow or deny")
        if not ("source_nodes" in rule or "source_roles" in rule):
            raise ValueError(f"rules[{index}] must specify source_nodes or source_roles")
        for required in ("services", "operations"):
            if required not in rule:
                raise ValueError(f"rules[{index}] must specify {required}; use ['*'] for an intentional wildcard")
        for field in ("source_nodes", "source_roles", "services", "operations"):
            value = rule.get(field, ["*"])
            if not isinstance(value, list) or not value or not all(isinstance(x, str) for x in value):
                raise ValueError(f"rules[{index}].{field} must be a non-empty list of strings")
    return raw


def load_policy(path: Path) -> dict[str, Any]:
    return validate_policy(yaml.safe_load(path.read_text(encoding="utf-8")))


def evaluate(policy: dict[str, Any] | None, *, node_id: str, role: str,
             service: str, operation: str, credential_valid: bool,
             revoked: bool, security_state: str = "HEALTHY") -> Decision:
    if not credential_valid:
        return Decision(False, "credential_invalid")
    if revoked:
        return Decision(False, "identity_revoked")
    if security_state != "HEALTHY":
        return Decision(False, "node_not_healthy")
    if policy is None:
        return Decision(False, "no_active_policy")
    matching = []
    for rule in policy["rules"]:
        if (node_id in rule.get("source_nodes", ["*"]) or "*" in rule.get("source_nodes", ["*"])) \
                and (role in rule.get("source_roles", ["*"]) or "*" in rule.get("source_roles", ["*"])) \
                and (service in rule.get("services", ["*"]) or "*" in rule.get("services", ["*"])) \
                and (operation in rule.get("operations", ["*"]) or "*" in rule.get("operations", ["*"])):
            matching.append(rule)
    if not matching:
        return Decision(False, "no_matching_allow_rule", policy.get("policy_id"), policy.get("version"))
    # Explicit deny wins if multiple rules match.
    if any(rule["effect"] == "deny" for rule in matching):
        return Decision(False, "explicit_deny", policy.get("policy_id"), policy.get("version"))
    return Decision(True, "explicit_allow", policy.get("policy_id"), policy.get("version"))
