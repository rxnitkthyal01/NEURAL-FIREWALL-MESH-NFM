import pytest

from nfm.policy.engine import evaluate, load_policy


def policy():
    return {"policy_id": "test", "version": 1, "rules": [
        {"effect": "allow", "source_roles": ["application"], "services": ["db"], "operations": ["connect"]},
        {"effect": "deny", "source_nodes": ["bad"], "services": ["*"], "operations": ["*"]},
    ]}


def test_default_deny_and_explicit_allow():
    p = policy()
    assert evaluate(None, node_id="a", role="application", service="db", operation="connect",
                    credential_valid=True, revoked=False).allowed is False
    assert evaluate(p, node_id="a", role="application", service="db", operation="connect",
                    credential_valid=True, revoked=False).allowed is True
    assert evaluate(p, node_id="a", role="application", service="admin", operation="connect",
                    credential_valid=True, revoked=False).allowed is False


def test_deny_rule_and_credential_state_take_precedence():
    p = policy()
    args = dict(policy=p, role="application", service="db", operation="connect",
                credential_valid=True, revoked=False)
    assert not evaluate(node_id="bad", **args).allowed
    assert not evaluate(node_id="a", **{**args, "credential_valid": False}).allowed
    assert not evaluate(node_id="a", **{**args, "revoked": True}).allowed
    assert not evaluate(node_id="a", **{**args, "security_state": "ISOLATED"}).allowed


def test_unknown_policy_fields_are_rejected(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("policy_id: x\nversion: 1\nrules:\n  - effect: allow\n    servcies: [db]\n")
    with pytest.raises(ValueError, match="unknown fields"):
        load_policy(path)


def test_policy_requires_explicit_service_and_operation_scopes(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("policy_id: x\nversion: 1\nrules:\n  - effect: allow\n    source_roles: [application]\n")
    with pytest.raises(ValueError, match="services"):
        load_policy(path)
