import copy

import pytest

from nfm.crypto.policy_signing import create_bundle, create_signing_key, verify_bundle


def test_signed_policy_bundle_verifies_and_detects_tampering(tmp_path):
    private_key, public_key = tmp_path / "signing-key.pem", tmp_path / "signing-public.pem"
    create_signing_key(private_key, public_key)
    policy = {"policy_id": "signed", "version": 1, "rules": [
        {"effect": "allow", "source_roles": ["app"], "services": ["db"], "operations": ["connect"]}
    ]}
    bundle = create_bundle(policy, private_key)
    assert verify_bundle(bundle, public_key) == policy
    tampered = copy.deepcopy(bundle)
    tampered["policy"]["rules"][0]["services"] = ["admin"]
    with pytest.raises(ValueError, match="signature verification failed"):
        verify_bundle(tampered, public_key)


def test_policy_signing_key_generation_refuses_partial_keypair(tmp_path):
    private_key, public_key = tmp_path / "key.pem", tmp_path / "public.pem"
    private_key.write_text("existing")
    with pytest.raises(FileExistsError):
        create_signing_key(private_key, public_key)


def test_policy_signing_key_generation_rejects_mismatched_pair(tmp_path):
    private_key, public_key = tmp_path / "key.pem", tmp_path / "public.pem"
    create_signing_key(private_key, public_key)
    other_private, other_public = tmp_path / "other-key.pem", tmp_path / "other-public.pem"
    create_signing_key(other_private, other_public)
    public_key.write_bytes(other_public.read_bytes())
    with pytest.raises(ValueError, match="do not match"):
        create_signing_key(private_key, public_key)
