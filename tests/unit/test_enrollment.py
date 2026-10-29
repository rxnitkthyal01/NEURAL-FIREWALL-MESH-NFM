from cryptography import x509
from cryptography.hazmat.primitives import serialization

from nfm.identity.credentials import (
    certificate_node_id,
    create_ca,
    create_enrollment_csr,
    issue_from_csr,
)


def test_controller_issues_certificate_for_agent_generated_key(tmp_path):
    ca, node = tmp_path / "ca", tmp_path / "agent"
    create_ca(ca)
    csr_pem = create_enrollment_csr(node, "node-a", "application")
    cert = issue_from_csr(csr_pem, ca, "node-a", "application")
    private = serialization.load_pem_private_key((node / "node-a-key.pem").read_bytes(), password=None)
    assert cert.public_key().public_numbers() == private.public_key().public_numbers()
    assert certificate_node_id(cert) == "node-a"
    assert cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)


def test_controller_rejects_csr_for_a_different_node(tmp_path):
    ca, node = tmp_path / "ca", tmp_path / "agent"
    create_ca(ca)
    csr_pem = create_enrollment_csr(node, "node-a", "application")
    try:
        issue_from_csr(csr_pem, ca, "node-b", "application")
    except ValueError as exc:
        assert "common name" in str(exc)
    else:
        raise AssertionError("CSR identity mismatch was accepted")
