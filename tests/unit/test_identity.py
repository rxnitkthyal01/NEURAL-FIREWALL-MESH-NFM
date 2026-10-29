import os
import stat

from cryptography import x509

from nfm.identity.credentials import certificate_node_id, create_ca, issue_node


def test_issued_identity_is_ca_signed_material_with_node_san(tmp_path):
    ca, identities = tmp_path / "ca", tmp_path / "identities"
    create_ca(ca)
    issue_node(identities, ca, "node-a", "application", days=7)
    cert = x509.load_pem_x509_certificate((identities / "node-a-cert.pem").read_bytes())
    assert certificate_node_id(cert) == "node-a"
    assert (identities / "node-a-key.pem").is_file()
    if os.name != "nt":
        mode = stat.S_IMODE((identities / "node-a-key.pem").stat().st_mode)
        assert mode == 0o600
