"""
OpenSearch security setup for the compose example, run as two one-shot jobs:

  python -m pelican.opensearch_setup certs   before OpenSearch starts
  python -m pelican.opensearch_setup users   once OpenSearch is healthy

`certs` creates a private CA, a server certificate for the `opensearch`
host and an admin client certificate in CERTS_DIR, if they're not there yet.
Run it as root: it hands the server key to OpenSearch's user (1000) and the
admin key to Pelican's (10001).

`users` signs in with the admin certificate and creates (or updates) the
accounts and their roles from environment variables:

  OS_PASSWORD          `pelican`: crawlers -- write to the index   (required)
  OS_STATUS_PASSWORD   `pelican-status`: status page -- read, stats (required)
  OS_READER_PASSWORD   `pelican-reader`: search UI -- read only    (optional)
  OS_ADMIN_PASSWORD    `admin`: full access, for you               (optional)

Re-running it applies password changes from the environment.
"""

import datetime
import ipaddress
import os
import sys

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import settings

CERTS_DIR = os.environ.get("CERTS_DIR", "/certs")
OS_UID = 1000        # the OpenSearch image's user
PELICAN_UID = 10001  # the Pelican images' user
VALID_DAYS = 3650

NODE_DN = "CN=opensearch,O=Pelican"
ADMIN_DN = "CN=pelican-admin,O=Pelican"


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Pelican"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write(name: str, data: bytes, mode: int, uid: int) -> None:
    path = os.path.join(CERTS_DIR, name)
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)
    os.chown(path, uid, uid)


def _issue(cn, ca_key, ca_name, usages, sans=None, ca=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(_name(cn))
               .issuer_name(ca_name or _name(cn))
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               # Python 3.13+ rejects certificates without these (strict X.509 checks).
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                   (ca_key or key).public_key()), critical=False)
               .add_extension(x509.KeyUsage(
                   digital_signature=not ca, key_encipherment=not ca, key_cert_sign=ca, crl_sign=ca,
                   content_commitment=False, data_encipherment=False, key_agreement=False,
                   encipher_only=False, decipher_only=False), critical=True))
    if usages:
        builder = builder.add_extension(x509.ExtendedKeyUsage(usages), critical=False)
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    cert = builder.sign(ca_key or key, hashes.SHA256())
    # OpenSearch only reads unencrypted PKCS#8 keys.
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return key, cert, key_pem, cert.public_bytes(serialization.Encoding.PEM)


def make_certs() -> None:
    if os.path.exists(os.path.join(CERTS_DIR, "ca.pem")):
        print(f"[certs] {CERTS_DIR}/ca.pem exists, leaving certificates as they are")
        return
    os.makedirs(CERTS_DIR, exist_ok=True)
    ca_key, ca_cert, _, ca_pem = _issue("Pelican CA", None, None, None, ca=True)
    _, _, node_key, node_pem = _issue(
        "opensearch", ca_key, ca_cert.subject,
        [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH],
        sans=[x509.DNSName("opensearch"), x509.DNSName("localhost"),
              x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
    _, _, admin_key, admin_pem = _issue("pelican-admin", ca_key, ca_cert.subject,
                                        [ExtendedKeyUsageOID.CLIENT_AUTH])
    # The CA key isn't kept: delete the volume to re-issue everything.
    _write("ca.pem", ca_pem, 0o644, 0)
    _write("node.pem", node_pem, 0o644, OS_UID)
    _write("node-key.pem", node_key, 0o600, OS_UID)
    _write("admin.pem", admin_pem, 0o644, PELICAN_UID)
    _write("admin-key.pem", admin_key, 0o600, PELICAN_UID)
    print(f"[certs] created CA, server and admin certificates in {CERTS_DIR}, valid {VALID_DAYS} days")


def _api(method: str, path: str, body: dict) -> None:
    resp = requests.request(
        method, f"{settings.OS_HOST.rstrip('/')}/_plugins/_security/api/{path}", json=body,
        cert=(os.path.join(CERTS_DIR, "admin.pem"), os.path.join(CERTS_DIR, "admin-key.pem")),
        verify=os.path.join(CERTS_DIR, "ca.pem"), timeout=60)
    if not resp.ok:
        raise RuntimeError(f"{method} {path}: {resp.status_code} {resp.text[:300]}")


def _account(user: str, password: str, role: str, role_body: dict | None) -> None:
    if role_body is not None:
        _api("PUT", f"roles/{role}", role_body)
    _api("PUT", f"internalusers/{user}", {"password": password})
    _api("PUT", f"rolesmapping/{role}", {"users": [user]})
    print(f"[users] {user}: role {role}")


def make_users() -> None:
    passwords = {k: os.environ.get(k, "") for k in
                 ("OS_PASSWORD", "OS_STATUS_PASSWORD", "OS_READER_PASSWORD", "OS_ADMIN_PASSWORD")}
    missing = [k for k in ("OS_PASSWORD", "OS_STATUS_PASSWORD") if not passwords[k]]
    if missing:
        sys.exit(f"[users] missing environment variable(s): {', '.join(missing)}")
    index = settings.SEARCH_INDEX

    _account("pelican", passwords["OS_PASSWORD"], "pelican_crawler", {
        # Checked at cluster level: bulk writes, and the scroll and tasks
        # APIs behind the async update_by_query in roles.py.
        "cluster_permissions": ["indices:data/write/bulk", "indices:data/read/scroll",
                                "indices:data/read/scroll/clear", "cluster:monitor/task/get"],
        "index_permissions": [{
            "index_patterns": [index],
            # search_shards and refresh: update_by_query (slices="auto", refresh=True).
            "allowed_actions": ["crud", "create_index", "indices:admin/get", "indices:admin/mappings/get",
                                "indices:admin/shards/search_shards", "indices:admin/refresh"],
        }],
    })
    _account("pelican-status", passwords["OS_STATUS_PASSWORD"], "pelican_status", {
        "cluster_permissions": ["cluster:monitor/nodes/stats"],
        "index_permissions": [{"index_patterns": [index], "allowed_actions": ["read", "indices:monitor/stats"]}],
    })
    if passwords["OS_READER_PASSWORD"]:
        _account("pelican-reader", passwords["OS_READER_PASSWORD"], "pelican_reader", {
            "index_permissions": [{"index_patterns": [index], "allowed_actions": ["read"]}],
        })
    if passwords["OS_ADMIN_PASSWORD"]:
        _account("admin", passwords["OS_ADMIN_PASSWORD"], "all_access", None)


if __name__ == "__main__":
    commands = {"certs": make_certs, "users": make_users}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        sys.exit(f"usage: python -m pelican.opensearch_setup {{{'|'.join(commands)}}}")
    commands[sys.argv[1]]()
