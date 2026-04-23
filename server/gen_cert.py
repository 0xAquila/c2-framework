"""
Generate a self-signed TLS certificate for the C2 server.
Run once: python gen_cert.py

Produces:
  cert.pem            — certificate (share with agents as trust anchor)
  key.pem             — private key (server only, never distribute)
  cert_fingerprint.txt — SHA-256 fingerprint for agent certificate pinning
"""
import os
import ssl
import hashlib
import datetime
import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,      "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NexaCloud Inc."),
        x509.NameAttribute(NameOID.COMMON_NAME,       "nexacloud.io"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("nexacloud.io"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    base = os.path.dirname(os.path.abspath(__file__))

    cert_path = os.path.join(base, "cert.pem")
    key_path  = os.path.join(base, "key.pem")
    fp_path   = os.path.join(base, "cert_fingerprint.txt")

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

    # Compute SHA-256 fingerprint of the DER-encoded certificate.
    # Agents embed this value to pin the server certificate — MITM impossible
    # even with verify=False since the fingerprint is hardcoded at compile time.
    with open(cert_path, "r") as f:
        pem_data = f.read()
    der_data    = ssl.PEM_cert_to_DER_cert(pem_data)
    fingerprint = hashlib.sha256(der_data).hexdigest()

    with open(fp_path, "w") as f:
        f.write(fingerprint)

    print("[+] cert.pem and key.pem written.")
    print("[+] Server CN: nexacloud.io  (valid 825 days)")
    print(f"[+] cert_fingerprint.txt written: {fingerprint}")
    print("[+] Embed this fingerprint in agents via the generator (automatic)")
    print("    or set CERT_FINGERPRINT in agent/config.py manually.")


if __name__ == "__main__":
    generate()
