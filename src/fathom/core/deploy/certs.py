"""In-process minting of CA-signed agent client certs (ADR-026 §Cert minting).

The deployment subsystem mints the *agent's* mTLS identity itself rather than shelling out to
``openssl`` (deploy/mint-agent-cert.sh): an RSA-2048 client cert, ``CN=<host>-agent``, EKU
clientAuth, signed by the Fathom CA. The CA material is loaded from references resolved at runtime
(ADR-010), never embedded. The minted cert's SHA-1 fingerprint is the agent's identity — the same
value the mTLS proxy stamps as ``X-Client-Cert-Fingerprint`` and ingest keys a ``Host`` on, so a
freshly deployed agent enrols deterministically on its first push.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from fathom.core.deploy import DeploymentError

_RSA_BITS = 2048
# Match deploy/gen-certs.sh's clientAuth EKU + a CA:FALSE leaf so the cert can only ever be a
# client identity, never sign other certs.
_CLIENT_EKU = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])


@dataclass(frozen=True, slots=True)
class MintedCert:
    """A freshly minted agent identity: the client key + cert, the CA cert, and the fingerprint.

    ``key_pem``/``cert_pem`` go into the agent bundle's ``certs/client.{key,crt}``; ``ca_cert_pem``
    is the trust anchor the agent pins to verify the proxy. ``fingerprint_sha1`` is the lowercase,
    colon-free SHA-1 hex the ingest boundary uses as the host identity.
    """

    common_name: str
    key_pem: str
    cert_pem: str
    ca_cert_pem: str
    fingerprint_sha1: str


class CertificateAuthority:
    """The Fathom CA, able to mint client certs. Built from PEM material (loaded by reference)."""

    def __init__(self, ca_cert: x509.Certificate, ca_key: rsa.RSAPrivateKey) -> None:
        self._ca_cert = ca_cert
        self._ca_key = ca_key
        self._ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

    @classmethod
    def from_pem(cls, *, cert_pem: str, key_pem: str) -> CertificateAuthority:
        """Load a CA from its cert + (unencrypted) private-key PEM.

        Raises:
            DeploymentError: the material is not a valid PEM cert / RSA private key.
        """
        try:
            ca_cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        except ValueError as exc:
            raise DeploymentError(
                "agent_deployment_ca_cert_ref is not a valid PEM certificate"
            ) from exc
        try:
            key = serialization.load_pem_private_key(key_pem.encode("utf-8"), password=None)
        except (ValueError, TypeError) as exc:
            raise DeploymentError(
                "agent_deployment_ca_key_ref is not a valid PEM private key"
            ) from exc
        if not isinstance(key, rsa.RSAPrivateKey):
            raise DeploymentError("agent CA key must be an RSA private key")
        # Reject a mis-pointed leaf/client cert: minting off a non-CA emits certs the mTLS proxy
        # rejects, so every deployed agent would silently fail to enrol. Fail loud at provisioning
        # instead (round-3 P3). A cert with no BasicConstraints extension is treated as non-CA.
        try:
            basic = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            is_ca = basic.ca
        except x509.ExtensionNotFound:
            is_ca = False
        if not is_ca:
            raise DeploymentError(
                "agent_deployment_ca_cert_ref is not a CA certificate (basicConstraints CA:false)"
            )
        return cls(ca_cert, key)

    @property
    def ca_cert_pem(self) -> str:
        """The CA certificate PEM (public; the agent's pinned trust anchor)."""
        return self._ca_cert_pem

    def mint_client_cert(
        self, common_name: str, *, days: int, now: _dt.datetime | None = None
    ) -> MintedCert:
        """Mint an RSA-2048 clientAuth cert for ``common_name``, signed by this CA.

        ``now`` is injectable for deterministic tests; production uses UTC wall-clock. The validity
        window is ``[now-5min, now+days]`` (a small backdate absorbs clock skew on the target).
        """
        if len(common_name) > 64:
            # X.509 caps an attribute at 64 chars; reject loudly rather than let cryptography raise
            # a bare ValueError mid-mint (on the pull path that is after the token is spent; r3).
            raise DeploymentError(
                f"certificate CN too long ({len(common_name)} > 64): {common_name!r}"
            )
        issued = (now or _dt.datetime.now(tz=_dt.UTC)).replace(microsecond=0)
        key = rsa.generate_private_key(public_exponent=65537, key_size=_RSA_BITS)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(issued - _dt.timedelta(minutes=5))
            .not_valid_after(issued + _dt.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_CLIENT_EKU, critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
            .sign(private_key=self._ca_key, algorithm=hashes.SHA256())
        )
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        fingerprint = cert.fingerprint(hashes.SHA1()).hex()  # noqa: S303 - identity, not security
        return MintedCert(
            common_name=common_name,
            key_pem=key_pem,
            cert_pem=cert_pem,
            ca_cert_pem=self._ca_cert_pem,
            fingerprint_sha1=fingerprint,
        )
