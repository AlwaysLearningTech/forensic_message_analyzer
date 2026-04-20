"""Detached-signature PKI signing for forensic output.

Defensibility goal: an opposing expert should be able to verify that the manifest, chain of custody, and final reports have not been altered since the examiner produced them. Hashing alone does not achieve this — an attacker with write access to the output directory can modify a file and recompute its hash.

Implementation: the examiner has an ed25519 keypair. The private key lives at a path under the examiner's control (set via EXAMINER_SIGNING_KEY, or auto-generated per-run into the run directory for an ephemeral but consistent chain within the run). Every signed artifact gets a sibling ``<file>.sig`` containing the detached Ed25519 signature over the file's raw bytes, plus a ``<file>.sig.pub`` with the PEM-encoded public key so a verifier only needs the file + .sig + .sig.pub to check.

Why ed25519: small keys, small signatures, standard library-free with pyca/cryptography (which is already a transitive dep of anthropic/weasyprint). Ed25519 is FIPS 186-5 approved and widely supported.

Trust model caveats (documented here so the methodology can point here):
  * An ephemeral per-run key is equivalent to notarizing the run with a self-signed cert. It proves internal consistency — the manifest and every report were signed by the same key that produced the run — but it doesn't anchor to an external trust anchor.
  * For the strongest defensibility, the examiner should generate a long-lived keypair out of band, publish the public cert, and set EXAMINER_SIGNING_KEY to the private key path. Then every run's signatures chain back to a single, publishable public key.

Either mode is a strict improvement over hashing alone.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class Signer:
    """Load or generate an Ed25519 signing key and sign files on demand."""

    def __init__(self, key_path: Optional[Path] = None, run_dir: Optional[Path] = None):
        """Prepare a signing key.

        If ``key_path`` is provided and exists, load it. If ``key_path`` is provided but does not exist, create a new key and write it. If ``key_path`` is None, generate a per-run ephemeral key in ``run_dir/keys/`` (mode 0600) — this gives internal consistency without requiring pre-configuration.
        """
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives import serialization
        except ImportError as exc:
            raise ImportError(
                "cryptography is required for signing; install via `pip install cryptography` "
                "(pulled in transitively by anthropic/weasyprint)"
            ) from exc

        self._Ed25519PrivateKey = Ed25519PrivateKey
        self._serialization = serialization

        if key_path is None:
            # Per-run ephemeral key
            base = run_dir or Path.cwd()
            keys_dir = base / "keys"
            keys_dir.mkdir(parents=True, exist_ok=True)
            key_path = keys_dir / "examiner_ed25519.pem"

        self.key_path = Path(key_path)

        if self.key_path.exists():
            self.private_key = self._load_key(self.key_path)
            self._generated = False
        else:
            self.private_key = Ed25519PrivateKey.generate()
            self._write_key(self.private_key, self.key_path)
            self._generated = True

        self.public_key = self.private_key.public_key()
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def _write_key(self, private_key, path: Path):
        serialization = self._serialization
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)

    def _load_key(self, path: Path):
        data = path.read_bytes()
        return self._serialization.load_pem_private_key(data, password=None)

    @property
    def is_ephemeral(self) -> bool:
        """True if this key was generated at init because no prior key existed."""
        return self._generated

    def sign_file(self, file_path: Path) -> Tuple[Path, Path]:
        """Sign ``file_path``, writing <file>.sig and <file>.sig.pub next to it.

        Returns (sig_path, pub_path). The .sig file contains the raw 64-byte Ed25519 signature; the .sig.pub file contains the PEM-encoded public key. A verifier needs only the original file, the .sig, and the .sig.pub to check the signature.
        """
        file_path = Path(file_path)
        sig_path = file_path.with_suffix(file_path.suffix + ".sig")
        pub_path = file_path.with_suffix(file_path.suffix + ".sig.pub")

        data = file_path.read_bytes()
        signature = self.private_key.sign(data)

        sig_path.write_bytes(signature)
        pub_path.write_bytes(self.public_key_pem)
        return sig_path, pub_path

    def verify_file(self, file_path: Path) -> bool:
        """Verify a previously-signed file using the sibling .sig and .sig.pub."""
        file_path = Path(file_path)
        sig_path = file_path.with_suffix(file_path.suffix + ".sig")
        pub_path = file_path.with_suffix(file_path.suffix + ".sig.pub")

        if not sig_path.exists() or not pub_path.exists():
            return False

        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            pub = self._serialization.load_pem_public_key(pub_path.read_bytes())
            pub.verify(sig_path.read_bytes(), file_path.read_bytes())
            return True
        except Exception:
            return False


__all__ = ["Signer"]
