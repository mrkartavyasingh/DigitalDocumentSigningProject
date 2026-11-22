"""ECDSA signature verification and public-key fingerprint helpers."""
import hashlib
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from signer import hash_file

def public_key_fingerprint(public_key):
    """SHA-256 fingerprint of the DER-encoded public key."""
    der = public_key.export_key(format="DER")
    return hashlib.sha256(der).hexdigest()

def verify_file(document_path, signature, public_key):
    digest = hash_file(document_path)
    try:
        verifier = DSS.new(public_key, "fips-186-3", encoding="binary")
        verifier.verify(digest, signature)
        return True
    except (ValueError, TypeError):
        return False
