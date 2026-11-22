"""ECDSA document signing using SHA-256 and PyCryptodome."""
from pathlib import Path
from time import perf_counter
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from key_manager import load_private_key

CHUNK_SIZE = 1024 * 1024

def hash_file(path):
    digest = SHA256.new()
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest

def sign_file(document_path, passphrase):
    """Return (signature_bytes, metrics_dict). Signature uses deterministic RFC 6979."""
    t0 = perf_counter()
    digest = hash_file(document_path)
    hash_seconds = perf_counter() - t0

    t1 = perf_counter()
    private_key = load_private_key(passphrase)
    signer = DSS.new(private_key, "deterministic-rfc6979", encoding="binary")
    signature = signer.sign(digest)
    sign_seconds = perf_counter() - t1

    return signature, {
        "hash_seconds": hash_seconds,
        "sign_seconds": sign_seconds,
        "document_bytes": Path(document_path).stat().st_size,
        "signature_bytes": len(signature),
    }
