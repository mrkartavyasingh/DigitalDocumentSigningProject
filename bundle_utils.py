"""Create and safely inspect signed-document ZIP bundles."""
import json
import os
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from datetime import datetime, timezone
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from key_manager import PUBLIC_KEY_PATH
from signer import hash_file, sign_file

MAX_BUNDLE_BYTES = 32 * 1024 * 1024
MAX_DOCUMENT_BYTES = 25 * 1024 * 1024
REQUIRED_FILES = {"manifest.json", "signature.bin", "public_key.pem"}

def sha256_hex(path):
    return hash_file(path).hexdigest()

def create_signed_bundle(document_path, original_filename, passphrase):
    document_path = Path(document_path)
    if document_path.stat().st_size > MAX_DOCUMENT_BYTES:
        raise ValueError("Document exceeds the 25 MB limit.")
    signature, metrics = sign_file(document_path, passphrase)
    manifest = {
        "format": "digital-document-signing-bundle-v1",
        "signature_algorithm": "ECDSA",
        "curve": "P-256",
        "hash_algorithm": "SHA-256",
        "signature_encoding": "fixed-width binary r||s",
        "document_filename": Path(original_filename).name,
        "document_sha256": sha256_hex(document_path),
        "created_utc": datetime.now(timezone.utc).isoformat(),
    }
    # Write into a temporary ZIP, with the document basename only.
    fd, bundle_name = tempfile.mkstemp(suffix=".zip")
    os.close(fd)
    try:
        with zipfile.ZipFile(bundle_name, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(document_path, arcname="document/" + Path(original_filename).name)
            zf.writestr("signature.bin", signature)
            zf.write(PUBLIC_KEY_PATH, arcname="public_key.pem")
            zf.writestr("manifest.json", json.dumps(manifest, indent=2))
        return bundle_name, metrics
    except Exception:
        try:
            os.unlink(bundle_name)
        except OSError:
            pass
        raise

def _safe_member_name(name):
    p = PurePosixPath(name)
    return bool(name) and not p.is_absolute() and ".." not in p.parts and "\\" not in name

def verify_signed_bundle(bundle_path, trusted_public_key):
    """Return (valid, message, details). Never extract ZIP paths to disk."""
    try:
        if Path(bundle_path).stat().st_size > MAX_BUNDLE_BYTES:
            return False, "Bundle exceeds the 32 MB limit.", {}
        with zipfile.ZipFile(bundle_path, "r") as zf:
            infos = zf.infolist()
            names = [i.filename for i in infos]
            if len(names) != len(set(names)):
                return False, "Bundle contains duplicate file names.", {}
            if any(not _safe_member_name(n) for n in names):
                return False, "Bundle contains an unsafe path.", {}
            if any(i.file_size > MAX_DOCUMENT_BYTES for i in infos):
                return False, "A bundle member exceeds the 25 MB limit.", {}
            if not REQUIRED_FILES.issubset(set(names)):
                return False, "Bundle is missing required files.", {}
            document_members = [n for n in names if n.startswith("document/") and not n.endswith("/")]
            if len(document_members) != 1:
                return False, "Bundle must contain exactly one document.", {}
            if sum(i.file_size for i in infos) > MAX_BUNDLE_BYTES:
                return False, "Expanded bundle is too large.", {}
            manifest = json.loads(zf.read("manifest.json"))
            if manifest.get("format") != "digital-document-signing-bundle-v1":
                return False, "Unsupported bundle format.", {}
            if manifest.get("signature_algorithm") != "ECDSA" or manifest.get("hash_algorithm") != "SHA-256":
                return False, "Unsupported signature or hash algorithm.", {}
            bundled_key = zf.read("public_key.pem")
            trusted_der = trusted_public_key.export_key(format="DER")
            from Crypto.PublicKey import ECC
            embedded_key = ECC.import_key(bundled_key)
            if embedded_key.has_private():
                return False, "Bundle must not contain a private key.", {}
            if embedded_key.export_key(format="DER") != trusted_der:
                return False, "Public key does not match the locally trusted key.", {}

            document_name = document_members[0]
            document_bytes = zf.read(document_name)
            actual_hash = SHA256.new(document_bytes).hexdigest()
            if actual_hash != manifest.get("document_sha256"):
                return False, "Document hash does not match the manifest.", {
                    "document_filename": Path(document_name).name,
                    "sha256": actual_hash,
                }
            signature = zf.read("signature.bin")
            from Crypto.Hash import SHA256 as SHA256Module
            digest = SHA256Module.new(document_bytes)
            verifier = DSS.new(trusted_public_key, "fips-186-3", encoding="binary")
            try:
                verifier.verify(digest, signature)
            except (ValueError, TypeError):
                return False, "Signature is invalid. The document or signature may have been modified.", {
                    "document_filename": Path(document_name).name,
                    "sha256": actual_hash,
                }
            return True, "Signature is valid and the public key matches the locally trusted key.", {
                "document_filename": Path(document_name).name,
                "sha256": actual_hash,
                "created_utc": manifest.get("created_utc", "Unknown"),
                "signature_bytes": len(signature),
            }
    except (zipfile.BadZipFile, KeyError, ValueError, OSError, json.JSONDecodeError, TypeError) as exc:
        return False, f"Could not verify bundle: {exc}", {}
