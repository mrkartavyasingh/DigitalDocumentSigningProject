import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
import bundle_utils

class BundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.doc = self.root / "note.txt"
        self.doc.write_bytes(b"Bundle integration test")
        self.key = ECC.generate(curve="P-256")
        self.public_pem = self.root / "public_key.pem"
        self.public_pem.write_text(self.key.public_key().export_key(format="PEM"), encoding="utf-8")
        self.bundle = self.root / "bundle.zip"
        sig = DSS.new(self.key, "deterministic-rfc6979", encoding="binary").sign(SHA256.new(self.doc.read_bytes()))
        manifest = {
            "format": "digital-document-signing-bundle-v1",
            "signature_algorithm": "ECDSA", "curve": "P-256", "hash_algorithm": "SHA-256",
            "document_sha256": SHA256.new(self.doc.read_bytes()).hexdigest(),
            "document_filename": "note.txt", "created_utc": "test"
        }
        with zipfile.ZipFile(self.bundle, "w", zipfile.ZIP_DEFLATED) as z:
            z.write(self.doc, "document/note.txt")
            z.writestr("signature.bin", sig)
            z.write(self.public_pem, "public_key.pem")
            z.writestr("manifest.json", json.dumps(manifest))

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_bundle(self):
        valid, message, details = bundle_utils.verify_signed_bundle(self.bundle, self.key.public_key())
        self.assertTrue(valid, message)
        self.assertEqual(details["document_filename"], "note.txt")

    def test_wrong_trusted_key(self):
        other = ECC.generate(curve="P-256")
        valid, _, _ = bundle_utils.verify_signed_bundle(self.bundle, other.public_key())
        self.assertFalse(valid)

    def test_document_tampering_inside_bundle(self):
        tampered = self.root / "tampered.zip"
        with zipfile.ZipFile(self.bundle, "r") as source, zipfile.ZipFile(tampered, "w") as target:
            for item in source.infolist():
                data = source.read(item.filename)
                if item.filename == "document/note.txt":
                    data = b"Tampered content"
                target.writestr(item.filename, data)
        valid, _, _ = bundle_utils.verify_signed_bundle(tampered, self.key.public_key())
        self.assertFalse(valid)

if __name__ == "__main__":
    unittest.main()
