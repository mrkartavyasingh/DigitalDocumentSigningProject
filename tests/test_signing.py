import tempfile
import unittest
from pathlib import Path
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from verifier import verify_file, public_key_fingerprint

class SignatureUnitTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.doc = self.root / "sample.txt"
        self.doc.write_bytes(b"Original document content.\n")
        self.key = ECC.generate(curve="P-256")
        digest = SHA256.new(self.doc.read_bytes())
        self.signature = DSS.new(self.key, "deterministic-rfc6979", encoding="binary").sign(digest)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_valid_signature(self):
        self.assertTrue(verify_file(self.doc, self.signature, self.key.public_key()))

    def test_document_tampering(self):
        self.doc.write_bytes(b"Modified document content.\n")
        self.assertFalse(verify_file(self.doc, self.signature, self.key.public_key()))

    def test_wrong_public_key(self):
        other = ECC.generate(curve="P-256")
        self.assertFalse(verify_file(self.doc, self.signature, other.public_key()))

    def test_signature_tampering(self):
        bad = bytearray(self.signature)
        bad[0] ^= 1
        self.assertFalse(verify_file(self.doc, bytes(bad), self.key.public_key()))

    def test_fingerprint_is_stable(self):
        self.assertEqual(public_key_fingerprint(self.key.public_key()), public_key_fingerprint(self.key.public_key()))

if __name__ == "__main__":
    unittest.main()
