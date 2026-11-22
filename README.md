# Digital Document Signing and Verification System

A modular Flask application for ECDSA document signing with SHA-256, password-encrypted private-key storage, tamper detection, security tests, and performance benchmarks.

## Important security notes

- The private key is encrypted at rest. The signing password is entered for each signing operation and is not saved by the application.
- Keep `keys/private_key.pem` secret and back it up securely. Never upload it or commit it to Git.
- A signature proves that the document matches a signature made by the corresponding private key. It does not by itself prove a real-world identity.
- Verification must use a trusted public key obtained out-of-band. The app compares the public key embedded in the bundle with its locally trusted `keys/public_key.pem`; it does not blindly trust a public key supplied by an untrusted bundle.
- This is an educational project. For production, add authentication, HTTPS, CSRF protection, rate limiting, malware scanning, audit logging, key rotation/revocation, and deployment hardening.

## 1. Requirements

- Python 3.10+
- pip
- OpenSSL is optional for the core application; it can be used for independent inspection/testing.

## 2. Create a virtual environment

### Windows (PowerShell)
```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Linux/macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 3. Generate keys

Run once:
```bash
python key_manager.py init
```
Choose a strong passphrase when prompted. This creates:
- `keys/private_key.pem` — encrypted ECDSA private key
- `keys/public_key.pem` — public key to distribute through a trusted channel

The app uses NIST P-256 (secp256r1). Protect the `keys/` directory and do not commit the private key.

If you need to generate a fresh key pair, back up or move the existing keys first. Replacing keys means old signatures will no longer match the newly trusted key.

## 4. Start the web app

```bash
python app.py
```
Open `http://127.0.0.1:5000`.

For local development, keep the server bound to localhost. Do not expose the development server to the public internet.

## 5. Sign a document

1. Open **Sign document**.
2. Select a file and enter the private-key passphrase.
3. The app returns a ZIP bundle containing the original document, binary ECDSA signature, public key, and JSON manifest.
4. Keep the ZIP unchanged for verification.

The passphrase is used only to decrypt the private key in memory for that signing operation.

## 6. Verify a document

1. Open **Verify bundle**.
2. Upload the ZIP returned by the signing operation.
3. The app checks the archive for unsafe/ambiguous paths, verifies the manifest and signature, and compares the bundled public key with the locally trusted public key.
4. If the document, signature, manifest, or key has been changed, verification should fail.

For another person's installation to verify your signatures, they must obtain your public key through a trusted, separate channel and install it as `keys/public_key.pem`. A public key sent only inside the same untrusted ZIP is not sufficient to establish signer identity.

## 7. Run tests

```bash
python -m unittest discover -s tests -v
```

The tests cover valid signatures, document tampering, wrong-key verification, signature tampering, and bundle verification.

## 8. Run benchmarks

```bash
python benchmark.py --trials 20 --output results/benchmarks.csv
```

This benchmarks hashing, signing, verification, and total signing/verification time for 1 KB, 100 KB, 1 MB, and 10 MB files. It creates a CSV and a PNG chart in `results/`.

Benchmark results depend on your hardware, Python version, and system load. Run several times and report the median as well as the mean.

## 9. Optional OpenSSL checks

Inspect the public key:
```bash
openssl pkey -pubin -in keys/public_key.pem -text -noout
```
Inspect the encrypted private key metadata (this does not decrypt it):
```bash
openssl pkey -in keys/private_key.pem -text -noout
```
OpenSSL will prompt for the passphrase. This command is an inspection aid; the project uses PyCryptodome for ECDSA signing and verification.

## Project structure

```text
DigitalDocumentSigning/
├── app.py
├── key_manager.py
├── signer.py
├── verifier.py
├── bundle_utils.py
├── benchmark.py
├── requirements.txt
├── keys/                 # created by key_manager.py; do not commit
├── uploads/               # created at runtime
├── results/               # benchmark output
├── templates/
└── tests/
```
