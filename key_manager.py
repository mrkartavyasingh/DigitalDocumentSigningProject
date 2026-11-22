"""Create and load encrypted ECDSA keys."""
from pathlib import Path
import getpass
from Crypto.PublicKey import ECC

BASE_DIR = Path(__file__).resolve().parent
KEY_DIR = BASE_DIR / "keys"
PRIVATE_KEY_PATH = KEY_DIR / "private_key.pem"
PUBLIC_KEY_PATH = KEY_DIR / "public_key.pem"

def generate_keys(passphrase: str, overwrite: bool = False):
    if not passphrase or len(passphrase) < 12:
        raise ValueError("Use a passphrase of at least 12 characters.")
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    if not overwrite and (PRIVATE_KEY_PATH.exists() or PUBLIC_KEY_PATH.exists()):
        raise FileExistsError("Keys already exist. Back them up or move them before generating replacements.")
    key = ECC.generate(curve="P-256")
    private_pem = key.export_key(
        format="PEM",
        passphrase=passphrase,
        protection="PBKDF2WithHMAC-SHA512AndAES256-CBC",
        prot_params={"iteration_count": 131072},
    )
    public_pem = key.public_key().export_key(format="PEM")
    PRIVATE_KEY_PATH.write_text(private_pem, encoding="utf-8")
    try:
        PRIVATE_KEY_PATH.chmod(0o600)
    except OSError:
        pass
    PUBLIC_KEY_PATH.write_text(public_pem, encoding="utf-8")
    return PRIVATE_KEY_PATH, PUBLIC_KEY_PATH

def load_private_key(passphrase: str):
    if not PRIVATE_KEY_PATH.exists():
        raise FileNotFoundError("Private key not found. Run: python key_manager.py init")
    try:
        key = ECC.import_key(PRIVATE_KEY_PATH.read_text(encoding="utf-8"), passphrase=passphrase)
    except (ValueError, IndexError) as exc:
        raise ValueError("Could not decrypt private key. Check the passphrase.") from exc
    if key.has_private() is False:
        raise ValueError("Configured key does not contain a private key.")
    return key

def load_public_key(path=PUBLIC_KEY_PATH):
    if not Path(path).exists():
        raise FileNotFoundError("Trusted public key not found. Run: python key_manager.py init")
    key = ECC.import_key(Path(path).read_text(encoding="utf-8"))
    if key.has_private():
        key = key.public_key()
    return key

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Manage ECDSA keys")
    parser.add_argument("command", choices=["init", "public-key"])
    args = parser.parse_args()
    if args.command == "init":
        first = getpass.getpass("New private-key passphrase (minimum 12 characters): ")
        second = getpass.getpass("Confirm passphrase: ")
        if first != second:
            raise SystemExit("Passphrases do not match.")
        try:
            priv, pub = generate_keys(first)
        except (ValueError, FileExistsError) as exc:
            raise SystemExit(str(exc))
        print(f"Encrypted private key: {priv}")
        print(f"Public key: {pub}")
        print("Keep the private key secret. Distribute the public key only through a trusted channel.")
    else:
        if not PUBLIC_KEY_PATH.exists():
            raise SystemExit("Public key not found. Run: python key_manager.py init")
        print(PUBLIC_KEY_PATH.read_text(encoding="utf-8"))
