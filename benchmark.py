"""Benchmark SHA-256, ECDSA signing, verification and total operation times."""
import argparse
import csv
import statistics
import tempfile
from pathlib import Path
from time import perf_counter
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

SIZES = [("1KB", 1024), ("100KB", 100 * 1024), ("1MB", 1024 * 1024), ("10MB", 10 * 1024 * 1024)]

def make_data(size):
    # Deterministic data generation; generate once outside timed sections.
    block = b"Digital Document Signing Benchmark|"
    return (block * (size // len(block) + 1))[:size]

def run_benchmark(trials=20, output="results/benchmarks.csv"):
    if trials < 1:
        raise ValueError("trials must be at least 1")
    key = ECC.generate(curve="P-256")
    pub = key.public_key()
    signer = DSS.new(key, "deterministic-rfc6979", encoding="binary")
    verifier = DSS.new(pub, "fips-186-3", encoding="binary")
    rows = []
    for label, size in SIZES:
        data = make_data(size)
        hash_times, sign_times, verify_times, total_sign_times, total_verify_times = [], [], [], [], []
        for _ in range(trials):
            t0 = perf_counter()
            digest = SHA256.new(data)
            hash_times.append(perf_counter() - t0)

            t1 = perf_counter()
            digest = SHA256.new(data)
            signature = signer.sign(digest)
            total_sign_times.append(perf_counter() - t1)
            # Isolate signature operation using a precomputed digest.
            digest_for_sign = SHA256.new(data)
            t2 = perf_counter()
            signature = signer.sign(digest_for_sign)
            sign_times.append(perf_counter() - t2)

            digest_for_verify = SHA256.new(data)
            t3 = perf_counter()
            verifier.verify(digest_for_verify, signature)
            verify_times.append(perf_counter() - t3)

            t4 = perf_counter()
            verifier.verify(SHA256.new(data), signature)
            total_verify_times.append(perf_counter() - t4)

        rows.append({
            "size_label": label, "document_bytes": size, "trials": trials,
            "hash_mean_ms": statistics.mean(hash_times) * 1000,
            "hash_median_ms": statistics.median(hash_times) * 1000,
            "sign_mean_ms": statistics.mean(sign_times) * 1000,
            "sign_median_ms": statistics.median(sign_times) * 1000,
            "verify_mean_ms": statistics.mean(verify_times) * 1000,
            "verify_median_ms": statistics.median(verify_times) * 1000,
            "sign_total_mean_ms": statistics.mean(total_sign_times) * 1000,
            "verify_total_mean_ms": statistics.mean(total_verify_times) * 1000,
            "signature_bytes": len(signature),
        })
    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots()
        x = [r["size_label"] for r in rows]
        ax.plot(x, [r["hash_mean_ms"] for r in rows], marker="o", label="SHA-256")
        ax.plot(x, [r["sign_total_mean_ms"] for r in rows], marker="o", label="Hash + sign")
        ax.plot(x, [r["verify_total_mean_ms"] for r in rows], marker="o", label="Hash + verify")
        ax.set_title("Document signing performance")
        ax.set_xlabel("Document size")
        ax.set_ylabel("Mean time (ms)")
        ax.grid(True, alpha=0.25)
        ax.legend()
        fig.tight_layout()
        chart = out.with_suffix(".png")
        fig.savefig(chart, dpi=160)
        plt.close(fig)
        print(f"Chart saved to: {chart}")
    except ImportError:
        print("Matplotlib not installed; CSV was created without a chart.")
    print(f"CSV saved to: {out}")
    for row in rows:
        print(f'{row["size_label"]:>5}: hash {row["hash_mean_ms"]:.3f} ms | '
              f'sign {row["sign_mean_ms"]:.3f} ms | verify {row["verify_mean_ms"]:.3f} ms')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--output", default="results/benchmarks.csv")
    args = parser.parse_args()
    run_benchmark(args.trials, args.output)
