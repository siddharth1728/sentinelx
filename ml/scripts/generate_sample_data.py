"""
generate_sample_data.py - Controlled Defensive Network Flow Dataset Generator for SENTINELX.

Why this module exists:
In Phase 1 of defensive ML research, public benchmark datasets (like NSL-KDD or CIC-IDS)
capture flow-level telemetry. To allow immediate, offline, and reproducible training
without downloading large external archives, this script synthesizes a statistically
grounded network flow dataset simulating:
- Benign normal traffic (HTTP, DNS, SSH, SMTP with SF flags and balanced byte distributions)
- DoS SYN Flood attacks (massive count, S0 flags, zero dst_bytes, rapid connection rate)
- Port Scanning / Reconnaissance (high diff_srv_rate, REJ flags, ICMP/TCP probe patterns)
- SSH/FTP Brute Force attacks (repeated srv_count, failed authentication flag patterns)

Strictly Defensive:
This script only generates synthetic tabular statistical log records for defensive classification.
"""

import os
from pathlib import Path
import numpy as np
import pandas as pd


def generate_network_dataset(
    n_samples: int = 5000,
    random_seed: int = 42,
    output_path: str = "ml/data/raw/network_traffic.csv",
) -> pd.DataFrame:
    """
    Generate synthetic network intrusion flow records.

    Args:
        n_samples: Total number of network flow records to synthesize.
        random_seed: Random seed for reproducible generation.
        output_path: Filepath where the raw CSV should be written.

    Returns:
        pd.DataFrame: The generated network traffic dataset.
    """
    np.random.seed(random_seed)

    # Traffic distribution: 60% Normal, 20% DoS, 12% PortScan, 8% BruteForce
    n_normal = int(n_samples * 0.60)
    n_dos = int(n_samples * 0.20)
    n_portscan = int(n_samples * 0.12)
    n_bruteforce = n_samples - (n_normal + n_dos + n_portscan)

    records = []

    # 1. Normal Traffic Generation
    for _ in range(n_normal):
        proto = np.random.choice(["tcp", "udp", "icmp"], p=[0.75, 0.20, 0.05])
        if proto == "tcp":
            srv = np.random.choice(["http", "https", "ssh", "smtp", "ftp"], p=[0.5, 0.3, 0.1, 0.05, 0.05])
            flag = np.random.choice(["SF", "S0", "REJ"], p=[0.95, 0.03, 0.02])
        elif proto == "udp":
            srv = "dns"
            flag = "SF"
        else:
            srv = "other"
            flag = "SF"

        duration = max(0.0, float(np.random.exponential(scale=2.5)))
        src_bytes = int(np.random.lognormal(mean=6.5, sigma=1.2))
        dst_bytes = int(np.random.lognormal(mean=7.5, sigma=1.5))
        count = int(np.random.poisson(lam=5))
        srv_count = int(np.random.poisson(lam=4))
        same_srv_rate = round(float(np.random.uniform(0.7, 1.0)), 3)
        diff_srv_rate = round(float(np.random.uniform(0.0, 0.3)), 3)
        dst_host_count = int(np.random.randint(1, 100))
        dst_host_srv_count = int(np.random.randint(1, 100))
        dst_host_same_srv_rate = round(float(np.random.uniform(0.6, 1.0)), 3)
        dst_host_diff_srv_rate = round(float(np.random.uniform(0.0, 0.2)), 3)

        records.append({
            "duration": duration,
            "protocol_type": proto,
            "service": srv,
            "flag": flag,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "count": count,
            "srv_count": srv_count,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "dst_host_count": dst_host_count,
            "dst_host_srv_count": dst_host_srv_count,
            "dst_host_same_srv_rate": dst_host_same_srv_rate,
            "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
            "label": "normal",
        })

    # 2. DoS SYN Flood Traffic Generation
    for _ in range(n_dos):
        proto = "tcp"
        srv = np.random.choice(["http", "private", "other"], p=[0.7, 0.2, 0.1])
        flag = np.random.choice(["S0", "RSTOS0"], p=[0.92, 0.08])
        duration = 0.0
        src_bytes = int(np.random.choice([0, 44, 60]))
        dst_bytes = 0  # No handshake response completed
        count = int(np.random.randint(150, 512))
        srv_count = int(np.random.randint(150, 512))
        same_srv_rate = round(float(np.random.uniform(0.95, 1.0)), 3)
        diff_srv_rate = round(float(np.random.uniform(0.0, 0.05)), 3)
        dst_host_count = 255
        dst_host_srv_count = int(np.random.randint(10, 50))
        dst_host_same_srv_rate = round(float(np.random.uniform(0.05, 0.20)), 3)
        dst_host_diff_srv_rate = round(float(np.random.uniform(0.60, 0.90)), 3)

        records.append({
            "duration": duration,
            "protocol_type": proto,
            "service": srv,
            "flag": flag,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "count": count,
            "srv_count": srv_count,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "dst_host_count": dst_host_count,
            "dst_host_srv_count": dst_host_srv_count,
            "dst_host_same_srv_rate": dst_host_same_srv_rate,
            "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
            "label": "dos_syn_flood",
        })

    # 3. Port Scan / Reconnaissance Traffic Generation
    for _ in range(n_portscan):
        proto = np.random.choice(["tcp", "icmp"], p=[0.85, 0.15])
        srv = np.random.choice(["private", "eco_i", "other", "telnet"], p=[0.4, 0.3, 0.2, 0.1])
        flag = np.random.choice(["REJ", "RSTR", "S0"], p=[0.70, 0.20, 0.10])
        duration = round(float(np.random.uniform(0.0, 0.2)), 3)
        src_bytes = int(np.random.choice([0, 20, 40, 64]))
        dst_bytes = 0
        count = int(np.random.randint(50, 200))
        srv_count = int(np.random.randint(1, 5))
        same_srv_rate = round(float(np.random.uniform(0.01, 0.15)), 3)
        diff_srv_rate = round(float(np.random.uniform(0.85, 1.0)), 3)
        dst_host_count = 255
        dst_host_srv_count = int(np.random.randint(1, 15))
        dst_host_same_srv_rate = round(float(np.random.uniform(0.01, 0.08)), 3)
        dst_host_diff_srv_rate = round(float(np.random.uniform(0.70, 0.99)), 3)

        records.append({
            "duration": duration,
            "protocol_type": proto,
            "service": srv,
            "flag": flag,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "count": count,
            "srv_count": srv_count,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "dst_host_count": dst_host_count,
            "dst_host_srv_count": dst_host_srv_count,
            "dst_host_same_srv_rate": dst_host_same_srv_rate,
            "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
            "label": "port_scan",
        })

    # 4. SSH/FTP Brute Force Traffic Generation
    for _ in range(n_bruteforce):
        proto = "tcp"
        srv = np.random.choice(["ssh", "ftp"], p=[0.75, 0.25])
        flag = np.random.choice(["SF", "REJ"], p=[0.60, 0.40])
        duration = round(float(np.random.uniform(0.5, 3.0)), 2)
        src_bytes = int(np.random.normal(loc=350, scale=40))
        dst_bytes = int(np.random.normal(loc=220, scale=30))
        count = int(np.random.randint(30, 90))
        srv_count = int(np.random.randint(25, 80))
        same_srv_rate = round(float(np.random.uniform(0.90, 1.0)), 3)
        diff_srv_rate = round(float(np.random.uniform(0.0, 0.10)), 3)
        dst_host_count = int(np.random.randint(100, 255))
        dst_host_srv_count = int(np.random.randint(20, 80))
        dst_host_same_srv_rate = round(float(np.random.uniform(0.70, 0.95)), 3)
        dst_host_diff_srv_rate = round(float(np.random.uniform(0.02, 0.15)), 3)

        records.append({
            "duration": duration,
            "protocol_type": proto,
            "service": srv,
            "flag": flag,
            "src_bytes": max(0, src_bytes),
            "dst_bytes": max(0, dst_bytes),
            "count": count,
            "srv_count": srv_count,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "dst_host_count": dst_host_count,
            "dst_host_srv_count": dst_host_srv_count,
            "dst_host_same_srv_rate": dst_host_same_srv_rate,
            "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
            "label": "ssh_bruteforce",
        })

    # Shuffle dataset
    df = pd.DataFrame(records).sample(frac=1.0, random_state=random_seed).reset_index(drop=True)

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_file, index=False)

    print(f"[SENTINELX] Synthetic network dataset successfully created at: {out_file.resolve()}")
    print(f"[SENTINELX] Total Records: {len(df):,}")
    print("[SENTINELX] Class Distribution:")
    for label, count in df["label"].value_counts().items():
        print(f"  - {label:<16}: {count:>5} ({count/len(df)*100:.1f}%)")

    return df


if __name__ == "__main__":
    generate_network_dataset()
