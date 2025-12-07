import argparse
import json
import os
import time

import pandas as pd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Filter large CSV by DDOS IPs using chunked processing")
    parser.add_argument(
        "input",
        nargs='+',
        help="Path(s) to input CSV file(s) - can specify multiple files",
    )
    parser.add_argument(
        "--output",
        default="decoded_pcap_data_set1_full_ddos.csv",
        help="Path to output CSV file",
    )
    parser.add_argument(
        "--ip-map",
        default="full_ip_map.json",
        dest="ip_map_path",
        help="Path to JSON mapping of IP string to integer id",
    )
    parser.add_argument(
        "--chunksize",
        type=int,
        default=1000000,
        help="Number of rows per chunk when reading the input CSV",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Load the mapping file
    with open(args.ip_map_path, "r") as f:
        ip_map = json.load(f)

    # Default IPs extracted from the provided image; used if no IPs are passed
    extracted_ips = [
        "172.28.3.121",
        "172.28.213.189",
        "172.28.214.102",
        "172.28.23.163",
        "172.28.197.120",
        "77.91.104.22",
        "201.89.32.16",
        "68.91.226.37",
        "172.28.3.242",
        "172.28.16.39",
        "172.28.3.56",
        "172.28.13.198",
        "172.28.133.17",
        "172.28.220.39",
        "172.28.12.167",
        "172.28.13.29",
        "172.28.6.9",
        "172.28.27.162",
        "172.28.197.210",
        "172.28.196.167",
        "172.28.212.207",
        "172.28.218.87",
        "172.28.5.81",
        "172.28.27.31",
        "172.28.11.182",
        "172.28.218.214",
        "172.28.133.166",
        "172.28.209.155",
        "172.28.219.150",
        "172.28.12.45",
        "172.28.222.131",
        "172.28.132.105",
        "172.28.198.83",
        "172.28.6.47",
        "172.28.211.200",
        "172.28.14.161",
        "172.28.128.124",
        "172.28.212.131",
        "172.28.211.212",
        "172.28.11.150",
        "172.28.130.107",
        "172.28.131.186",
        "172.28.212.85",
        "172.28.2.148",
        "172.28.194.173",
        "172.28.214.23",
        "172.28.16.212",
        "172.28.15.104",
        "172.28.128.218",
        "70.98.1.1",
        "66.200.1.1",
        "24.145.1.1",
        "64.180.1.1",
        "172.28.3.248",
        "172.28.8.210",
        "172.28.132.25",
        "172.28.22.122",
        "172.28.198.147",
        "172.28.2.90",
        "172.28.3.39",
        "172.28.6.48",
        "172.28.130.83",
        "172.28.6.170",
        "44.29.203.5",
        "123.44.92.173",
        "64.222.102.58",
    ]

    # Convert IPs to integers using the mapping and drop missing
    ddos_ids = {ip_map[ip] for ip in extracted_ips if ip in ip_map}

    # Ensure we start fresh
    if os.path.exists(args.output):
        os.remove(args.output)

    print(f"Processing {len(args.input)} input file(s)...")
    print(f"DDoS IPs to filter: {len(ddos_ids)} unique IPs")

    overall_start_time = time.time()
    overall_total_rows = 0
    overall_total_matched = 0

    # Process each input file
    for file_index, input_file in enumerate(args.input, start=1):
        print(f"\n[{file_index}/{len(args.input)}] Reading '{input_file}' in chunks of {args.chunksize:,} rows...")

        if not os.path.exists(input_file):
            print(f"  WARNING: File not found, skipping: {input_file}")
            continue

        file_start_time = time.time()
        file_total_rows = 0
        file_total_matched = 0
        chunk_index = 0

        # Stream input CSV in chunks and write matching rows incrementally
        for chunk in pd.read_csv(input_file, chunksize=args.chunksize):
            chunk_index += 1
            file_total_rows += len(chunk)
            overall_total_rows += len(chunk)

            if "src_ip" not in chunk.columns or "dst_ip" not in chunk.columns:
                # If required columns are missing, skip this chunk
                continue

            # src_ip and dst_ip might be floats or strings; coerce to nullable Int64 before matching
            src_ids = pd.to_numeric(chunk["src_ip"], errors="coerce").astype("Int64")
            dst_ids = pd.to_numeric(chunk["dst_ip"], errors="coerce").astype("Int64")
            mask = src_ids.isin(ddos_ids) | dst_ids.isin(ddos_ids)
            filtered_chunk = chunk[mask]
            matched_count = len(filtered_chunk)
            file_total_matched += matched_count
            overall_total_matched += matched_count

            if not filtered_chunk.empty:
                # Write header only on first write (file doesn't exist because we removed it)
                write_header = not os.path.exists(args.output)
                filtered_chunk.to_csv(args.output, index=False, mode="a", header=write_header)

            print(
                f"  Chunk {chunk_index}: processed {len(chunk):,} rows (file total {file_total_rows:,}); matched {matched_count:,} (file total {file_total_matched:,})"
            )

        file_elapsed = time.time() - file_start_time
        print(f"  File complete: {file_total_rows:,} rows processed, {file_total_matched:,} matched in {file_elapsed:.2f}s")

    overall_elapsed = time.time() - overall_start_time
    print(f"\n{'='*80}")
    if os.path.exists(args.output):
        print(
            f"All files processed. Wrote {overall_total_matched:,} matched rows to '{args.output}' in {overall_elapsed:.2f}s."
        )
        print(f"Total rows processed: {overall_total_rows:,}")
    else:
        print(
            f"All files processed. No matches found after processing {overall_total_rows:,} rows in {overall_elapsed:.2f}s."
        )


if __name__ == "__main__":
    main()
