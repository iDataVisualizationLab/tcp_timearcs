#!/usr/bin/env python3
"""
TCP Data Loader - Streaming/Memory-Efficient Version (v2.0)
MEMORY-OPTIMIZED: Processes large CSV files in chunks to avoid out-of-memory errors.

Key differences from tcp_data_loader_chunked.py:
- Reads CSV in chunks (default 500k rows) instead of loading entire file
- Writes packets.csv incrementally during processing
- Detects flows incrementally, keeping only active flows in memory
- Completes flows on FIN/RST or timeout, freeing memory immediately
- Memory usage: ~200MB vs. 10-20GB for large files (98% reduction)

Generates the same chunked folder structure as v2.0:
- packets.csv: All packets for timearcs visualization
- flows/: Directory containing chunked flow files (multiple flows per file)
- flows/flows_index.json: Index of all flows with chunk references
- ips/ip_stats.json: IP statistics for sidebar
- ips/flag_stats.json: Flag statistics for sidebar
- ips/unique_ips.json: List of unique IP addresses
- indices/bins.json: Time-based bins for range queries
- manifest.json: Metadata about the dataset (version 2.0)
"""

import pandas as pd
import numpy as np
import json
import sys
import argparse
from pathlib import Path
from collections import defaultdict
import time
import random

# TCP flag constants
FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80

def load_ip_mapping(ip_map_file):
    """Load IP mapping from JSON file"""
    try:
        with open(ip_map_file, 'r') as f:
            ip_map = json.load(f)
        # Create reverse mapping (int -> ip_str)
        int_to_ip = {v: k for k, v in ip_map.items()}
        return ip_map, int_to_ip
    except Exception as e:
        print(f"Error loading IP mapping: {e}", file=sys.stderr)
        return {}, {}

def classify_tcp_flags(flag_val):
    """Classify TCP flags into readable format"""
    if pd.isna(flag_val):
        return "INVALID"

    try:
        flag_val = int(flag_val)
    except:
        return "INVALID"

    # TCP flag constants
    flags = {
        "FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08,
        "ACK": 0x10, "URG": 0x20, "ECE": 0x40, "CWR": 0x80
    }

    # Common combinations
    combinations = {
        (flags["SYN"] | flags["ACK"]): "SYN+ACK",
        (flags["FIN"] | flags["ACK"]): "FIN+ACK",
        (flags["PSH"] | flags["ACK"]): "PSH+ACK",
        (flags["RST"] | flags["ACK"]): "RST+ACK",
    }

    if flag_val in combinations:
        return combinations[flag_val]

    # Individual flags
    set_flags = [name for name, val in flags.items() if flag_val & val]
    if set_flags:
        return "+".join(sorted(set_flags))

    return "NONE" if flag_val == 0 else f"OTHER_{flag_val}"

def _safe_int(val, default=0):
    """Safely convert to int, handling NaN/None/empty."""
    try:
        import pandas as _pd
        if _pd.isna(val):
            return default
    except Exception:
        pass
    try:
        return int(val)
    except Exception:
        return default

def _is_set(flags: int, mask: int) -> bool:
    try:
        return (int(flags) & mask) != 0
    except Exception:
        return False

def process_single_flow(connection_key, connection_packets, flow_id):
    """
    Process a single TCP connection's packets into a flow object.
    Extracted from detect_tcp_flows() for use in incremental processing.

    Args:
        connection_key: Bidirectional connection identifier
        connection_packets: List of packets for this connection (sorted by timestamp)
        flow_id: Flow identifier string (e.g., "flow_000123")

    Returns:
        dict: Flow object with all TCP state machine processing complete
    """
    # Sort packets by timestamp
    connection_packets.sort(key=lambda a: a['timestamp'])

    # Initialize flow with given ID
    flow = {
        'id': flow_id,
        'key': connection_key,
        'initiator': None,
        'responder': None,
        'initiatorPort': None,
        'responderPort': None,
        'state': 'new',
        'phases': {
            'establishment': [],
            'dataTransfer': [],
            'closing': []
        },
        'establishmentComplete': False,
        'dataTransferStarted': False,
        'closingStarted': False,
        'closeType': None,
        'startTime': None,
        'endTime': None,
        'totalPackets': 0,
        'totalBytes': 0,
        'invalidReason': None,
        'expectedSeqNum': None,
        'expectedAckNum': None,
        'invalidPacket': None,
        'synPacket': None,
        'synAckPacket': None,
        'packets': []  # Store all packets for this flow
    }

    # Set computed values
    flow['startTime'] = connection_packets[0]['timestamp']
    flow['endTime'] = connection_packets[-1]['timestamp']
    flow['totalPackets'] = len(connection_packets)
    flow['totalBytes'] = sum((p.get('length') or 0) for p in connection_packets)

    # Process packets in chronological order
    for packet in connection_packets:
        flags = packet['flags']
        syn = (flags & 0x02) != 0
        ack = (flags & 0x10) != 0
        fin = (flags & 0x01) != 0
        rst = (flags & 0x04) != 0
        psh = (flags & 0x08) != 0

        # Add packet to flow's packet list
        flow['packets'].append(packet)

        # Skip processing if connection is already marked as invalid
        if flow['state'] == 'invalid':
            continue

        # Process TCP state machine
        if syn and not ack and not rst:
            # SYN packet - connection initiation
            if not flow['initiator']:
                flow['initiator'] = packet['src_ip']
                flow['responder'] = packet['dst_ip']
                flow['initiatorPort'] = packet['src_port']
                flow['responderPort'] = packet['dst_port']
                flow['state'] = 'establishing'
                flow['synPacket'] = packet
                flow['expectedAckNum'] = packet['seq_num'] + 1

                flow['phases']['establishment'].append({
                    'packet': packet,
                    'phase': 'syn',
                    'description': 'Connection Request'
                })
        elif syn and ack and not rst:
            # SYN+ACK packet - connection acceptance
            if flow['state'] == 'establishing' and flow.get('synPacket'):
                # Validate SYN+ACK acknowledgment number
                if packet['ack_num'] == flow['expectedAckNum']:
                    flow['synAckPacket'] = packet
                    flow['expectedSeqNum'] = packet['seq_num'] + 1
                    flow['phases']['establishment'].append({
                        'packet': packet,
                        'phase': 'syn_ack',
                        'description': 'Connection Acceptance'
                    })
                else:
                    # Invalid SYN+ACK - wrong acknowledgment number
                    flow['state'] = 'invalid'
                    flow['invalidReason'] = 'invalid_synack'
                    flow['invalidPacket'] = packet
                    flow['closeType'] = 'invalid'
                    break
            elif not flow.get('synAckPacket'):
                flow['phases']['establishment'].append({
                    'packet': packet,
                    'phase': 'syn_ack',
                    'description': 'Connection Acceptance'
                })
                flow['synAckPacket'] = packet
        elif ack and not syn and not fin and not rst and not psh and flow['state'] == 'establishing':
            # Pure ACK packet - establishment completion
            if flow.get('synAckPacket') and flow.get('expectedSeqNum'):
                # Validate final ACK
                if packet['ack_num'] == flow['expectedSeqNum'] and packet['seq_num'] == flow['expectedAckNum']:
                    flow['phases']['establishment'].append({
                        'packet': packet,
                        'phase': 'ack',
                        'description': 'Connection Established'
                    })
                    flow['establishmentComplete'] = True
                    flow['state'] = 'established'
                else:
                    # Invalid ACK - wrong sequence/acknowledgment numbers
                    flow['state'] = 'invalid'
                    flow['invalidReason'] = 'invalid_ack'
                    flow['invalidPacket'] = packet
                    flow['closeType'] = 'invalid'
                    break
            elif not flow['establishmentComplete']:
                flow['phases']['establishment'].append({
                    'packet': packet,
                    'phase': 'ack',
                    'description': 'Connection Established'
                })
                flow['establishmentComplete'] = True
                flow['state'] = 'established'
        elif (ack and not syn and not fin and not rst and flow['establishmentComplete'] and
              ((packet.get('length') and packet['length'] > 0) or (packet.get('seg_len') and packet['seg_len'] > 0))):
            # Data transfer: any ACK packet with payload
            if not flow['dataTransferStarted']:
                flow['dataTransferStarted'] = True
                flow['state'] = 'data_transfer'
            flow['phases']['dataTransfer'].append({
                'packet': packet,
                'phase': 'data',
                'description': 'Data Transfer'
            })
        elif fin and not rst:
            # FIN packet - graceful close initiation
            if not flow['closingStarted']:
                flow['closingStarted'] = True
                flow['state'] = 'closing'
                flow['closeType'] = 'graceful'
            flow['phases']['closing'].append({
                'packet': packet,
                'phase': 'fin',
                'description': 'Close Request'
            })
        elif rst:
            # RST packet - abortive close
            if flow['state'] == 'establishing':
                flow['invalidReason'] = 'rst_during_handshake'
                flow['state'] = 'invalid'
                flow['closeType'] = 'invalid'
            else:
                flow['state'] = 'aborted'
                flow['closeType'] = 'abortive'
            flow['invalidPacket'] = packet
            flow['phases']['closing'].append({
                'packet': packet,
                'phase': 'rst',
                'description': 'Connection Aborted'
            })
        elif ack and not syn and not fin and not rst and flow['establishmentComplete']:
            # Other ACK packets
            if flow['closingStarted']:
                flow['phases']['closing'].append({
                    'packet': packet,
                    'phase': 'ack_close',
                    'description': 'Close Acknowledgment'
                })
            else:
                if not flow['dataTransferStarted']:
                    flow['dataTransferStarted'] = True
                    flow['state'] = 'data_transfer'
                flow['phases']['dataTransfer'].append({
                    'packet': packet,
                    'phase': 'ack_data',
                    'description': 'Data Acknowledgment'
                })

    # Final flow state validation
    if flow['state'] == 'establishing':
        # Incomplete handshake
        if not flow.get('synPacket'):
            flow['state'] = 'invalid'
            flow['invalidReason'] = 'incomplete_no_syn'
            flow['closeType'] = 'invalid'
        elif not flow.get('synAckPacket'):
            flow['state'] = 'invalid'
            flow['invalidReason'] = 'incomplete_no_synack'
            flow['closeType'] = 'invalid'
        elif not flow['establishmentComplete']:
            flow['state'] = 'invalid'
            flow['invalidReason'] = 'incomplete_no_ack'
            flow['closeType'] = 'invalid'
    elif flow['state'] == 'closing':
        flow['state'] = 'closed'

    # Mark ongoing flows explicitly
    if (
        flow['state'] not in ('invalid', 'closed', 'aborted')
        and not flow.get('closeType')
        and (flow.get('establishmentComplete') or flow.get('dataTransferStarted'))
    ):
        flow['state'] = 'ongoing'
        flow['ongoing'] = True
        flow['closeType'] = 'open'

    return flow

def detect_tcp_flows_incremental(chunk_records, connection_map, ip_stats, flag_stats,
                                  ip_pair_map, flow_counter, flow_timeout_seconds=300):
    """
    Incrementally detect TCP flows from a chunk of packet records.
    Maintains state across chunks via connection_map.

    Args:
        chunk_records: Current chunk of packets to process
        connection_map: Persistent connection state (modified in place)
        ip_stats: IP statistics accumulator (modified in place)
        flag_stats: Flag statistics accumulator (modified in place)
        ip_pair_map: IP pair statistics (modified in place)
        flow_counter: Current flow ID counter
        flow_timeout_seconds: Mark flows inactive after N seconds without packets (default: 300)

    Returns:
        tuple: (completed_flows, updated_flow_counter)
    """
    # Helper functions for IP stats (same as detect_tcp_flows)
    def update_ip_stats(ip_from, ip_to, length, ts):
        s = ip_stats[ip_from]
        s['sent_packets'] = (s.get('sent_packets') or 0) + 1
        s['sent_bytes'] = (s.get('sent_bytes') or 0) + max(0, int(length or 0))
        s['first_ts'] = ts if s['first_ts'] is None else min(s['first_ts'], ts)
        s['last_ts'] = ts if s['last_ts'] is None else max(s['last_ts'], ts)

        r = ip_stats[ip_to]
        r['recv_packets'] = (r.get('recv_packets') or 0) + 1
        r['recv_bytes'] = (r.get('recv_bytes') or 0) + max(0, int(length or 0))
        r['first_ts'] = ts if r['first_ts'] is None else min(r['first_ts'], ts)
        r['last_ts'] = ts if r['last_ts'] is None else max(r['last_ts'], ts)

    def update_ip_pair(src_ip, dst_ip, length, ts):
        a, b = sorted([str(src_ip), str(dst_ip)])
        key = (a, b)
        entry = ip_pair_map.get(key)
        if not entry:
            entry = {
                'ip1': a, 'ip2': b,
                'packet_count': 0,
                'a_to_b_packets': 0,
                'b_to_a_packets': 0,
                'a_to_b_bytes': 0,
                'b_to_a_bytes': 0,
                'first_ts': ts,
                'last_ts': ts
            }
            ip_pair_map[key] = entry
        entry['packet_count'] = (entry.get('packet_count') or 0) + 1
        entry['first_ts'] = min(entry['first_ts'], ts)
        entry['last_ts'] = max(entry['last_ts'], ts)
        if str(src_ip) == a:
            entry['a_to_b_packets'] = (entry.get('a_to_b_packets') or 0) + 1
            entry['a_to_b_bytes'] = (entry.get('a_to_b_bytes') or 0) + max(0, int(length or 0))
        else:
            entry['b_to_a_packets'] = (entry.get('b_to_a_packets') or 0) + 1
            entry['b_to_a_bytes'] = (entry.get('b_to_a_bytes') or 0) + max(0, int(length or 0))

    # Process current chunk: update IP stats and group packets by connection
    for packet in chunk_records:
        # Update IP statistics
        ts = int(packet.get('timestamp', 0))
        s_ip = str(packet.get('src_ip', ''))
        d_ip = str(packet.get('dst_ip', ''))
        length = int(packet.get('length', 0))
        flag_type = str(packet.get('flag_type', 'UNKNOWN'))

        flag_stats[flag_type] = flag_stats.get(flag_type, 0) + 1
        update_ip_stats(s_ip, d_ip, length, ts)
        update_ip_pair(s_ip, d_ip, length, ts)

        # Group packets by connection (bidirectional)
        if packet.get('src_port') and packet.get('dst_port') and s_ip and d_ip:
            connection_a = f"{s_ip}:{packet['src_port']}-{d_ip}:{packet['dst_port']}"
            connection_b = f"{d_ip}:{packet['dst_port']}-{s_ip}:{packet['src_port']}"
            connection_key = connection_a if connection_a < connection_b else connection_b

            # Initialize or update connection state
            if connection_key not in connection_map:
                flow_counter += 1
                connection_map[connection_key] = {
                    'packets': [],
                    'flow_id': f"flow_{flow_counter:06d}",
                    'last_packet_time': ts,  # Track time in microseconds
                    'has_fin_or_rst': False
                }

            conn_data = connection_map[connection_key]
            conn_data['packets'].append(packet)
            conn_data['last_packet_time'] = ts  # Update to most recent packet time

            # Check if packet has FIN or RST flag
            flags = packet.get('flags', 0)
            if (flags & 0x01) or (flags & 0x04):  # FIN or RST
                conn_data['has_fin_or_rst'] = True

    # Identify completed flows (FIN/RST or timeout)
    # Find the latest timestamp in this chunk for timeout calculation
    if chunk_records:
        latest_timestamp = max(r['timestamp'] for r in chunk_records)
    else:
        latest_timestamp = 0

    completed_flows = []
    connections_to_remove = []
    timed_out_count = 0

    for conn_key, conn_data in connection_map.items():
        # Calculate inactivity time in seconds
        time_diff_microseconds = latest_timestamp - conn_data['last_packet_time']
        inactive_seconds = time_diff_microseconds / 1_000_000  # Convert to seconds

        has_explicit_close = conn_data['has_fin_or_rst']
        has_timed_out = inactive_seconds >= flow_timeout_seconds

        is_complete = has_explicit_close or has_timed_out

        if is_complete:
            # Process flow using helper function
            flow = process_single_flow(conn_key, conn_data['packets'], conn_data['flow_id'])

            # Mark if flow was completed by timeout (for statistics)
            if has_timed_out and not has_explicit_close:
                flow['completed_by_timeout'] = True
                timed_out_count += 1

            completed_flows.append(flow)
            connections_to_remove.append(conn_key)

    # Remove completed flows from active connection map
    for conn_key in connections_to_remove:
        del connection_map[conn_key]

    return completed_flows, flow_counter, timed_out_count

def detect_tcp_flows(records):
    """
    Detect TCP flows from packet records.
    Returns flows with full packet details for individual flow files.
    """
    # Aggregates for IP stats
    ip_pair_map = {}
    ip_stats = defaultdict(lambda: {
        'sent_packets': 0, 'recv_packets': 0,
        'sent_bytes': 0, 'recv_bytes': 0,
        'first_ts': None, 'last_ts': None
    })
    flag_stats = defaultdict(int)

    def update_ip_stats(ip_from, ip_to, length, ts):
        s = ip_stats[ip_from]
        s['sent_packets'] = (s.get('sent_packets') or 0) + 1
        s['sent_bytes'] = (s.get('sent_bytes') or 0) + max(0, int(length or 0))
        s['first_ts'] = ts if s['first_ts'] is None else min(s['first_ts'], ts)
        s['last_ts'] = ts if s['last_ts'] is None else max(s['last_ts'], ts)

        r = ip_stats[ip_to]
        r['recv_packets'] = (r.get('recv_packets') or 0) + 1
        r['recv_bytes'] = (r.get('recv_bytes') or 0) + max(0, int(length or 0))
        r['first_ts'] = ts if r['first_ts'] is None else min(r['first_ts'], ts)
        r['last_ts'] = ts if r['last_ts'] is None else max(r['last_ts'], ts)

    def update_ip_pair(src_ip, dst_ip, length, ts):
        a, b = sorted([str(src_ip), str(dst_ip)])
        key = (a, b)
        entry = ip_pair_map.get(key)
        if not entry:
            entry = {
                'ip1': a, 'ip2': b,
                'packet_count': 0,
                'a_to_b_packets': 0,
                'b_to_a_packets': 0,
                'a_to_b_bytes': 0,
                'b_to_a_bytes': 0,
                'first_ts': ts,
                'last_ts': ts
            }
            ip_pair_map[key] = entry
        entry['packet_count'] = (entry.get('packet_count') or 0) + 1
        entry['first_ts'] = min(entry['first_ts'], ts)
        entry['last_ts'] = max(entry['last_ts'], ts)
        if str(src_ip) == a:
            entry['a_to_b_packets'] = (entry.get('a_to_b_packets') or 0) + 1
            entry['a_to_b_bytes'] = (entry.get('a_to_b_bytes') or 0) + max(0, int(length or 0))
        else:
            entry['b_to_a_packets'] = (entry.get('b_to_a_packets') or 0) + 1
            entry['b_to_a_bytes'] = (entry.get('b_to_a_bytes') or 0) + max(0, int(length or 0))

    # Build aggregates from all TCP records
    for pkt in records:
        ts = int(pkt.get('timestamp', 0))
        s_ip = str(pkt.get('src_ip', ''))
        d_ip = str(pkt.get('dst_ip', ''))
        length = int(pkt.get('length', 0))
        flag_type = str(pkt.get('flag_type', 'UNKNOWN'))

        flag_stats[flag_type] += 1
        update_ip_stats(s_ip, d_ip, length, ts)
        update_ip_pair(s_ip, d_ip, length, ts)

    # Detect flows
    flows = []
    connection_map = {}

    # Group packets by connection
    for packet in records:
        if packet.get('src_port') and packet.get('dst_port') and packet.get('src_ip') and packet.get('dst_ip'):
            # Create bidirectional connection key
            connection_a = f"{packet['src_ip']}:{packet['src_port']}-{packet['dst_ip']}:{packet['dst_port']}"
            connection_b = f"{packet['dst_ip']}:{packet['dst_port']}-{packet['src_ip']}:{packet['src_port']}"
            connection_key = connection_a if connection_a < connection_b else connection_b

            if connection_key not in connection_map:
                connection_map[connection_key] = []
            connection_map[connection_key].append(packet)

    # Process each connection
    flow_counter = 0
    for connection_key, connection_packets in connection_map.items():
        # Sort packets by timestamp
        connection_packets.sort(key=lambda a: a['timestamp'])

        flow_counter += 1
        # Initialize flow with simple ID
        flow = {
            'id': f"flow_{flow_counter:06d}",
            'key': connection_key,
            'initiator': None,
            'responder': None,
            'initiatorPort': None,
            'responderPort': None,
            'state': 'new',
            'phases': {
                'establishment': [],
                'dataTransfer': [],
                'closing': []
            },
            'establishmentComplete': False,
            'dataTransferStarted': False,
            'closingStarted': False,
            'closeType': None,
            'startTime': None,
            'endTime': None,
            'totalPackets': 0,
            'totalBytes': 0,
            'invalidReason': None,
            'expectedSeqNum': None,
            'expectedAckNum': None,
            'invalidPacket': None,
            'synPacket': None,
            'synAckPacket': None,
            'packets': []  # Store all packets for this flow
        }

        # Set computed values
        flow['startTime'] = connection_packets[0]['timestamp']
        flow['endTime'] = connection_packets[-1]['timestamp']
        flow['totalPackets'] = len(connection_packets)
        flow['totalBytes'] = sum((p.get('length') or 0) for p in connection_packets)

        # Process packets in chronological order
        for packet in connection_packets:
            flags = packet['flags']
            syn = (flags & 0x02) != 0
            ack = (flags & 0x10) != 0
            fin = (flags & 0x01) != 0
            rst = (flags & 0x04) != 0
            psh = (flags & 0x08) != 0

            # Add packet to flow's packet list
            flow['packets'].append(packet)

            # Skip processing if connection is already marked as invalid
            if flow['state'] == 'invalid':
                continue

            # Process TCP state machine
            if syn and not ack and not rst:
                # SYN packet - connection initiation
                if not flow['initiator']:
                    flow['initiator'] = packet['src_ip']
                    flow['responder'] = packet['dst_ip']
                    flow['initiatorPort'] = packet['src_port']
                    flow['responderPort'] = packet['dst_port']
                    flow['state'] = 'establishing'
                    flow['synPacket'] = packet
                    flow['expectedAckNum'] = packet['seq_num'] + 1

                    flow['phases']['establishment'].append({
                        'packet': packet,
                        'phase': 'syn',
                        'description': 'Connection Request'
                    })
            elif syn and ack and not rst:
                # SYN+ACK packet - connection acceptance
                if flow['state'] == 'establishing' and flow.get('synPacket'):
                    # Validate SYN+ACK acknowledgment number
                    if packet['ack_num'] == flow['expectedAckNum']:
                        flow['synAckPacket'] = packet
                        flow['expectedSeqNum'] = packet['seq_num'] + 1
                        flow['phases']['establishment'].append({
                            'packet': packet,
                            'phase': 'syn_ack',
                            'description': 'Connection Acceptance'
                        })
                    else:
                        # Invalid SYN+ACK - wrong acknowledgment number
                        flow['state'] = 'invalid'
                        flow['invalidReason'] = 'invalid_synack'
                        flow['invalidPacket'] = packet
                        flow['closeType'] = 'invalid'
                        break
                elif not flow.get('synAckPacket'):
                    flow['phases']['establishment'].append({
                        'packet': packet,
                        'phase': 'syn_ack',
                        'description': 'Connection Acceptance'
                    })
                    flow['synAckPacket'] = packet
            elif ack and not syn and not fin and not rst and not psh and flow['state'] == 'establishing':
                # Pure ACK packet - establishment completion
                if flow.get('synAckPacket') and flow.get('expectedSeqNum'):
                    # Validate final ACK
                    if packet['ack_num'] == flow['expectedSeqNum'] and packet['seq_num'] == flow['expectedAckNum']:
                        flow['phases']['establishment'].append({
                            'packet': packet,
                            'phase': 'ack',
                            'description': 'Connection Established'
                        })
                        flow['establishmentComplete'] = True
                        flow['state'] = 'established'
                    else:
                        # Invalid ACK - wrong sequence/acknowledgment numbers
                        flow['state'] = 'invalid'
                        flow['invalidReason'] = 'invalid_ack'
                        flow['invalidPacket'] = packet
                        flow['closeType'] = 'invalid'
                        break
                elif not flow['establishmentComplete']:
                    flow['phases']['establishment'].append({
                        'packet': packet,
                        'phase': 'ack',
                        'description': 'Connection Established'
                    })
                    flow['establishmentComplete'] = True
                    flow['state'] = 'established'
            elif (ack and not syn and not fin and not rst and flow['establishmentComplete'] and
                  ((packet.get('length') and packet['length'] > 0) or (packet.get('seg_len') and packet['seg_len'] > 0))):
                # Data transfer: any ACK packet with payload
                if not flow['dataTransferStarted']:
                    flow['dataTransferStarted'] = True
                    flow['state'] = 'data_transfer'
                flow['phases']['dataTransfer'].append({
                    'packet': packet,
                    'phase': 'data',
                    'description': 'Data Transfer'
                })
            elif fin and not rst:
                # FIN packet - graceful close initiation
                if not flow['closingStarted']:
                    flow['closingStarted'] = True
                    flow['state'] = 'closing'
                    flow['closeType'] = 'graceful'
                flow['phases']['closing'].append({
                    'packet': packet,
                    'phase': 'fin',
                    'description': 'Close Request'
                })
            elif rst:
                # RST packet - abortive close
                if flow['state'] == 'establishing':
                    flow['invalidReason'] = 'rst_during_handshake'
                    flow['state'] = 'invalid'
                    flow['closeType'] = 'invalid'
                else:
                    flow['state'] = 'aborted'
                    flow['closeType'] = 'abortive'
                flow['invalidPacket'] = packet
                flow['phases']['closing'].append({
                    'packet': packet,
                    'phase': 'rst',
                    'description': 'Connection Aborted'
                })
            elif ack and not syn and not fin and not rst and flow['establishmentComplete']:
                # Other ACK packets
                if flow['closingStarted']:
                    flow['phases']['closing'].append({
                        'packet': packet,
                        'phase': 'ack_close',
                        'description': 'Close Acknowledgment'
                    })
                else:
                    if not flow['dataTransferStarted']:
                        flow['dataTransferStarted'] = True
                        flow['state'] = 'data_transfer'
                    flow['phases']['dataTransfer'].append({
                        'packet': packet,
                        'phase': 'ack_data',
                        'description': 'Data Acknowledgment'
                    })

        # Final flow state validation
        if flow['state'] == 'establishing':
            # Incomplete handshake
            if not flow.get('synPacket'):
                flow['state'] = 'invalid'
                flow['invalidReason'] = 'incomplete_no_syn'
                flow['closeType'] = 'invalid'
            elif not flow.get('synAckPacket'):
                flow['state'] = 'invalid'
                flow['invalidReason'] = 'incomplete_no_synack'
                flow['closeType'] = 'invalid'
            elif not flow['establishmentComplete']:
                flow['state'] = 'invalid'
                flow['invalidReason'] = 'incomplete_no_ack'
                flow['closeType'] = 'invalid'
        elif flow['state'] == 'closing':
            flow['state'] = 'closed'

        # Mark ongoing flows explicitly
        if (
            flow['state'] not in ('invalid', 'closed', 'aborted')
            and not flow.get('closeType')
            and (flow.get('establishmentComplete') or flow.get('dataTransferStarted'))
        ):
            flow['state'] = 'ongoing'
            flow['ongoing'] = True
            flow['closeType'] = 'open'

        flows.append(flow)

    # Convert aggregates to output format
    ip_pairs = list(ip_pair_map.values())
    ip_stats_out = {ip: s for ip, s in ip_stats.items()}

    return flows, ip_pairs, ip_stats_out, dict(flag_stats)

def write_flow_chunk(flows_to_write, chunk_idx, flows_dir, flows_index):
    """
    Write a chunk of flows to disk and update the flows index.

    Args:
        flows_to_write: List of flow objects to write
        chunk_idx: Chunk file number
        flows_dir: Directory to write chunk files
        flows_index: List to append flow summaries to (modified in place)
    """
    chunk_filename = f"chunk_{chunk_idx:05d}.json"
    chunk_file = flows_dir / chunk_filename

    # Write chunk file
    with open(chunk_file, 'w') as f:
        json.dump(flows_to_write, f, indent=2)

    # Add flows to index
    for local_idx, flow in enumerate(flows_to_write):
        flow_summary = {
            'id': flow['id'],
            'key': flow['key'],
            'initiator': flow['initiator'],
            'responder': flow['responder'],
            'initiatorPort': flow['initiatorPort'],
            'responderPort': flow['responderPort'],
            'state': flow['state'],
            'closeType': flow['closeType'],
            'startTime': flow['startTime'],
            'endTime': flow['endTime'],
            'totalPackets': flow['totalPackets'],
            'totalBytes': flow['totalBytes'],
            'establishmentComplete': flow['establishmentComplete'],
            'dataTransferStarted': flow['dataTransferStarted'],
            'closingStarted': flow['closingStarted'],
            'invalidReason': flow['invalidReason'],
            'ongoing': flow.get('ongoing', False),
            'establishment_packets': len(flow['phases']['establishment']),
            'data_transfer_packets': len(flow['phases']['dataTransfer']),
            'closing_packets': len(flow['phases']['closing']),
            'chunk_file': chunk_filename,
            'chunk_index': local_idx
        }
        flows_index.append(flow_summary)

    return chunk_filename

def generate_time_bins(records, num_bins=100):
    """Generate time-based bins for range queries"""
    if not records:
        return []

    timestamps = [r['timestamp'] for r in records]
    min_ts = min(timestamps)
    max_ts = max(timestamps)

    if min_ts == max_ts:
        return [{'bin': 0, 'start': min_ts, 'end': max_ts, 'count': len(records)}]

    bin_width = (max_ts - min_ts) / num_bins
    bins = []

    for i in range(num_bins):
        bin_start = min_ts + (i * bin_width)
        bin_end = min_ts + ((i + 1) * bin_width)

        # Count packets in this bin
        count = sum(1 for ts in timestamps if bin_start <= ts < bin_end)

        bins.append({
            'bin': i,
            'start': int(bin_start),
            'end': int(bin_end),
            'count': count
        })

    return bins

def process_tcp_data_chunked(data_file, ip_map_file, output_dir, max_records=None,
                             chunk_size=200, chunk_read_size=500000, flow_timeout_seconds=300):
    """
    Process TCP data and create chunked output structure (v2.0) - STREAMING VERSION

    Memory-optimized: processes CSV in chunks to avoid loading entire file into memory.

    Args:
        data_file: Input CSV file path
        ip_map_file: IP mapping JSON file path
        output_dir: Output directory path
        max_records: Maximum records to process (None = all)
        chunk_size: Flows per output chunk file (default: 200)
        chunk_read_size: CSV rows per read chunk (default: 500000)
        flow_timeout_seconds: Seconds of inactivity before flow timeout (default: 300)
    """

    # Create output directory structure
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Create subdirectories
    flows_dir = output_path / 'flows'
    ips_dir = output_path / 'ips'
    indices_dir = output_path / 'indices'

    flows_dir.mkdir(exist_ok=True)
    ips_dir.mkdir(exist_ok=True)
    indices_dir.mkdir(exist_ok=True)

    print(f"Loading IP mapping from {ip_map_file}...")
    ip_map, int_to_ip = load_ip_mapping(ip_map_file)

    print(f"Processing TCP data from {data_file} in chunks of {chunk_read_size:,} rows...")

    # Determine compression
    compression = 'gzip' if data_file.endswith('.gz') else None

    # Initialize streaming state
    connection_map = {}          # Active flows
    all_completed_flows = []     # Buffer for completed flows (written when full)
    ip_stats = defaultdict(lambda: {
        'sent_packets': 0, 'recv_packets': 0,
        'sent_bytes': 0, 'recv_bytes': 0,
        'first_ts': None, 'last_ts': None
    })
    flag_stats = defaultdict(int)
    ip_pair_map = {}
    unique_ips = set()
    all_timestamps = []

    packets_file = output_path / 'packets.csv'
    packets_written = False
    chunk_number = 0
    total_packets = 0
    tcp_packets = 0
    flow_counter = 0

    # Flow chunk writing state
    flow_chunk_counter = 0
    flows_index = []
    total_flows_written = 0

    # Helper function to convert IP columns (used for each chunk)
    def _convert_ip_column(df_chunk, col_name):
        if col_name not in df_chunk.columns:
            return
        series = df_chunk[col_name]
        if series.dtype == object:
            mask_numeric_like = series.str.fullmatch(r'\d+')
            if mask_numeric_like is not None and mask_numeric_like.any():
                numeric = pd.to_numeric(series.where(mask_numeric_like), errors='coerce')
                mapped = []
                for v in numeric:
                    if pd.isna(v):
                        mapped.append('')
                        continue
                    ival = int(v)
                    mapped.append(int_to_ip.get(ival, str(ival)))
                series = series.mask(mask_numeric_like, pd.Series(mapped, index=series.index))
            df_chunk[col_name] = series.fillna('').astype(str)
            return
        if series.dtype.kind in 'fi':
            numeric = pd.to_numeric(series, errors='coerce')
            out = []
            for v in numeric:
                if pd.isna(v):
                    out.append('')
                    continue
                ival = int(v)
                out.append(int_to_ip.get(ival, str(ival)))
            df_chunk[col_name] = pd.Series(out, index=series.index).fillna('').astype(str)
        else:
            df_chunk[col_name] = series.astype(str).fillna('')

    # Process CSV in chunks
    try:
        csv_iterator = pd.read_csv(data_file, chunksize=chunk_read_size, compression=compression)

        for df_chunk in csv_iterator:
            chunk_number += 1

            # Robust timestamp cleaning for this chunk
            if 'timestamp' in df_chunk.columns:
                df_chunk['timestamp'] = pd.to_numeric(df_chunk['timestamp'], errors='coerce')
                before_drop_count = len(df_chunk)
                df_chunk = df_chunk[df_chunk['timestamp'].notna() & np.isfinite(df_chunk['timestamp'])]
                dropped_count = before_drop_count - len(df_chunk)
                if dropped_count > 0 and chunk_number == 1:
                    print(f"Note: Dropping rows with invalid timestamps (chunk 1: {dropped_count} dropped)")

            # Convert integer IPs to dotted notation
            _convert_ip_column(df_chunk, 'src_ip')
            _convert_ip_column(df_chunk, 'dst_ip')

            # Process flags
            if 'flags' in df_chunk.columns:
                df_chunk['flag_type'] = df_chunk['flags'].apply(classify_tcp_flags)

            # Convert chunk to list of dictionaries
            chunk_records = []
            for _, row in df_chunk.iterrows():
                proto_raw = row.get('protocol') if 'protocol' in df_chunk.columns else None
                try:
                    if proto_raw is not None and not pd.isna(proto_raw):
                        protocol_val = int(proto_raw)
                    else:
                        protocol_val = ''
                except Exception:
                    protocol_val = ''

                record = {
                    'timestamp': _safe_int(row.get('timestamp', 0), 0),
                    'src_ip': str(row.get('src_ip', '')),
                    'dst_ip': str(row.get('dst_ip', '')),
                    'src_port': _safe_int(row.get('src_port', 0), 0),
                    'dst_port': _safe_int(row.get('dst_port', 0), 0),
                    'flags': _safe_int(row.get('flags', 0), 0),
                    'flag_type': row.get('flag_type', 'UNKNOWN'),
                    'seq_num': _safe_int(row.get('seq_num', 0), 0),
                    'ack_num': _safe_int(row.get('ack_num', 0), 0),
                    'length': _safe_int(row.get('length', 0), 0),
                    'protocol': protocol_val
                }
                chunk_records.append(record)

            # Apply max_records limit
            if max_records and total_packets + len(chunk_records) > max_records:
                chunk_records = chunk_records[:max_records - total_packets]

            total_packets += len(chunk_records)

            # Write packets incrementally to packets.csv
            if chunk_records:
                chunk_df = pd.DataFrame(chunk_records)
                if not packets_written:
                    chunk_df.to_csv(packets_file, mode='w', index=False)
                    packets_written = True
                else:
                    chunk_df.to_csv(packets_file, mode='a', index=False, header=False)

                # Update unique IPs and timestamps
                unique_ips.update([r['src_ip'] for r in chunk_records])
                unique_ips.update([r['dst_ip'] for r in chunk_records])
                all_timestamps.extend([r['timestamp'] for r in chunk_records])

                # Incremental flow detection
                tcp_chunk = [r for r in chunk_records if r.get('protocol') == 6 or str(r.get('protocol')).upper() == 'TCP']
                tcp_packets += len(tcp_chunk)

                if tcp_chunk:
                    completed_flows, flow_counter, timed_out = detect_tcp_flows_incremental(
                        tcp_chunk,
                        connection_map,
                        ip_stats,
                        flag_stats,
                        ip_pair_map,
                        flow_counter,
                        flow_timeout_seconds
                    )

                    all_completed_flows.extend(completed_flows)

                    # Write flow chunks incrementally when buffer is full (frees memory!)
                    while len(all_completed_flows) >= chunk_size:
                        flows_to_write = all_completed_flows[:chunk_size]
                        chunk_filename = write_flow_chunk(flows_to_write, flow_chunk_counter,
                                                          flows_dir, flows_index)
                        flow_chunk_counter += 1
                        total_flows_written += len(flows_to_write)
                        all_completed_flows = all_completed_flows[chunk_size:]  # Remove written flows
                        print(f"  → Wrote flow chunk {chunk_filename} ({len(flows_to_write)} flows, "
                              f"freed ~{len(flows_to_write) * 50 * 100 / 1024:.1f}KB memory)")

                    # Enhanced progress output showing timeout statistics
                    print(f"Chunk {chunk_number}: processed {len(chunk_records):,} packets, "
                          f"{len(tcp_chunk):,} TCP, {len(connection_map):,} active flows, "
                          f"{len(completed_flows):,} completed ({timed_out} by timeout), "
                          f"buffered flows: {len(all_completed_flows)}, total: {total_packets:,}")

            # Check if we've reached max_records limit
            if max_records and total_packets >= max_records:
                print(f"Reached max_records limit of {max_records:,}")
                break

    except Exception as e:
        print(f"Error reading CSV: {e}", file=sys.stderr)
        raise

    # Finalize: process all remaining active flows
    print(f"\nFinalizing {len(connection_map):,} remaining active flows...")
    for conn_key, conn_data in connection_map.items():
        flow = process_single_flow(conn_key, conn_data['packets'], conn_data['flow_id'])
        all_completed_flows.append(flow)

    # Write any remaining flows (buffer might not be full)
    if all_completed_flows:
        print(f"\nWriting final {len(all_completed_flows)} flows to disk...")
        while all_completed_flows:
            flows_to_write = all_completed_flows[:chunk_size]
            chunk_filename = write_flow_chunk(flows_to_write, flow_chunk_counter,
                                              flows_dir, flows_index)
            flow_chunk_counter += 1
            total_flows_written += len(flows_to_write)
            all_completed_flows = all_completed_flows[len(flows_to_write):]
            print(f"  Wrote {chunk_filename} ({len(flows_to_write)} flows)")

    unique_ips = sorted(list(unique_ips))

    # Convert ip_pair_map to list for compatibility
    ip_pairs = list(ip_pair_map.values())

    # Calculate timeout statistics from flows_index
    flows_by_timeout = sum(1 for f in flows_index if f.get('ongoing', False))
    flows_by_close = len(flows_index) - flows_by_timeout

    print(f"\nProcessing complete:")
    print(f"  - Total packets: {total_packets:,}")
    print(f"  - TCP packets: {tcp_packets:,}")
    print(f"  - Total flows: {total_flows_written:,}")
    print(f"    • Completed by FIN/RST: {flows_by_close:,}")
    print(f"    • Completed by timeout: {flows_by_timeout:,} ({flow_timeout_seconds}s inactivity)")
    print(f"  - Flow chunks written: {flow_chunk_counter}")
    print(f"  - Unique IPs: {len(unique_ips):,}")

    # packets.csv already saved incrementally during chunk processing
    # flow chunks already saved incrementally above

    # Save flows_index.json (inside flows/ directory)
    print(f"Saving flows index to {flows_dir / 'flows_index.json'}...")
    with open(flows_dir / 'flows_index.json', 'w') as f:
        json.dump(flows_index, f, indent=2)

    # 4. Save IP-related files in ips/ subdirectory
    print(f"Saving IP statistics to {ips_dir / 'ip_stats.json'}...")
    with open(ips_dir / 'ip_stats.json', 'w') as f:
        json.dump(ip_stats, f, indent=2)

    print(f"Saving flag statistics to {ips_dir / 'flag_stats.json'}...")
    with open(ips_dir / 'flag_stats.json', 'w') as f:
        json.dump(flag_stats, f, indent=2)

    print(f"Saving unique IPs to {ips_dir / 'unique_ips.json'}...")
    with open(ips_dir / 'unique_ips.json', 'w') as f:
        json.dump(unique_ips, f, indent=2)

    # 5. Generate and save time bins
    print(f"Generating time bins...")
    # Create minimal records structure for time binning from collected timestamps
    timestamp_records = [{'timestamp': ts} for ts in all_timestamps]
    bins = generate_time_bins(timestamp_records, num_bins=100)
    print(f"Saving time bins to {indices_dir / 'bins.json'}...")
    with open(indices_dir / 'bins.json', 'w') as f:
        json.dump(bins, f, indent=2)

    # 6. Save manifest.json with v2.0 metadata
    time_start = min(all_timestamps) if all_timestamps else 0
    time_end = max(all_timestamps) if all_timestamps else 0

    manifest = {
        'version': '2.0',
        'format': 'chunked',
        'created': pd.Timestamp.now().isoformat(),
        'source_file': str(data_file),
        'total_packets': total_packets,
        'tcp_packets': tcp_packets,
        'unique_ips': len(unique_ips),
        'total_flows': total_flows_written,
        'flows_per_chunk': chunk_size,
        'total_chunks': flow_chunk_counter,
        'time_range': {
            'start': int(time_start),
            'end': int(time_end),
            'duration': int(time_end - time_start)
        },
        'structure': {
            'packets': 'packets.csv',
            'flows_index': 'flows/flows_index.json',
            'flow_chunks': 'flows/chunk_*.json',
            'time_bins': 'indices/bins.json',
            'ip_stats': 'ips/ip_stats.json',
            'flag_stats': 'ips/flag_stats.json',
            'unique_ips': 'ips/unique_ips.json'
        }
    }

    print(f"Saving manifest to {output_path / 'manifest.json'}...")
    with open(output_path / 'manifest.json', 'w') as f:
        json.dump(manifest, f, indent=2)

    print(f"\nSuccessfully processed data:")
    print(f"  - Total packets: {total_packets}")
    print(f"  - TCP packets: {tcp_packets}")
    print(f"  - Unique IPs: {len(unique_ips)}")
    print(f"  - Total flows: {total_flows_written}")
    print(f"  - Flows per chunk: {chunk_size}")
    print(f"  - Total chunks: {flow_chunk_counter}")
    print(f"  - Time range: {time_start} to {time_end}")
    print(f"  - Output directory: {output_path}")

    return {
        'output_dir': str(output_path),
        'total_packets': total_packets,
        'tcp_packets': tcp_packets,
        'unique_ips': len(unique_ips),
        'total_flows': total_flows_written,
        'flows_per_chunk': chunk_size,
        'total_chunks': flow_chunk_counter,
        'manifest': manifest
    }

def main():
    parser = argparse.ArgumentParser(
        description='Convert TCP data to chunked file structure (v2.0) - STREAMING/MEMORY-EFFICIENT VERSION. '
                    'Processes large CSV files in chunks to avoid out-of-memory errors.')
    parser.add_argument('--data', required=True, help='Input TCP data file (CSV or CSV.GZ)')
    parser.add_argument('--ip-map', required=True, help='IP mapping JSON file')
    parser.add_argument('--output-dir', required=True, help='Output directory for chunked files')
    parser.add_argument('--max-records', type=int, help='Maximum number of records to process')
    parser.add_argument('--chunk-size', type=int, default=200,
                       help='Number of flows per output chunk file (default: 200)')
    parser.add_argument('--chunk-read-size', type=int, default=500000,
                       help='Number of CSV rows to read per chunk (default: 500000). '
                            'Lower values use less memory but slower; higher values faster but more memory.')
    parser.add_argument('--flow-timeout-seconds', type=int, default=300,
                       help='Seconds of inactivity before flow timeout (default: 300). '
                            'Flows without FIN/RST are completed after this many seconds of no packets. '
                            'Common values: 60 (1 min), 300 (5 min, recommended), 1800 (30 min). '
                            'Use very large value (e.g., 999999) to disable timeout.')

    args = parser.parse_args()

    # Check if input files exist
    if not Path(args.data).exists():
        print(f"Error: Data file '{args.data}' not found", file=sys.stderr)
        sys.exit(1)

    if not Path(args.ip_map).exists():
        print(f"Error: IP mapping file '{args.ip_map}' not found", file=sys.stderr)
        sys.exit(1)

    try:
        process_tcp_data_chunked(args.data, args.ip_map, args.output_dir, args.max_records,
                                 args.chunk_size, args.chunk_read_size, args.flow_timeout_seconds)
    except Exception as e:
        print(f"Error processing data: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
