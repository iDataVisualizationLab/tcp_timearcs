#!/usr/bin/env python3
"""
TCP Data Loader for Analysis
Converts TCP analysis data to CSV format for analysis and reporting
"""

import pandas as pd
import json
import sys
import argparse
from pathlib import Path
from collections import defaultdict

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

def _is_set(flags: int, mask: int) -> bool:
    try:
        return (int(flags) & mask) != 0
    except Exception:
        return False

def _make_conn_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int):
    """Normalized 4-tuple key, order-agnostic for grouping packets into flows."""
    a = (src_ip, int(src_port))
    b = (dst_ip, int(dst_port))
    return (a, b) if a <= b else (b, a)

def _format_conn_key(key):
    (a_ip, a_p), (b_ip, b_p) = key
    return f"{a_ip}:{a_p}<->{b_ip}:{b_p}"

def detect_tcp_flows(records, selected_ips=None):
    """
    EXACT translation of processTcpFlowsChunked function from HTML.
    If selected_ips is provided, filters packets like HTML does:
    only includes packets where both src_ip AND dst_ip are in selected_ips list.
    """
    # Aggregates for IP stats (preserve existing functionality)
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

    # Apply HTML-style filtering if selected_ips provided
    filtered_records = records
    if selected_ips is not None and len(selected_ips) >= 2:
        # Filter like HTML: only packets where both src_ip AND dst_ip are in selected_ips
        filtered_records = [
            pkt for pkt in records 
            if str(pkt.get('src_ip', '')) in selected_ips and str(pkt.get('dst_ip', '')) in selected_ips
        ]
        print(f"Filtered from {len(records)} to {len(filtered_records)} packets using selected IPs: {selected_ips}")
    
    # Build aggregates from filtered records
    for pkt in filtered_records:
        ts = int(pkt.get('timestamp', 0))
        s_ip = str(pkt.get('src_ip', ''))
        d_ip = str(pkt.get('dst_ip', ''))
        length = int(pkt.get('length', 0))
        flag_type = str(pkt.get('flag_type', 'UNKNOWN'))

        flag_stats[flag_type] += 1
        update_ip_stats(s_ip, d_ip, length, ts)
        update_ip_pair(s_ip, d_ip, length, ts)

    # EXACT translation of processTcpFlowsChunked JavaScript (lines 3601-4016)
    flows = []
    connection_map = {}
    
    # Group packets by connection exactly like HTML (JS uses Map, we use dict)
    # Use filtered_records to match HTML behavior
    for packet in filtered_records:
        if packet.get('src_port') and packet.get('dst_port') and packet.get('src_ip') and packet.get('dst_ip'):
            # Create bidirectional connection key exactly like HTML
            connection_a = f"{packet['src_ip']}:{packet['src_port']}-{packet['dst_ip']}:{packet['dst_port']}"
            connection_b = f"{packet['dst_ip']}:{packet['dst_port']}-{packet['src_ip']}:{packet['src_port']}"
            connection_key = connection_a if connection_a < connection_b else connection_b
            
            if connection_key not in connection_map:
                connection_map[connection_key] = []
            connection_map[connection_key].append(packet)

    # Process connections exactly like HTML Array.from(connectionMap.entries())
    for connection_key, connection_packets in connection_map.items():
        # Sort packets by timestamp
        connection_packets.sort(key=lambda a: a['timestamp'])
        
        # Initialize flow exactly like HTML connectionStates (lines 3627-3645)
        flow = {
            'id': f"flow_{int(__import__('time').time() * 1000)}_{__import__('random').randint(100000, 999999)}",
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
            # These fields are added during processing but missing from initial state
            'invalidReason': None,
            'expectedSeqNum': None,
            'expectedAckNum': None,
            'invalidPacket': None,
            'synPacket': None,
            'synAckPacket': None
        }
        
        # Set computed values after initialization (like HTML lines 3668-3671)
        flow['startTime'] = connection_packets[0]['timestamp']
        flow['endTime'] = connection_packets[-1]['timestamp']
        flow['totalPackets'] = len(connection_packets)
        flow['totalBytes'] = sum((p.get('length') or 0) for p in connection_packets)
        
        # Process packets in chronological order - EXACT chunked version (lines 3682-3985)
        for packet in connection_packets:
            flags = packet['flags']
            syn = (flags & 0x02) != 0
            ack = (flags & 0x10) != 0
            fin = (flags & 0x01) != 0
            rst = (flags & 0x04) != 0
            psh = (flags & 0x08) != 0
            
            # Skip processing if connection is already marked as invalid
            if flow['state'] == 'invalid':
                continue
            
            # EXACT matching of HTML lines 3693-3979
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
                    # Only add SYN+ACK if we haven't seen one yet for this flow
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
                    # ACK without proper SYN/SYN+ACK sequence
                    flow['phases']['establishment'].append({
                        'packet': packet,
                        'phase': 'ack',
                        'description': 'Connection Established'
                    })
                    flow['establishmentComplete'] = True
                    flow['state'] = 'established'
            elif (ack and not syn and not fin and not rst and flow['establishmentComplete'] and
                  ((packet.get('length') and packet['length'] > 0) or (packet.get('seg_len') and packet['seg_len'] > 0))):
                # Data transfer: any ACK packet with payload (not SYN/FIN/RST)
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
                # RST packet - abortive close (chunked version behavior)
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
                # No break in chunked version - continue processing
            elif ack and not syn and not fin and not rst and flow['establishmentComplete']:
                # Other ACK packets - could be data transfer or closing ACKs (HTML lines 3813-3828)
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
        
        # Final flow state validation - EXACT chunked version (lines 3831-3849)
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

        # Mark ongoing flows explicitly (non-invalid, not gracefully/abortively closed)
        # Ongoing = reached establishment or data, no RST/FIN completion observed
        if (
            flow['state'] not in ('invalid', 'closed', 'aborted')
            and not flow.get('closeType')  # no graceful/abortive/invalid close type
            and (flow.get('establishmentComplete') or flow.get('dataTransferStarted'))
        ):
            flow['state'] = 'ongoing'
            flow['ongoing'] = True
            # Label close type as 'open' for downstream consumers; UI maps non-graceful/abortive to Unknown
            flow['closeType'] = 'open'

        # HTML adds ALL flows, no filtering (line 3850: flows.push(flow))
        flows.append(flow)
    
    # Convert aggregates to lists for JSON
    ip_pairs = list(ip_pair_map.values())
    ip_stats_out = {ip: s for ip, s in ip_stats.items()}

    return flows, ip_pairs, ip_stats_out, dict(flag_stats)

def process_tcp_data(data_file, ip_map_file, output_file, max_records=None, selected_ips=None):
    """Process TCP data and convert to CSV for analysis"""
    
    print(f"Loading IP mapping from {ip_map_file}...")
    ip_map, int_to_ip = load_ip_mapping(ip_map_file)
    
    print(f"Loading TCP data from {data_file}...")
    
    # Handle different file formats
    if data_file.endswith('.gz'):
        df = pd.read_csv(data_file, compression='gzip')
    else:
        df = pd.read_csv(data_file)
    
    print(f"Loaded {len(df)} records")
    
    # Limit records if specified
    if max_records and len(df) > max_records:
        df = df.head(max_records)
        print(f"Limited to {max_records} records")
    
    # Filter for TCP protocol only
    if 'protocol' in df.columns:
        df = df[df['protocol'] == 6]  # TCP protocol number
        print(f"Filtered to {len(df)} TCP records")
    
    # Convert integer IPs to dotted notation if needed
    if 'src_ip' in df.columns:
        if df['src_ip'].dtype in ['int64', 'int32', 'float64', 'float32']:
            # Convert float to int first, then map to IP
            df['src_ip'] = df['src_ip'].astype(int).map(int_to_ip).fillna(df['src_ip'].astype(int).astype(str))
        else:
            df['src_ip'] = df['src_ip'].astype(str)
    
    if 'dst_ip' in df.columns:
        if df['dst_ip'].dtype in ['int64', 'int32', 'float64', 'float32']:
            # Convert float to int first, then map to IP
            df['dst_ip'] = df['dst_ip'].astype(int).map(int_to_ip).fillna(df['dst_ip'].astype(int).astype(str))
        else:
            df['dst_ip'] = df['dst_ip'].astype(str)
    
    # Process flags
    if 'flags' in df.columns:
        df['flag_type'] = df['flags'].apply(classify_tcp_flags)
    
    # Ensure required columns exist
    required_cols = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port']
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        print(f"Warning: Missing required columns: {missing_cols}", file=sys.stderr)
    
    # Convert to list of dictionaries
    records = []
    for _, row in df.iterrows():
        record = {
            'timestamp': int(row.get('timestamp', 0)),
            'src_ip': str(row.get('src_ip', '')),
            'dst_ip': str(row.get('dst_ip', '')),
            'src_port': int(row.get('src_port', 0)),
            'dst_port': int(row.get('dst_port', 0)),
            'flags': int(row.get('flags', 0)),
            'flag_type': row.get('flag_type', 'UNKNOWN'),
            'seq_num': int(row.get('seq_num', 0)),
            'ack_num': int(row.get('ack_num', 0)),
            'length': int(row.get('length', 0)),
            'protocol': 'TCP'
        }
        records.append(record)
    
    # Get unique IPs for the selector
    unique_ips = sorted(list(set(
        [r['src_ip'] for r in records] + [r['dst_ip'] for r in records]
    )))

    # Pre-compute flows and aggregates for ALL records (no IP filtering in Python)
    print("Detecting TCP flows and computing aggregates...")
    flows, ip_pairs, ip_stats, flag_stats = detect_tcp_flows(records, selected_ips=None)
    
    # Create a comprehensive single CSV with all data
    print(f"Saving all processed data to {output_file}...")
    
    # Start with the packet records as the base
    all_data = []
    
    # Create a mapping from connection key to flow info for easy lookup
    flow_lookup = {}
    if flows:
        for flow in flows:
            flow_lookup[flow['key']] = {
                'flow_id': flow['id'],
                'flow_state': flow['state'],
                'flow_close_type': flow['closeType'],
                'establishment_complete': flow['establishmentComplete'],
                'data_transfer_started': flow['dataTransferStarted'],
                'closing_started': flow['closingStarted'],
                'flow_start_time': flow['startTime'],
                'flow_end_time': flow['endTime'],
                'flow_total_packets': flow['totalPackets'],
                'flow_total_bytes': flow['totalBytes'],
                'flow_invalid_reason': flow.get('invalidReason', ''),
                'establishment_packets': len(flow['phases']['establishment']),
                'data_transfer_packets': len(flow['phases']['dataTransfer']),
                'closing_packets': len(flow['phases']['closing']),
                'flow_ongoing': flow.get('ongoing', False)
            }
    
    # Enhanced packet records with flow information
    for record in records:
        # Create connection key for this packet
        connection_a = f"{record['src_ip']}:{record['src_port']}-{record['dst_ip']}:{record['dst_port']}"
        connection_b = f"{record['dst_ip']}:{record['dst_port']}-{record['src_ip']}:{record['src_port']}"
        connection_key = connection_a if connection_a < connection_b else connection_b
        
        # Get flow info for this connection
        flow_info = flow_lookup.get(connection_key, {})
        
        # Get IP stats for source and destination
        src_stats = ip_stats.get(record['src_ip'], {})
        dst_stats = ip_stats.get(record['dst_ip'], {})
        
        # Create enhanced record
        enhanced_record = {
            # Original packet data
            'timestamp': record['timestamp'],
            'src_ip': record['src_ip'],
            'dst_ip': record['dst_ip'],
            'src_port': record['src_port'],
            'dst_port': record['dst_port'],
            'flags': record['flags'],
            'flag_type': record['flag_type'],
            'seq_num': record['seq_num'],
            'ack_num': record['ack_num'],
            'length': record['length'],
            'protocol': record['protocol'],
            
            # Flow information
            'flow_id': flow_info.get('flow_id', ''),
            'flow_state': flow_info.get('flow_state', ''),
            'flow_close_type': flow_info.get('flow_close_type', ''),
            'establishment_complete': flow_info.get('establishment_complete', False),
            'data_transfer_started': flow_info.get('data_transfer_started', False),
            'closing_started': flow_info.get('closing_started', False),
            'flow_start_time': flow_info.get('flow_start_time', ''),
            'flow_end_time': flow_info.get('flow_end_time', ''),
            'flow_total_packets': flow_info.get('flow_total_packets', 0),
            'flow_total_bytes': flow_info.get('flow_total_bytes', 0),
            'flow_invalid_reason': flow_info.get('flow_invalid_reason', ''),
            'establishment_packets': flow_info.get('establishment_packets', 0),
            'data_transfer_packets': flow_info.get('data_transfer_packets', 0),
            'closing_packets': flow_info.get('closing_packets', 0),
            'flow_ongoing': flow_info.get('flow_ongoing', False),
            
            # Source IP statistics
            'src_sent_packets': src_stats.get('sent_packets', 0),
            'src_recv_packets': src_stats.get('recv_packets', 0),
            'src_sent_bytes': src_stats.get('sent_bytes', 0),
            'src_recv_bytes': src_stats.get('recv_bytes', 0),
            'src_first_ts': src_stats.get('first_ts', ''),
            'src_last_ts': src_stats.get('last_ts', ''),
            
            # Destination IP statistics  
            'dst_sent_packets': dst_stats.get('sent_packets', 0),
            'dst_recv_packets': dst_stats.get('recv_packets', 0),
            'dst_sent_bytes': dst_stats.get('sent_bytes', 0),
            'dst_recv_bytes': dst_stats.get('recv_bytes', 0),
            'dst_first_ts': dst_stats.get('first_ts', ''),
            'dst_last_ts': dst_stats.get('last_ts', ''),
        }
        
        all_data.append(enhanced_record)
    
    # Convert to DataFrame and save
    df_output = pd.DataFrame(all_data)
    df_output.to_csv(output_file, index=False)
    
    print(f"Saved comprehensive data with {len(all_data)} records and {len(df_output.columns)} columns")
    
    print(f"Successfully processed {len(records)} records")
    print(f"Found {len(unique_ips)} unique IP addresses")
    time_start = min([r['timestamp'] for r in records]) if records else 0
    time_end = max([r['timestamp'] for r in records]) if records else 0
    print(f"Time range: {time_start} to {time_end}")
    
    # Return summary for compatibility
    return {
        'output_file': output_file,
        'total_packets': len(records),
        'unique_ips': len(unique_ips),
        'total_flows': len(flows),
        'columns': len(df_output.columns)
    }

def main():
    parser = argparse.ArgumentParser(description='Convert TCP data to CSV for analysis')
    parser.add_argument('--data', required=True, help='Input TCP data file (CSV)')
    parser.add_argument('--ip-map', required=True, help='IP mapping JSON file')
    parser.add_argument('--output', default='tcp_data.csv', help='Output CSV file')
    parser.add_argument('--max-records', type=int, help='Maximum number of records to process')
    
    args = parser.parse_args()
    
    # Check if input files exist
    if not Path(args.data).exists():
        print(f"Error: Data file '{args.data}' not found", file=sys.stderr)
        sys.exit(1)
    
    if not Path(args.ip_map).exists():
        print(f"Error: IP mapping file '{args.ip_map}' not found", file=sys.stderr)
        sys.exit(1)
    
    try:
        process_tcp_data(args.data, args.ip_map, args.output, args.max_records)
    except Exception as e:
        print(f"Error processing data: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()