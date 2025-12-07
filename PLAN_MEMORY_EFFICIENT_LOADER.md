# Plan: Memory-Efficient Chunked Processing for tcp_data_loader_chunked.py

## Problem Analysis

**Current Memory Bottlenecks:**
1. **Line 449-451**: Loads entire CSV into pandas DataFrame (`pd.read_csv(data_file)`)
2. **Line 512-535**: Converts entire DataFrame to in-memory records list
3. **Line 545**: Passes all records to `detect_tcp_flows()` which processes everything at once
4. **Line 560**: Holds complete DataFrame for packets.csv output

**Result**: For `full_10days_spambot.csv` (likely millions of rows), this causes out-of-memory errors on systems with 16-32GB RAM.

## Solution: Streaming CSV Processing with Incremental Flow Detection

**Inspiration**: `attack_extract.py` already implements chunked CSV reading using pandas `chunksize=1_000_000` parameter.

### Implementation Strategy

**Phase 1: Chunked CSV Reading**
- Use `pd.read_csv()` with `chunksize` parameter (default: 500,000 rows)
- Process CSV in manageable chunks to avoid loading entire file into memory

**Phase 2: Incremental Packet Writing**
- Write `packets.csv` incrementally during first pass
- Each chunk appends to packets.csv (using `mode='a'`)
- No need to hold all packets in memory

**Phase 3: Streaming Flow Detection**
- Modify `detect_tcp_flows()` to be **stateful and incremental**
- Track active flows in a connection map across chunks
- Complete flows are written to chunk files immediately and removed from memory
- Only "active" flows remain in memory between chunks

**Phase 4: Incremental Aggregation**
- IP statistics accumulated incrementally per chunk
- Flag statistics accumulated incrementally
- Timestamp collection for binning (lightweight - just integers)

### Key Design Decisions

**1. Flow Completion Detection**
A flow is considered "complete" when:
- It has a FIN/RST packet (explicit close)
- It hasn't seen packets for N chunks (configurable timeout)
- End of file reached

**2. Memory Management**
- **Active flows**: Kept in memory with full packet data
- **Completed flows**: Written to chunk files immediately, cleared from memory
- **Chunk size**: Configurable (default 500k rows) - balance between I/O and memory

**3. Two-Pass vs. One-Pass Approach**

**Chosen: Modified One-Pass with Streaming Flow Completion**
- **Pass 1 (streaming)**:
  - Read CSV chunks
  - Write packets.csv incrementally
  - Detect flows incrementally
  - Write completed flows to chunk files as they finish
  - Keep only active flows in memory
- **Pass 2 (finalization)**:
  - Write any remaining active flows
  - Generate flows_index.json
  - Write manifest.json and metadata files

**Advantage**: Minimal memory footprint, single data read

## Implementation Plan

### Step 1: Add Chunked CSV Reading
**File**: `tcp_data_loader_chunked.py:445-470`

Replace:
```python
if data_file.endswith('.gz'):
    df = pd.read_csv(data_file, compression='gzip')
else:
    df = pd.read_csv(data_file)
```

With:
```python
# Determine compression
compression = 'gzip' if data_file.endswith('.gz') else None

# Create CSV reader with chunking
csv_iterator = pd.read_csv(
    data_file,
    chunksize=chunk_read_size,  # new parameter
    compression=compression
)
```

### Step 2: Create Incremental Flow Detector
**New function**: `detect_tcp_flows_incremental()`

**Signature**:
```python
def detect_tcp_flows_incremental(
    chunk_records,           # Current chunk of packets
    connection_map,          # Persistent state across chunks (modified in place)
    ip_stats,               # Accumulator for IP statistics (modified in place)
    flag_stats,             # Accumulator for flag statistics (modified in place)
    chunk_number,           # For timeout detection
    flow_counter,           # Current flow ID counter (for new flows)
    flow_timeout_chunks=5   # Mark flows inactive after N chunks
):
    """
    Process a chunk of packets and update flow state.
    Returns: (completed_flows, updated_flow_counter)
    """
```

**Key implementation details**:

1. **Connection Map Structure** (modified from original lines 160-172):
   ```python
   connection_map[connection_key] = {
       'packets': [...],              # Packet data
       'flow_id': flow_counter,       # Assigned flow ID
       'last_chunk': chunk_number,    # Last chunk this flow was seen
       'state': 'new',                # Flow state tracking
       'has_fin_or_rst': False        # Completion marker
   }
   ```

2. **Add packets to existing/new connections**:
   - For each packet, determine connection_key (same as lines 165-168)
   - If connection exists: append packet, update last_chunk
   - If new connection: create new entry, increment flow_counter

3. **Update IP/flag stats** (same as original lines 107-156):
   - Call `update_ip_stats()` and `update_ip_pair()` for each packet
   - Accumulate flag_stats

4. **Detect completed flows**:
   ```python
   completed_flows = []
   for conn_key, conn_data in list(connection_map.items()):
       # Flow is complete if:
       # - Has FIN or RST flag (conn_data['has_fin_or_rst'])
       # - OR hasn't seen packets for flow_timeout_chunks
       is_complete = (
           conn_data['has_fin_or_rst'] or
           (chunk_number - conn_data['last_chunk'] >= flow_timeout_chunks)
       )

       if is_complete:
           # Process flow (same logic as original lines 176-387)
           flow = process_single_flow(conn_key, conn_data['packets'], conn_data['flow_id'])
           completed_flows.append(flow)
           del connection_map[conn_key]  # Remove from active flows

   return completed_flows, flow_counter
   ```

5. **Extract flow processing logic**:
   - Create helper function `process_single_flow()` from original lines 181-387
   - This processes a single connection's packets into a flow object
   - Same TCP state machine logic, unchanged

### Step 3: Implement Streaming Main Loop
**File**: `tcp_data_loader_chunked.py:426-687`

Replace `process_tcp_data_chunked()` with streaming version:

```python
def process_tcp_data_chunked(data_file, ip_map_file, output_dir,
                             max_records=None, chunk_size=200,
                             chunk_read_size=500000):
    # Setup (same as before)
    output_path = Path(output_dir)
    # ... create directories ...

    # Initialize streaming state
    connection_map = {}          # Active flows
    all_completed_flows = []     # Completed flows
    ip_stats = defaultdict(...)  # IP aggregates
    flag_stats = defaultdict(int)
    unique_ips = set()
    all_timestamps = []

    packets_file = output_path / 'packets.csv'
    packets_written = False
    chunk_number = 0
    total_packets = 0
    tcp_packets = 0

    # Process CSV in chunks
    for df_chunk in csv_iterator:
        chunk_number += 1

        # Convert chunk to records
        chunk_records = []
        for _, row in df_chunk.iterrows():
            # ... same conversion logic ...
            chunk_records.append(record)

        # Apply max_records limit
        if max_records and total_packets + len(chunk_records) > max_records:
            chunk_records = chunk_records[:max_records - total_packets]

        total_packets += len(chunk_records)

        # Write packets incrementally to packets.csv
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
        tcp_chunk = [r for r in chunk_records if r.get('protocol') == 6]
        tcp_packets += len(tcp_chunk)

        completed_flows, flow_counter = detect_tcp_flows_incremental(
            tcp_chunk,
            connection_map,      # updated in place
            ip_stats,           # updated in place
            flag_stats,         # updated in place
            chunk_number,
            flow_counter,
            flow_timeout_chunks=args.flow_timeout_chunks
        )

        # Add completed flows to list (will write all at end)
        # Note: We could write chunk files incrementally here too,
        # but keeping all flows for final chunking is simpler
        all_completed_flows.extend(completed_flows)

        print(f"Chunk {chunk_number}: processed {len(chunk_records):,} packets, "
              f"{len(tcp_chunk):,} TCP, {len(connection_map):,} active flows, "
              f"{len(completed_flows):,} completed")

        if max_records and total_packets >= max_records:
            break

    # Finalize: mark remaining active flows as completed
    for conn_key, packets in connection_map.items():
        # ... finalize flow ...
        all_completed_flows.append(flow)

    # Write flows in chunks (same as before, lines 562-606)
    # Write IP stats, bins, manifest (same as before)
```

### Step 4: Optimize Flow Packet Storage
**Challenge**: Flows need full packet data, but we can't keep all packets in memory.

**Solution**: Use lightweight packet references during chunking:
- Store packet index/timestamp instead of full packet data during streaming
- Option A: Keep only essential fields (timestamp, flags, seq/ack) in flow state
- Option B: Write flow packets to temporary per-flow files, consolidate later

**Recommended**: **Option A** - Store minimal packet representation in flows:

```python
# In detect_tcp_flows_incremental, store lightweight packet refs:
flow['packets'].append({
    'timestamp': packet['timestamp'],
    'src_ip': packet['src_ip'],
    'dst_ip': packet['dst_ip'],
    'src_port': packet['src_port'],
    'dst_port': packet['dst_port'],
    'flags': packet['flags'],
    'seq_num': packet['seq_num'],
    'ack_num': packet['ack_num'],
    'length': packet['length']
    # Drop: flag_type (can be recomputed), protocol (always TCP)
})
```

This reduces memory per packet from ~200 bytes to ~100 bytes.

### Step 5: Add Configuration Parameter
**File**: `tcp_data_loader_chunked.py:689-697`

Add new CLI argument:
```python
parser.add_argument('--chunk-read-size', type=int, default=500000,
                   help='Number of CSV rows to read per chunk (default: 500000)')
parser.add_argument('--flow-timeout-chunks', type=int, default=5,
                   help='Mark flows inactive after N chunks without packets (default: 5)')
```

### Step 6: Update Progress Reporting
Add detailed progress information:
- Current chunk number
- Packets processed so far
- Active flows count
- Completed flows count
- Memory estimate (active flows × avg packets × bytes per packet)

### Step 7: Add Memory Profiling (Optional)
For debugging, add optional memory tracking:
```python
import tracemalloc  # Python 3.4+

if args.debug:
    tracemalloc.start()
    # ... after each chunk ...
    current, peak = tracemalloc.get_traced_memory()
    print(f"  Memory: current={current/1024/1024:.1f}MB, peak={peak/1024/1024:.1f}MB")
```

## Testing Strategy

### Test 1: Small File (Validation)
```bash
python tcp_data_loader_chunked.py \
  --data set1_first90_minutes.csv \
  --ip-map combined_pcap_data_set5_compressed_ip_map.json \
  --output-dir test_small \
  --chunk-read-size 10000
```
**Verify**: Output matches original implementation exactly

### Test 2: Large File (Memory)
```bash
python tcp_data_loader_chunked.py \
  --data full_10days_spambot.csv \
  --ip-map combined_pcap_data_set5_compressed_ip_map.json \
  --output-dir test_large \
  --chunk-read-size 500000
```
**Monitor**: Memory usage stays under 8GB, completes without errors

### Test 3: Performance Tuning
Test different chunk sizes to find optimal balance:
- 100k rows: More I/O, less memory
- 500k rows: Balanced (recommended)
- 1M rows: Less I/O, more memory

## Expected Improvements

**Before (current implementation)**:
- Memory: Entire CSV loaded (~100-200 bytes per packet)
- 10M packets = 1-2GB for packets alone + flows + overhead = 3-5GB minimum
- 100M packets = 10-20GB (**out of memory on 16GB system**)

**After (streaming implementation)**:
- Memory: Only active flows + current chunk
- Chunk: 500k packets × 150 bytes = ~75MB
- Active flows: ~10k flows × 50 packets × 100 bytes = ~50MB
- Total: **~150-200MB peak memory (98% reduction!)**

**Real-world example (10-day dataset)**:
- If `full_10days_spambot.csv` has ~50M packets:
  - **Before**: Needs ~10-12GB RAM → **CRASHES** on 16GB system
  - **After**: Needs ~200MB RAM → **SUCCEEDS** easily

**Processing time**:
- Slightly slower due to incremental I/O (~10-20% overhead)
- But **completes successfully** vs. crashing completely
- Trade-off: 20% slower but 98% less memory = worthwhile for large files

## Files Created/Modified

**NEW FILE**: `tcp_data_loader_streaming.py`
- Copy from `tcp_data_loader_chunked.py` as the starting point
- Implement all changes described in this plan
- Keep original `tcp_data_loader_chunked.py` unchanged for comparison

**Changes in the new file**:
1. Lines 426-687: Replace `process_tcp_data_chunked()` with streaming version
2. Add new function `detect_tcp_flows_incremental()` (based on original lines 93-393)
3. Add new helper function `process_single_flow()` (extracted from flow processing logic)
4. Lines 689-697: Add CLI parameters for `--chunk-read-size` and `--flow-timeout-chunks`

This approach allows you to:
- Keep the original working version as a backup
- Test the streaming version without risk
- Compare performance and output between both versions
- Easily switch back if needed

## Backward Compatibility

**Maintained**:
- Output format identical (v2.0 chunked format)
- All output files same structure (manifest.json, packets.csv, flows/, ips/, indices/)
- Browser-side code requires no changes

**Changed**:
- Processing happens in chunks (invisible to output)
- New CLI parameters (optional, with defaults)
- Progress output includes chunk information

## Alternative Approaches Considered

### Alt 1: Two-Pass Processing
**Pass 1**: Write packets.csv, collect flow keys
**Pass 2**: Re-read packets.csv, build flows from keys

**Rejected**: Doubles I/O time, requires storing all flow keys

### Alt 2: External Flow Storage
Write flow packets to SQLite/temp files during processing

**Rejected**: Adds complexity, SQLite overhead, disk I/O bottleneck

### Alt 3: Lazy Flow Assembly
Store only flow metadata, load packets on-demand from packets.csv when writing chunk files

**Rejected**: Random access to CSV is inefficient, complex indexing required

## Risk Mitigation

**Risk 1**: Flow timeout logic incorrectly marks active flows as complete
**Mitigation**: Conservative timeout (5 chunks = 2.5M packets), configurable, add validation

**Risk 2**: Incremental flow detection produces different results than original
**Mitigation**: Comprehensive testing with known datasets, compare output byte-for-byte

**Risk 3**: Disk I/O becomes bottleneck with frequent append operations
**Mitigation**: Buffer packets in memory (10k-50k), write in batches; use SSD if available

## Success Criteria

✅ Processes `full_10days_spambot.csv` without out-of-memory errors
✅ Memory usage stays under 2GB peak (vs. 10-20GB currently)
✅ Output files identical to original implementation (for test files)
✅ Processing time within 2x of original (acceptable for 98% memory reduction)
✅ Progress reporting shows chunk-by-chunk status
