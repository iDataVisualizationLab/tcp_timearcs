# Integration Plan: Attack TimeArcs + IP Bar Diagram

## Overview

This document outlines the plan to integrate the Attack TimeArcs visualization with the IP Bar Diagram visualization, allowing users to select attack arcs and view detailed TCP flows for those IPs within the selected time frame.

## Problem Statement

### Current State

| System | Data Source | Size | Features |
|--------|-------------|------|----------|
| Attack TimeArcs | `set1_first90_minutes.csv` | 25 MB | Attack labels, aggregated arcs |
| IP Bar Diagram | `decoded_set1_full.csv` | **60 GB/day** | TCP flows, microsecond timestamps |

### Key Challenges

1. **Different data sources**: Attack data is small/aggregated; flow data is massive/detailed
2. **No attack labels in streaming data**: The 60GB file lacks attack type information
3. **Scale mismatch**: Cannot load 60GB into browser memory
4. **Timestamp formats differ**: Attack data uses minutes, streaming data uses microseconds
5. **Multi-day support gap**: Attack TimeArcs supports multiple files, streaming loader does not

### Multi-File Support Status

| System | Multi-File Support | Implementation |
|--------|-------------------|----------------|
| attack_timearcs.js | ✅ Yes | Iterates files, combines into `combinedData` array |
| tcp_data_loader_streaming.py | ❌ No | Single `--data` argument only |

This gap must be addressed for multi-day analysis scenarios.

### Timestamp Correlation (Verified)

```
Attack TimeArcs:  20954244 minutes
Streaming Data:   1257254615805569 microseconds
                  ↓ convert to minutes
                  20954243.60 minutes

Difference: 0.40 minutes ✓ (same time period)
```

## Solution Architecture

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              WORKFLOW                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  1. ATTACK TIMEARCS (Browser)                                          │ │
│  │     • Load small attack CSV (25 MB)                                    │ │
│  │     • User selects attack arcs via click/brush                         │ │
│  │     • Selection: {ips, timeRange, attackType}                          │ │
│  └────────────────────────────────────┬───────────────────────────────────┘ │
│                                       │                                      │
│                                       ▼                                      │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  2. COMMAND GENERATOR (Browser)                                        │ │
│  │     • Convert minutes → microseconds                                   │ │
│  │     • Format filter parameters                                         │ │
│  │     • Display Python command to user                                   │ │
│  └────────────────────────────────────┬───────────────────────────────────┘ │
│                                       │                                      │
│                                       ▼                                      │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  3. STREAMING LOADER (Python - User runs locally)                      │ │
│  │     • tcp_data_loader_streaming.py with new filter options             │ │
│  │     • Processes 60GB file in 500K row chunks (~200MB RAM)              │ │
│  │     • Filters by IP + time range during streaming                      │ │
│  │     • Outputs small subset folder (1-50 MB)                            │ │
│  └────────────────────────────────────┬───────────────────────────────────┘ │
│                                       │                                      │
│                                       ▼                                      │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  4. IP BAR DIAGRAM (Browser)                                           │ │
│  │     • Load generated subset folder                                     │ │
│  │     • Display TCP flows for selected IPs/time                          │ │
│  │     • Attack context from manifest.json                                │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Component Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           UNIFIED VISUALIZATION                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  unified_timearcs.html                                                        │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │  ┌───────────────────────────────────────────────────────────────────┐  │ │
│  │  │  ATTACK TIMEARCS PANEL (Top)                                      │  │ │
│  │  │  ════════════════════════════════════════════════════════════════ │  │ │
│  │  │    IP1 ──────●────●●●●●────●──────────────────                    │  │ │
│  │  │    IP2 ──────●────●●●●●────●──────────────────                    │  │ │
│  │  │    IP3 ────────────────────●●●●────●──────────                    │  │ │
│  │  │  ════════════════════════════════════════════════════════════════ │  │ │
│  │  │          [====BRUSH SELECTION====]                                │  │ │
│  │  └───────────────────────────────────────────────────────────────────┘  │ │
│  │                                                                          │ │
│  │  ┌───────────────────────────────────────────────────────────────────┐  │ │
│  │  │  SELECTION PANEL (Middle)                                         │  │ │
│  │  │  IPs: 172.28.185.51, 60.203.52.184  (numeric: 1, 2)              │  │ │
│  │  │  Time: 20954244 - 20954250 (6 minutes)                           │  │ │
│  │  │  Attack: client compromise                                        │  │ │
│  │  │                                                                   │  │ │
│  │  │  [Copy Command]  [Show Instructions]                              │  │ │
│  │  └───────────────────────────────────────────────────────────────────┘  │ │
│  │                                                                          │ │
│  │  ┌───────────────────────────────────────────────────────────────────┐  │ │
│  │  │  IP BAR DIAGRAM PANEL (Bottom)                                    │  │ │
│  │  │  [Load Generated Folder]                                          │  │ │
│  │  │  ─────────────────────────────────────────────────────────────── │  │ │
│  │  │   Flow 1: 172.28.185.51:49382 ↔ 60.203.52.184:80                 │  │ │
│  │  │   ┌─────┬─────────────────────────┬─────┐                        │  │ │
│  │  │   │ EST │      DATA TRANSFER      │ CLS │                        │  │ │
│  │  │   └─────┴─────────────────────────┴─────┘                        │  │ │
│  │  └───────────────────────────────────────────────────────────────────┘  │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Implementation Details

### Phase 1: Modify `tcp_data_loader_streaming.py`

**Estimated changes: ~100 lines** (increased due to multi-file support)

#### New Command-Line Arguments

```python
# Change --data to accept multiple files (like attack_extract.py)
parser.add_argument('--data',
    nargs='+',  # Accept one or more files
    required=True,
    help='Input TCP data file(s) (CSV or CSV.GZ) - can specify multiple files for multi-day analysis')

parser.add_argument('--filter-ips', type=str,
    help='Comma-separated list of IP IDs to filter (e.g., "1,2,7204")')

parser.add_argument('--filter-time-start', type=int,
    help='Filter packets >= this timestamp (microseconds)')

parser.add_argument('--filter-time-end', type=int,
    help='Filter packets <= this timestamp (microseconds)')

parser.add_argument('--attack-context', type=str,
    help='Attack type label for this subset (stored in manifest)')
```

#### Multi-File Processing Logic

```python
def process_tcp_data_chunked(data_files, ip_map_file, output_dir, ...):
    """
    Process multiple TCP data files sequentially.

    Args:
        data_files: List of input CSV file paths (can be single file or multiple)
        ...
    """
    # data_files is now a list (even if single file)
    if isinstance(data_files, str):
        data_files = [data_files]

    print(f"Processing {len(data_files)} input file(s)...")

    # Process each file sequentially
    for file_index, data_file in enumerate(data_files, start=1):
        print(f"\n[{file_index}/{len(data_files)}] Processing: {data_file}")

        if not Path(data_file).exists():
            print(f"  WARNING: File not found, skipping: {data_file}")
            continue

        compression = 'gzip' if data_file.endswith('.gz') else None
        csv_iterator = pd.read_csv(data_file, chunksize=chunk_read_size,
                                    compression=compression)

        for df_chunk in csv_iterator:
            # ... existing chunk processing with filtering ...

    # Finalize flows from all files combined
    # (connection_map persists across files for cross-file flows)
```

#### Filtering Logic (in chunk processing loop)

```python
def process_tcp_data_chunked(..., filter_ips=None, filter_time_start=None,
                              filter_time_end=None, attack_context=None):

    # Parse filter IPs into set for O(1) lookup
    ip_filter_set = None
    if filter_ips:
        ip_filter_set = set(filter_ips.split(','))

    for df_chunk in csv_iterator:
        # ... existing IP conversion code ...

        # === NEW: Apply filters BEFORE processing ===

        # Time range filter
        if filter_time_start is not None:
            df_chunk = df_chunk[df_chunk['timestamp'] >= filter_time_start]
        if filter_time_end is not None:
            df_chunk = df_chunk[df_chunk['timestamp'] <= filter_time_end]

        # IP filter (either src or dst must match)
        if ip_filter_set:
            # Convert numeric IPs to string for comparison
            src_match = df_chunk['src_ip'].astype(str).isin(ip_filter_set)
            dst_match = df_chunk['dst_ip'].astype(str).isin(ip_filter_set)
            df_chunk = df_chunk[src_match | dst_match]

        # Skip chunk if empty after filtering
        if len(df_chunk) == 0:
            print(f"Chunk {chunk_number}: skipped (no matching packets)")
            continue

        # ... rest of existing processing ...
```

#### Cross-File Flow Handling

When processing multiple files, TCP flows may span across file boundaries:

```python
# connection_map persists across files
# This allows flows that start in day1.csv to continue in day2.csv

connection_map = {}  # Initialized once, shared across all files

for data_file in data_files:
    for df_chunk in pd.read_csv(data_file, chunksize=...):
        # Incremental flow detection uses shared connection_map
        completed_flows, flow_counter, timed_out = detect_tcp_flows_incremental(
            tcp_chunk,
            connection_map,  # Shared across files!
            ...
        )
```

#### Manifest Enhancement

```python
# At the end, add attack context to manifest
manifest = {
    'version': '2.0',
    'format': 'chunked',
    # ... existing fields ...

    # NEW: Source files (supports multiple)
    'source_files': data_files,  # List of all input files processed

    # NEW: Attack context from selection
    'attack_context': {
        'type': attack_context,
        'source': 'attack_timearcs_selection'
    },
    'filter_applied': {
        'ips': filter_ips.split(',') if filter_ips else None,
        'time_start': filter_time_start,
        'time_end': filter_time_end,
        'time_start_minutes': filter_time_start // 60_000_000 if filter_time_start else None,
        'time_end_minutes': filter_time_end // 60_000_000 if filter_time_end else None
    }
}
```

### Phase 2: Create Unified UI

**Files to create:**
- `unified_timearcs.html` (~200 lines)
- `unified_timearcs.js` (~400 lines)

#### HTML Structure

```html
<!DOCTYPE html>
<html>
<head>
    <title>Unified TimeArcs - Attack + Flow Analysis</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <!-- Header with file loaders -->
    <div id="header">
        <div id="attack-loaders">
            <input type="file" id="attack-csv" accept=".csv">
            <input type="file" id="ip-map" accept=".json">
            <input type="file" id="event-mapping" accept=".json">
        </div>
    </div>

    <!-- Attack TimeArcs Panel -->
    <div id="attack-panel">
        <h3>Attack TimeArcs</h3>
        <svg id="attack-svg"></svg>
    </div>

    <!-- Selection Info Panel -->
    <div id="selection-panel">
        <h3>Selection</h3>
        <div id="selection-info">
            <p>IPs: <span id="selected-ips">-</span></p>
            <p>Time: <span id="selected-time">-</span></p>
            <p>Attack: <span id="selected-attack">-</span></p>
        </div>
        <div id="command-area">
            <pre id="python-command"></pre>
            <button id="copy-command">Copy Command</button>
        </div>
    </div>

    <!-- IP Bar Diagram Panel -->
    <div id="flow-panel">
        <h3>TCP Flows</h3>
        <button id="load-folder">Load Generated Folder</button>
        <svg id="flow-svg"></svg>
    </div>

    <script type="module" src="unified_timearcs.js"></script>
</body>
</html>
```

#### JavaScript: Selection Handler

```javascript
// unified_timearcs.js

// Timestamp conversion utilities
function minutesToMicroseconds(minutes) {
    return BigInt(minutes) * 60n * 1_000_000n;
}

function microsecondsToMinutes(us) {
    return Number(BigInt(us) / 60_000_000n);
}

// Selection state
let currentSelection = {
    ips: [],
    ipNames: [],
    timeRange: [null, null],
    attackType: null
};

// Handle arc selection (called from attack_timearcs interaction)
function onArcSelection(selectedArcs) {
    // Extract unique IPs from selected arcs
    const ipSet = new Set();
    const ipNameSet = new Set();
    let minTime = Infinity, maxTime = -Infinity;
    const attackCounts = {};

    selectedArcs.forEach(arc => {
        // Collect IPs (both numeric IDs and resolved names)
        ipSet.add(arc.sourceId);
        ipSet.add(arc.targetId);
        ipNameSet.add(arc.source);
        ipNameSet.add(arc.target);

        // Track time range
        minTime = Math.min(minTime, arc.minute);
        maxTime = Math.max(maxTime, arc.minute);

        // Count attack types
        attackCounts[arc.attack] = (attackCounts[arc.attack] || 0) + arc.count;
    });

    // Find dominant attack type
    const dominantAttack = Object.entries(attackCounts)
        .sort((a, b) => b[1] - a[1])[0]?.[0] || 'unknown';

    currentSelection = {
        ips: Array.from(ipSet),
        ipNames: Array.from(ipNameSet),
        timeRange: [minTime, maxTime],
        attackType: dominantAttack
    };

    updateSelectionUI();
    generatePythonCommand();
}

// Generate Python command for subset extraction
function generatePythonCommand() {
    const { ips, timeRange, attackType } = currentSelection;

    if (ips.length === 0 || !timeRange[0]) {
        document.getElementById('python-command').textContent = '# Make a selection first';
        return;
    }

    // Convert time range from minutes to microseconds
    const timeStartUs = minutesToMicroseconds(timeRange[0]);
    const timeEndUs = minutesToMicroseconds(timeRange[1] + 1); // +1 to include full minute

    const command = `python tcp_data_loader_streaming.py \\
  --data /path/to/decoded_set1_full.csv \\
  --ip-map combined_pcap_data_set5_compressed_ip_map.json \\
  --output-dir subset_${attackType.replace(/\s+/g, '_')}_${Date.now()}/ \\
  --filter-ips ${ips.join(',')} \\
  --filter-time-start ${timeStartUs} \\
  --filter-time-end ${timeEndUs} \\
  --attack-context "${attackType}"`;

    document.getElementById('python-command').textContent = command;
}

// Copy command to clipboard
document.getElementById('copy-command').addEventListener('click', () => {
    const command = document.getElementById('python-command').textContent;
    navigator.clipboard.writeText(command);
    alert('Command copied to clipboard!');
});
```

### Phase 3: Integrate Existing Modules

The unified UI will import and use existing modules:

```javascript
// unified_timearcs.js

// Import existing attack_timearcs functionality
import { parseCSVStream, render as renderAttackArcs } from './attack_timearcs.js';

// Import existing IP bar diagram functionality
import { visualizeTimeArcs } from './ip_bar_diagram.js';

// Import folder loader for generated subset
import { FolderLoader } from './folder_loader.js';
```

## User Workflow

### Step-by-Step Instructions

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           USER WORKFLOW                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  STEP 1: Open Unified Visualization                                         │
│  ───────────────────────────────────                                        │
│  • Open unified_timearcs.html in Chrome/Edge                                │
│  • Load attack CSV: set1_first90_minutes.csv                                │
│  • Load IP map: combined_pcap_data_set5_compressed_ip_map.json              │
│  • Load event mapping: event_type_mapping.json                              │
│                                                                              │
│  STEP 2: Explore Attack Patterns                                            │
│  ──────────────────────────────                                             │
│  • View attack arcs in top panel                                            │
│  • Hover over arcs to see details                                           │
│  • Use legend to filter by attack type                                      │
│                                                                              │
│  STEP 3: Select Attack Arcs                                                 │
│  ─────────────────────────────                                              │
│  • Click individual arc to select                                           │
│  • Or brush (click+drag) to select time range                               │
│  • Selection panel shows: IPs, time range, attack type                      │
│                                                                              │
│  STEP 4: Copy and Run Python Command                                        │
│  ────────────────────────────────────                                       │
│  • Click "Copy Command" button                                              │
│  • Open terminal, navigate to tcp_timearcs directory                        │
│  • Paste and run command (adjust --data path as needed)                     │
│  • Wait for processing (typically 10-60 seconds)                            │
│                                                                              │
│  STEP 5: Load Generated Subset                                              │
│  ─────────────────────────────                                              │
│  • Click "Load Generated Folder" in bottom panel                            │
│  • Select the output directory from Python command                          │
│  • View TCP flows for selected IPs in selected time range                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Example Session (Single File)

```bash
# User selects arcs showing DDoS attack between IPs 1,2 at minutes 20954244-20954250

# Generated command (single day):
python tcp_data_loader_streaming.py \
  --data /mnt/data/decoded_set1_full.csv \
  --ip-map combined_pcap_data_set5_compressed_ip_map.json \
  --output-dir subset_ddos_1702345678/ \
  --filter-ips 1,2 \
  --filter-time-start 1257254640000000 \
  --filter-time-end 1257255000000000 \
  --attack-context "ddos"

# Output:
# Loading IP mapping from combined_pcap_data_set5_compressed_ip_map.json...
# Processing 1 input file(s)...
# [1/1] Processing: /mnt/data/decoded_set1_full.csv
# Chunk 1: skipped (no matching packets)
# Chunk 2: skipped (no matching packets)
# ...
# Chunk 47: processed 12,345 packets, 11,234 TCP, 156 active flows...
# ...
# Successfully processed data:
#   - Total packets: 45,678
#   - TCP packets: 42,345
#   - Unique IPs: 2
#   - Total flows: 234
#   - Output directory: subset_ddos_1702345678/
```

### Example Session (Multiple Days)

```bash
# User loads multiple days in attack_timearcs, selects arcs spanning day 1 and day 2

# Generated command (multi-day):
python tcp_data_loader_streaming.py \
  --data /mnt/data/decoded_set1_day1.csv \
        /mnt/data/decoded_set1_day2.csv \
        /mnt/data/decoded_set1_day3.csv \
  --ip-map combined_pcap_data_set5_compressed_ip_map.json \
  --output-dir subset_multiday_ddos/ \
  --filter-ips 1,2,15,42 \
  --filter-time-start 1257254640000000 \
  --filter-time-end 1257427440000000 \
  --attack-context "ddos"

# Output:
# Loading IP mapping from combined_pcap_data_set5_compressed_ip_map.json...
# Processing 3 input file(s)...
#
# [1/3] Processing: /mnt/data/decoded_set1_day1.csv
# Chunk 1: skipped (no matching packets)
# ...
# Chunk 47: processed 12,345 packets, 11,234 TCP, 156 active flows...
#   File complete: 45,678 matched rows
#
# [2/3] Processing: /mnt/data/decoded_set1_day2.csv
# Chunk 1: processed 8,901 packets, 8,234 TCP, 89 active flows...
# ...
#   File complete: 38,901 matched rows
#
# [3/3] Processing: /mnt/data/decoded_set1_day3.csv
# ...
#   File complete: 12,456 matched rows
#
# Successfully processed data:
#   - Source files: 3
#   - Total packets: 97,035
#   - TCP packets: 89,234
#   - Unique IPs: 4
#   - Total flows: 567 (including 23 cross-file flows)
#   - Output directory: subset_multiday_ddos/
```

## Technical Details

### Memory Efficiency

The streaming loader maintains low memory usage by:

1. **Chunked CSV reading**: 500,000 rows at a time (configurable)
2. **Early filtering**: Packets filtered before processing
3. **Incremental flow writing**: Completed flows written to disk, freed from memory
4. **Timeout-based completion**: Flows completed after 300s inactivity

```
Memory usage comparison:
─────────────────────────────────────────
Without streaming:  10-20 GB (entire file in memory)
With streaming:     ~200 MB (constant regardless of file size)
With filtering:     ~50-100 MB (fewer active flows)
```

### Filtering Efficiency

```
60 GB file, 6-minute selection, 2 IPs:
─────────────────────────────────────────
Total chunks:           ~120 (500K rows each)
Chunks with matches:    ~5-10
Processing time:        10-60 seconds
Output size:            1-50 MB
```

### Attack Label Correlation

Since the streaming data lacks attack labels, they are inherited from the selection:

```
Attack TimeArcs Selection:
├── IPs: [1, 2]
├── Time: 20954244 - 20954250 (minutes)
└── Attack: "ddos"
          │
          ▼
All extracted flows labeled as "ddos" in manifest.json
```

This is valid because:
- Attack arcs represent the dominant attack type for that IP pair at that time
- User specifically selected that attack pattern
- Individual packet-level attack labels don't exist anyway

## Files Summary

### Files to Modify

| File | Changes | Lines |
|------|---------|-------|
| `tcp_data_loader_streaming.py` | Add multi-file support + filter args + logic | ~100 |

### Files to Create

| File | Purpose | Lines |
|------|---------|-------|
| `unified_timearcs.html` | Combined UI layout | ~200 |
| `unified_timearcs.js` | Selection + command generation (multi-file aware) | ~450 |

### Existing Files Used (No Changes)

| File | Purpose |
|------|---------|
| `attack_timearcs.js` | Attack arc rendering (already supports multi-file) |
| `ip_bar_diagram.js` | TCP flow rendering |
| `folder_loader.js` | Folder-based data loading |
| `folder_integration.js` | UI integration for folder loader |

### Multi-File Considerations

The unified UI must track which source files were loaded in attack_timearcs to generate the correct `--data` arguments:

```javascript
// Track loaded attack data files
let loadedAttackFiles = [];

fileInput.addEventListener('change', (e) => {
    loadedAttackFiles = Array.from(e.target.files).map(f => f.name);
});

// When generating command, include all corresponding streaming data files
function generateCommand(selection) {
    // Map attack CSV names to streaming data file paths
    // e.g., "day1_attacks.csv" → "/path/to/decoded_day1.csv"
    const streamingFiles = loadedAttackFiles.map(f => mapToStreamingFile(f));

    return `python tcp_data_loader_streaming.py \\
  --data ${streamingFiles.join(' \\\n        ')} \\
  --filter-ips ${selection.ips.join(',')} \\
  ...`;
}
```

## Future Enhancements (Optional)

### Automated Backend

For seamless integration without manual Python runs:

```python
# tcp_server.py - Simple Flask server
from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

@app.route('/extract', methods=['POST'])
def extract():
    params = request.json
    # Run streaming loader with filter params
    subprocess.run([
        'python', 'tcp_data_loader_streaming.py',
        '--data', params['data_path'],
        '--ip-map', params['ip_map'],
        '--output-dir', params['output_dir'],
        '--filter-ips', params['filter_ips'],
        '--filter-time-start', str(params['time_start']),
        '--filter-time-end', str(params['time_end']),
        '--attack-context', params['attack_context']
    ])
    return jsonify({"status": "complete", "output": params['output_dir']})

if __name__ == '__main__':
    app.run(port=5000)
```

### Pre-computed Time Index

For even faster filtering on repeated queries:

```python
# tcp_time_index.py - One-time index generation
# Creates byte offsets for each minute in 60GB file
# Enables O(1) seeking instead of sequential scan
```

## Appendix

### Timestamp Conversion Reference

```
Minutes to Microseconds:
────────────────────────
minutes × 60 × 1,000,000 = microseconds

Example:
20954244 × 60 × 1,000,000 = 1,257,254,640,000,000 μs

Microseconds to Minutes:
────────────────────────
microseconds ÷ 60,000,000 = minutes

Example:
1,257,254,615,805,569 ÷ 60,000,000 = 20,954,243.60 minutes
```

### Data Format Reference

#### Attack TimeArcs Input CSV
```csv
timestamp,length,src_ip,dst_ip,protocol,src_port,dst_port,flags,attack,count
20954244,66,7204,7203,6,80,52784,16,25,1
```

#### Streaming Loader Input CSV
```csv
timestamp,length,protocol,src_port,dst_port,src_ip,dst_ip,flags,seq_num,ack_num
1257254615805569,66.0,6,49382,80,1.0,2.0,16,2183799410,4243715536
```

#### Generated Output Structure
```
subset_output/
├── manifest.json          # Includes attack_context
├── packets.csv            # Filtered packets
├── flows/
│   ├── flows_index.json
│   └── chunk_00000.json
├── ips/
│   ├── ip_stats.json
│   ├── flag_stats.json
│   └── unique_ips.json
└── indices/
    └── bins.json
```
