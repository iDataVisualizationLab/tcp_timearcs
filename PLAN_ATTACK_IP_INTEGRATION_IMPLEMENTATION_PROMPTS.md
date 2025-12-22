# Implementation Prompts for Attack TimeArcs + IP Bar Diagram Integration

This document contains detailed, self-contained prompts for each implementation phase. Each prompt can be fed to an AI assistant to implement that specific phase.

---

## Phase 1: Modify `tcp_data_loader_streaming.py`

### Prompt

```
You are modifying the file `tcp_data_loader_streaming.py` to add multi-file support and filtering capabilities.

## Context

This is a memory-efficient TCP data loader that:
- Processes large CSV files (60GB+) in chunks of 500K rows
- Detects TCP flows incrementally with timeout-based completion
- Generates a chunked folder structure (v2.0 format) for browser visualization
- Currently only accepts a single `--data` file

## Your Task

Add the following features to `tcp_data_loader_streaming.py`:

### 1. Multi-File Support

Change the `--data` argument to accept multiple files:

```python
parser.add_argument('--data',
    nargs='+',  # Accept one or more files
    required=True,
    help='Input TCP data file(s) (CSV or CSV.GZ) - can specify multiple files for multi-day analysis')
```

Modify `process_tcp_data_chunked()` to:
- Accept `data_files` as a list (rename from `data_file`)
- Iterate through each file sequentially
- Print progress like `[1/3] Processing: filename.csv`
- Skip missing files with a warning
- Keep `connection_map` shared across all files (for cross-file TCP flows)

### 2. New Filter Arguments

Add these new command-line arguments:

```python
parser.add_argument('--filter-ips', type=str, default=None,
    help='Comma-separated list of IP IDs to filter (e.g., "1,2,7204"). Only packets involving these IPs are processed.')

parser.add_argument('--filter-time-start', type=int, default=None,
    help='Filter packets with timestamp >= this value (microseconds since epoch)')

parser.add_argument('--filter-time-end', type=int, default=None,
    help='Filter packets with timestamp <= this value (microseconds since epoch)')

parser.add_argument('--attack-context', type=str, default=None,
    help='Attack type label for this subset (stored in manifest.json for UI display)')
```

### 3. Filtering Logic

Inside the chunk processing loop, BEFORE any other processing, add filtering:

```python
# Parse filter IPs once at the start
ip_filter_set = None
if filter_ips:
    ip_filter_set = set(filter_ips.split(','))

# Inside the loop, after loading df_chunk:

# Apply time range filter
if filter_time_start is not None:
    df_chunk = df_chunk[df_chunk['timestamp'] >= filter_time_start]
if filter_time_end is not None:
    df_chunk = df_chunk[df_chunk['timestamp'] <= filter_time_end]

# Apply IP filter (match either src_ip OR dst_ip)
if ip_filter_set:
    # After IP conversion, filter by IP
    src_match = df_chunk['src_ip'].astype(str).isin(ip_filter_set)
    dst_match = df_chunk['dst_ip'].astype(str).isin(ip_filter_set)
    df_chunk = df_chunk[src_match | dst_match]

# Skip empty chunks
if len(df_chunk) == 0:
    print(f"Chunk {chunk_number}: skipped (no matching packets)")
    continue
```

### 4. Update Manifest

Add these fields to the manifest.json output:

```python
manifest = {
    # ... existing fields ...

    # NEW: List of source files processed
    'source_files': [str(f) for f in data_files],

    # NEW: Attack context from selection
    'attack_context': {
        'type': attack_context,
        'source': 'attack_timearcs_selection'
    } if attack_context else None,

    # NEW: Filter parameters applied
    'filter_applied': {
        'ips': filter_ips.split(',') if filter_ips else None,
        'time_start_us': filter_time_start,
        'time_end_us': filter_time_end,
        'time_start_minutes': filter_time_start // 60_000_000 if filter_time_start else None,
        'time_end_minutes': filter_time_end // 60_000_000 if filter_time_end else None
    }
}
```

### 5. Update Function Signature

Update `process_tcp_data_chunked()` signature:

```python
def process_tcp_data_chunked(data_files, ip_map_file, output_dir, max_records=None,
                             chunk_size=200, chunk_read_size=500000, flow_timeout_seconds=300,
                             filter_ips=None, filter_time_start=None, filter_time_end=None,
                             attack_context=None):
```

And update the `main()` function to pass these new arguments.

### 6. Update Input Validation

In `main()`, update the file existence check:

```python
# Check if input files exist (now a list)
for data_file in args.data:
    if not Path(data_file).exists():
        print(f"Warning: Data file '{data_file}' not found", file=sys.stderr)
        # Don't exit - just warn, the loop will skip missing files
```

## Important Notes

- Maintain backward compatibility: single file usage should still work
- The IP filter should work with BOTH numeric IDs (e.g., "1", "2") AND dotted-quad IPs (e.g., "192.168.1.1")
- Apply filters BEFORE IP conversion to maximize performance (skip unnecessary conversions)
- Print summary statistics at the end showing how many packets were filtered

## Example Usage After Implementation

```bash
# Single file (backward compatible)
python tcp_data_loader_streaming.py \
  --data decoded_set1.csv \
  --ip-map ip_map.json \
  --output-dir output/

# Multiple files
python tcp_data_loader_streaming.py \
  --data decoded_day1.csv decoded_day2.csv decoded_day3.csv \
  --ip-map ip_map.json \
  --output-dir output/

# With filtering
python tcp_data_loader_streaming.py \
  --data decoded_day1.csv decoded_day2.csv \
  --ip-map ip_map.json \
  --output-dir subset_output/ \
  --filter-ips 1,2,15,42 \
  --filter-time-start 1257254640000000 \
  --filter-time-end 1257427440000000 \
  --attack-context "ddos"
```

## Files to Read First

Before making changes, read:
1. `tcp_data_loader_streaming.py` - the file you're modifying
2. `attack_extract.py` - reference for multi-file argument pattern (nargs='+')
```

---

## Phase 2: Create `unified_timearcs.html`

### Prompt

```
You are creating a new HTML file `unified_timearcs.html` that provides a split-pane interface combining Attack TimeArcs visualization with IP Bar Diagram visualization.

## Context

This project has two separate visualization systems:
1. **Attack TimeArcs** (`attack_timearcs.html`) - Shows attack patterns as arcs over time
2. **IP Bar Diagram** (`index.html` + `ip_bar_diagram.js`) - Shows TCP flow details

We need to combine them into a unified interface where users can:
1. Load and view attack arcs in the top panel
2. Select attack arcs (click or brush)
3. See a generated Python command in the middle panel
4. Load generated subset data in the bottom panel to view TCP flows

## Your Task

Create `unified_timearcs.html` with the following structure:

### 1. HTML Structure

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Unified TimeArcs - Attack + Flow Analysis</title>

    <!-- Include D3.js -->
    <script src="https://d3js.org/d3.v7.min.js"></script>

    <!-- Existing styles -->
    <link rel="stylesheet" href="styles.css">

    <style>
        /* Add unified layout styles */
    </style>
</head>
<body>
    <!-- Header with data loaders -->
    <!-- Attack TimeArcs panel -->
    <!-- Selection info panel with Python command -->
    <!-- IP Bar Diagram panel -->

    <script type="module" src="unified_timearcs.js"></script>
</body>
</html>
```

### 2. Header Section

Create a header with file input controls:

```html
<header id="header">
    <h1>Unified TimeArcs - Attack + Flow Analysis</h1>

    <div class="file-controls">
        <!-- Attack data loaders (for top panel) -->
        <div class="control-group">
            <label>Attack Data:</label>
            <input type="file" id="attack-csv-input" accept=".csv" multiple>
            <span class="file-hint">Load attack CSV(s) - supports multiple files</span>
        </div>

        <div class="control-group">
            <label>IP Map:</label>
            <input type="file" id="ip-map-input" accept=".json">
        </div>

        <div class="control-group">
            <label>Event Mapping:</label>
            <input type="file" id="event-mapping-input" accept=".json">
        </div>
    </div>
</header>
```

### 3. Attack TimeArcs Panel (Top)

```html
<section id="attack-panel" class="panel">
    <div class="panel-header">
        <h2>Attack TimeArcs</h2>
        <div class="panel-controls">
            <label>
                <input type="radio" name="label-mode" value="attack" checked>
                Attack Type
            </label>
            <label>
                <input type="radio" name="label-mode" value="attack_group">
                Attack Group
            </label>
            <button id="toggle-lensing">Toggle Lensing (Shift+L)</button>
        </div>
    </div>

    <div id="attack-viz-container">
        <svg id="attack-svg"></svg>
    </div>

    <div id="attack-legend"></div>
    <div id="attack-status" class="status-bar"></div>
</section>
```

### 4. Selection Info Panel (Middle)

```html
<section id="selection-panel" class="panel">
    <div class="panel-header">
        <h2>Selection</h2>
        <button id="clear-selection">Clear Selection</button>
    </div>

    <div id="selection-info">
        <div class="info-row">
            <span class="label">Selected IPs:</span>
            <span id="selected-ips" class="value">-</span>
        </div>
        <div class="info-row">
            <span class="label">IP Names:</span>
            <span id="selected-ip-names" class="value">-</span>
        </div>
        <div class="info-row">
            <span class="label">Time Range:</span>
            <span id="selected-time-range" class="value">-</span>
        </div>
        <div class="info-row">
            <span class="label">Attack Type:</span>
            <span id="selected-attack-type" class="value">-</span>
        </div>
        <div class="info-row">
            <span class="label">Packet Count:</span>
            <span id="selected-packet-count" class="value">-</span>
        </div>
    </div>

    <div id="command-section">
        <h3>Python Command</h3>
        <p class="hint">Run this command to extract TCP flow data for the selected IPs and time range:</p>

        <div id="streaming-files-config">
            <label>Streaming Data Path:</label>
            <input type="text" id="streaming-data-path"
                   placeholder="/path/to/decoded_data/"
                   value="/mnt/data/">
            <span class="hint">Base path where streaming CSV files are located</span>
        </div>

        <pre id="python-command"># Make a selection in the Attack TimeArcs panel above</pre>

        <div class="command-buttons">
            <button id="copy-command" disabled>Copy Command</button>
            <button id="show-instructions">Show Instructions</button>
        </div>
    </div>
</section>
```

### 5. IP Bar Diagram Panel (Bottom)

```html
<section id="flow-panel" class="panel">
    <div class="panel-header">
        <h2>TCP Flow Analysis</h2>
        <div class="panel-controls">
            <button id="load-folder-btn">Load Generated Folder</button>
            <span id="flow-status" class="status-text">No data loaded</span>
        </div>
    </div>

    <div id="flow-sidebar" class="sidebar">
        <!-- IP selection checkboxes will be populated here -->
        <div id="ip-checkboxes"></div>

        <!-- Flow statistics -->
        <div id="flow-stats"></div>
    </div>

    <div id="flow-viz-container">
        <svg id="flow-svg"></svg>
    </div>

    <div id="flow-legend"></div>
</section>
```

### 6. Instructions Modal

```html
<div id="instructions-modal" class="modal hidden">
    <div class="modal-content">
        <span class="close-btn">&times;</span>
        <h2>How to Use</h2>

        <h3>Step 1: Load Attack Data</h3>
        <p>Load your attack CSV file(s) and mapping files in the header.</p>

        <h3>Step 2: Select Attack Arcs</h3>
        <p>Click on arcs or use brush selection to select attack traffic.</p>

        <h3>Step 3: Run Python Command</h3>
        <p>Copy the generated command and run it in your terminal:</p>
        <pre>cd /path/to/tcp_timearcs
python tcp_data_loader_streaming.py ...</pre>

        <h3>Step 4: Load Generated Data</h3>
        <p>Click "Load Generated Folder" and select the output directory.</p>

        <button class="close-modal-btn">Got it!</button>
    </div>
</div>
```

### 7. CSS Styles

Include comprehensive styles for:
- Dark theme (background: #1a1a2e)
- Split-pane layout with resizable panels
- File input controls
- Selection panel with Python command display
- Modal styling
- Responsive design for smaller screens

## Important Notes

- The HTML should be self-contained and work with the existing styles.css
- Use `type="module"` for the script tag to support ES6 imports
- Support multiple file selection for attack CSVs
- The streaming data path input allows users to configure where their raw data files are located
- Include proper ARIA labels for accessibility

## Files to Reference

Before creating this file, look at:
1. `attack_timearcs.html` - existing attack visualization layout
2. `index.html` - existing IP bar diagram layout
3. `styles.css` - existing styles to maintain consistency
```

---

## Phase 3: Create `unified_timearcs.js`

### Prompt

```
You are creating a new JavaScript module `unified_timearcs.js` that orchestrates the unified TimeArcs interface, handling:
1. Loading attack data and rendering in the top panel
2. Selection handling (click, brush) on attack arcs
3. Generating Python commands based on selection
4. Loading generated subset data into the bottom panel

## Context

The unified interface combines:
- **Attack TimeArcs** (`attack_timearcs.js`) - existing attack visualization
- **IP Bar Diagram** (`ip_bar_diagram.js`) - existing flow visualization
- **Folder Loader** (`folder_loader.js`) - for loading generated subsets

The user workflow is:
1. Load attack CSV(s) → View attack arcs
2. Select arcs → See Python command
3. Run Python command externally
4. Load generated folder → View TCP flows

## Your Task

Create `unified_timearcs.js` as an ES6 module with the following functionality:

### 1. State Management

```javascript
const state = {
    // Loaded data
    attackData: [],
    ipMap: new Map(),           // IP ID → IP address
    reverseIpMap: new Map(),    // IP address → IP ID
    eventMapping: {},

    // Loaded file tracking (for multi-file support)
    loadedAttackFiles: [],

    // Selection state
    selection: {
        ips: [],                // Numeric IP IDs
        ipNames: [],            // Dotted-quad IP addresses
        timeRange: [null, null], // [startMinute, endMinute]
        attackType: null,
        packetCount: 0
    },

    // Configuration
    config: {
        streamingDataPath: '/mnt/data/',
        ipMapPath: 'combined_pcap_data_set5_compressed_ip_map.json'
    },

    // Flow panel state
    flowData: null
};
```

### 2. Timestamp Utilities

```javascript
/**
 * Convert minutes (attack_timearcs format) to microseconds (streaming format)
 */
function minutesToMicroseconds(minutes) {
    return BigInt(minutes) * 60n * 1_000_000n;
}

/**
 * Convert microseconds to minutes
 */
function microsecondsToMinutes(microseconds) {
    return Number(BigInt(microseconds) / 60_000_000n);
}
```

### 3. File Loading Functions

- `handleAttackCsvLoad(event)` - Load multiple attack CSVs, combine data
- `handleIpMapLoad(event)` - Load IP mapping JSON
- `handleEventMappingLoad(event)` - Load event type mapping
- `parseAttackCsv(text)` - Parse CSV text to objects
- `resolveIpName(ipId)` - Resolve numeric IP ID to address

### 4. Selection Handling

- `handleArcSelection(event)` - Handle single arc click
- `handleBrushSelection(event)` - Handle brush selection of multiple arcs
- `addIpToSelection(ipName, ipId)` - Add IP to selection set
- `updateTimeRange(minute)` - Expand time range to include minute
- `clearSelection()` - Reset selection state

### 5. Python Command Generation

```javascript
function updatePythonCommand() {
    const sel = state.selection;

    if (sel.ips.length === 0) {
        // Show placeholder
        return;
    }

    // Map attack CSV names to streaming data paths
    const streamingFiles = mapToStreamingFiles(state.loadedAttackFiles);

    // Convert time range to microseconds
    const timeStartUs = minutesToMicroseconds(sel.timeRange[0]);
    const timeEndUs = minutesToMicroseconds(sel.timeRange[1] + 1);

    // Generate command string
    const command = `python tcp_data_loader_streaming.py \\
  --data ${streamingFiles.join(' ')} \\
  --ip-map ${state.config.ipMapPath} \\
  --output-dir subset_${sel.attackType}_${Date.now()}/ \\
  --filter-ips ${sel.ips.join(',')} \\
  --filter-time-start ${timeStartUs} \\
  --filter-time-end ${timeEndUs} \\
  --attack-context "${sel.attackType}"`;

    document.getElementById('python-command').textContent = command;
}

function mapToStreamingFiles(attackFiles) {
    // Map attack CSV names to streaming data file paths
    // User configures base path in UI
    return attackFiles.map(f => {
        // Apply naming convention transformation
        // e.g., "day1_attacks.csv" → "/mnt/data/decoded_day1.csv"
        return `${state.config.streamingDataPath}decoded_${f.replace(/_attacks?\.csv$/i, '.csv')}`;
    });
}
```

### 6. Flow Panel Integration

- `initFlowPanel()` - Set up folder loading
- `handleLoadFolder()` - Trigger File System Access API
- `handleFolderDataLoaded(event)` - Process loaded folder data
- `renderFlowVisualization()` - Dispatch to ip_bar_diagram.js

### 7. Event-Based Architecture

Use custom events for loose coupling with existing modules:

```javascript
// Dispatch when attack data is ready
document.dispatchEvent(new CustomEvent('attackDataLoaded', {
    detail: { data, ipMap, eventMapping }
}));

// Listen for arc selection from attack_timearcs.js
document.addEventListener('arcSelected', handleArcSelection);

// Listen for folder data from folder_loader.js
document.addEventListener('folderDataLoaded', handleFolderDataLoaded);
```

### 8. UI Updates

- `updateSelectionUI()` - Update selection info display
- `updateStatus(elementId, message)` - Update status messages
- `initCopyButton()` - Set up clipboard copy functionality
- `initModal()` - Set up instructions modal

## Important Implementation Notes

1. **BigInt for Microseconds**: Use BigInt for precise microsecond calculations
2. **Multi-file Tracking**: Track loaded attack file names to generate correct streaming data paths
3. **Error Handling**: Wrap async operations in try-catch, show user-friendly errors
4. **Event Architecture**: Use custom events to integrate with existing modules without tight coupling

## Files to Reference

Before creating this file, read:
1. `attack_timearcs.js` - understand data format, rendering, selection handling
2. `ip_bar_diagram.js` - understand flow visualization
3. `folder_loader.js` - understand folder loading API
4. `folder_integration.js` - understand UI integration patterns
```

---

## Phase 4 (Optional): Create `tcp_server.py`

### Prompt

```
You are creating an optional Python Flask server `tcp_server.py` that allows the browser to trigger data extraction without manual command-line execution.

## Context

The unified TimeArcs interface generates a Python command that users must manually run. This optional server automates that process:
1. Browser sends extraction request via HTTP
2. Server runs tcp_data_loader_streaming.py with the specified parameters
3. Server responds when extraction is complete
4. Browser can then load the generated folder

## Your Task

Create `tcp_server.py` with the following endpoints:

### Endpoints

1. **GET /health** - Health check, returns config and active jobs
2. **POST /extract** - Trigger extraction job
   - Body: `{ data_files, filter_ips, time_start, time_end, attack_context }`
   - Returns: `{ job_id, status, output_dir }`
3. **GET /job/<job_id>** - Get job status
   - Returns: `{ status, duration, error, last_log }`
4. **GET /job/<job_id>/log** - Get full job log
5. **GET /jobs** - List all jobs

### Key Features

- Run extraction in background threads
- Track job progress and capture output
- CORS enabled for browser requests
- Configurable data directory and output paths

### Security Note

This server executes local Python scripts based on browser requests. Only run on trusted local networks.

## Usage

```bash
pip install flask flask-cors
python tcp_server.py --port 5000 --data-dir /mnt/data/
```

## Browser Integration

Add optional server extraction to unified_timearcs.js:

```javascript
async function triggerServerExtraction() {
    const response = await fetch('http://localhost:5000/extract', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            data_files: streamingFiles,
            filter_ips: selection.ips.join(','),
            time_start: timeStartUs,
            time_end: timeEndUs,
            attack_context: attackType
        })
    });
    // Poll for completion
}
```
```

---

## Summary of All Phases

| Phase | File | Purpose | Lines |
|-------|------|---------|-------|
| 1 | `tcp_data_loader_streaming.py` | Add multi-file + filter support | ~100 changes |
| 2 | `unified_timearcs.html` | Combined UI layout | ~300 |
| 3 | `unified_timearcs.js` | Selection + command generation | ~500 |
| 4 | `tcp_server.py` (optional) | Automated extraction server | ~200 |
