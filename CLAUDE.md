# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**TCP TimeArcs** is a network traffic visualization tool that extends the TimeArcs technique for visualizing temporal relationships in TCP/IP packet data. It processes network traffic captures (CSV format) and creates interactive arc-based visualizations showing connections between IP addresses over time, with special emphasis on attack traffic patterns.

The project combines Python data processing scripts with browser-based D3.js visualizations, supporting multiple data loading strategies for different dataset sizes (from thousands to millions of packets).

## Core Architecture

### Data Processing Pipeline (Python → JSON/CSV)

**Flow**: Raw PCAP/CSV → Python processors → Structured JSON/CSV → Browser visualization

1. **tcp_data_loader.py** - Basic single-file processor for small datasets
2. **tcp_data_loader_all.py** - Comprehensive processor with full TCP flow state machine
3. **tcp_data_loader_split.py** - Generates folder structure with individual flow files (v1.0 format)
4. **tcp_data_loader_chunked.py** - Generates chunked flow files (v2.0 format, preferred)

All Python loaders implement the same TCP flow detection logic:
- 3-way handshake detection (SYN → SYN+ACK → ACK)
- Flow state tracking (establishment, data transfer, closing)
- Proper flow termination (FIN/RST handling)
- IP address mapping to numeric IDs

### Visualization Architecture (Browser)

**Two parallel visualization systems:**

#### 1. Legacy System (attack_timearcs.html + attack_timearcs.js)
- Direct CSV upload with multiple files
- Synchronous rendering
- Best for small datasets (<100k packets)
- Features lensing/magnification (mouse-based time zooming)
- Entry point: [attack_timearcs.html](attack_timearcs.html)

#### 2. Modern System (index.html + modular JS)
- Folder-based loading with File System Access API
- Progressive rendering with Web Workers
- Handles large datasets (1M+ packets)
- Entry point: [index.html](index.html)

**Key JavaScript Modules:**
- **folder_loader.js** - Handles File System Access API for folder-based loading
- **folder_integration.js** - Bridges folder loader with visualization
- **ip_bar_diagram.js** / **ip_arc_diagram.js** - Main visualization renderers
- **overview_chart.js** - Time-series overview with clickable bins
- **legends.js** - Legend rendering and filtering
- **sidebar.js** - IP selection sidebar
- **config.js** - Global configuration (bin counts, batch sizes)

### TypeScript Worker System (src/)

High-performance data ingestion using Web Workers and browser storage:

**Architecture**: Parse Workers → Aggregator → Tile Store (OPFS/IndexedDB)

- **src/ingest/parse-worker.ts** - CSV parsing in parallel workers
- **src/ingest/aggregate-worker.ts** - Aggregates parsed data into time tiles
- **src/ingest/worker-pool.ts** - Orchestrates worker pool and data flow
- **src/storage/tile-store.ts** - Persists time-binned data (OPFS preferred, IndexedDB fallback)
- **src/api.ts** - Public API for ingestion and querying

**Data model**: Time-series points stored in 60-second tiles (configurable) as Float64Arrays

## Data Generation Commands

### Quick Start (Small Dataset)
```bash
# Generate folder structure with chunked flows (recommended)
python tcp_data_loader_chunked.py \
  --data set1_first90_minutes.csv \
  --ip-map combined_pcap_data_set5_compressed_ip_map.json \
  --output-dir output_folder

# Legacy single-file format
python tcp_data_loader.py \
  --data set1_first90_minutes.csv \
  --ip-map combined_pcap_data_set5_compressed_ip_map.json \
  --output output.json
```

### Common Options
```bash
--data FILE           # Input CSV (supports .csv.gz)
--ip-map FILE         # JSON mapping of IP→numeric ID
--output-dir DIR      # Output directory for split files
--max-records N       # Limit packets processed (for testing)
--chunk-size N        # Flows per chunk file (default: 200)
```

### Data Format Requirements

**Input CSV columns**: `timestamp,length,src_ip,dst_ip,src_port,dst_port,flags,protocol,[attack]`
- timestamp: Unix epoch (seconds/milliseconds/microseconds auto-detected)
- flags: TCP flags as integer (e.g., 2=SYN, 16=ACK, 18=SYN+ACK)
- attack: Optional attack type label

**IP mapping JSON**: `{"192.168.1.1": 1, "10.0.0.2": 2, ...}`

## Folder-Based Loading (v2.0 Chunked Format)

### Generated Structure
```
output_folder/
├── manifest.json              # Dataset metadata, format version
├── packets.csv               # Minimal packets for timearcs rendering
├── flows/
│   ├── flows_index.json     # Flow metadata with chunk references
│   ├── chunk_00000.json     # Flows 0-199 with full packet data
│   ├── chunk_00001.json     # Flows 200-399
│   └── ...
├── indices/
│   └── bins.json            # Time-based bins for range queries
└── ips/
    ├── ip_stats.json        # Per-IP statistics
    ├── flag_stats.json      # TCP flag distribution
    └── unique_ips.json      # IP address list
```

### Loading Strategy
1. Load `manifest.json` (instant)
2. Load `packets.csv` progressively with worker pool
3. Load `flows_index.json` (contains chunk references)
4. Load flow chunks on-demand when user clicks flows
5. Cache chunks for reuse (200 flows cached together)

**Why chunked?** Loading flow 42 also loads flows 0-199 in same chunk, so subsequent clicks in that range are instant.

## Key Configuration Points

### Global Settings (config.js)
- `GLOBAL_BIN_COUNT = 300` - Time bins for overview chart (affects all visualizations)
- `MAX_FLOW_LIST_ITEMS = 500` - Performance limit for flow lists
- `FLOW_LIST_RENDER_BATCH = 200` - DOM update batch size
- `FLOW_RECONSTRUCT_BATCH = 5000` - Worker progress update frequency

### Lensing Feature (attack_timearcs.js)
- `isLensing` - Toggle magnification mode (line 60)
- `lensingMul` - Magnification factor, default 5x (line 62)
- `lensingRange` - Width of magnified region (line 64)
- Keyboard shortcut: Shift+L to toggle
- Implementation: `xScaleWithLensing()` wrapper function (lines 871-927)

### Worker Pool (src/ingest/worker-pool.ts)
- `tileMs = 60_000` - Time window per tile (milliseconds)
- `maxPointsPerFlush = 50_000` - Batch size for persistence
- `numWorkers` - Auto-detected from `navigator.hardwareConcurrency - 1`

## Development Workflow

### Running the Visualization
1. **No build step required** for basic usage - open HTML directly in browser
2. For TypeScript workers: Build with bundler (Vite/Webpack) if modifying src/
3. Chrome/Edge required for File System Access API (folder loading)
4. Firefox/Safari: Use legacy CSV upload mode

### Testing Data Generation
```bash
# Create small test dataset
python tcp_data_loader_chunked.py \
  --data set1_first90_minutes.csv \
  --ip-map combined_pcap_data_set5_compressed_ip_map.json \
  --output-dir test_output \
  --max-records 10000 \
  --chunk-size 100
```

### Browser DevTools Debugging
```javascript
// Enable debug logging (in browser console)
localStorage.setItem('debug', 'true');
location.reload();

// Access current data state
folderLoader.manifest         // Dataset metadata
folderLoader.packets          // Loaded packets
folderLoader.flowsIndex       // Flow summaries
folderLoader.loadedFlows      // Cached flow details (Map)
```

## Important Implementation Details

### TCP Flow State Machine
All Python loaders implement identical 3-phase flow detection:
1. **Establishment**: SYN → SYN+ACK → ACK
2. **Data Transfer**: Any packets with PSH, ACK flags
3. **Closing**: FIN → FIN+ACK → ACK, or immediate RST

Flows are identified by bidirectional 5-tuple: `(src_ip, dst_ip, src_port, dst_port, protocol)`

### Timestamp Handling
Auto-detection of timestamp format:
- If timestamp > 1e6: Treated as absolute time (minutes since epoch)
- Otherwise: Relative time (displayed as t=0, t=1, etc.)
- Supports seconds, milliseconds, microseconds - normalized to minutes

### Backward Compatibility
The folder loader auto-detects format versions:
- Check `manifest.json` → `format: "chunked"` (v2.0)
- Check flow index entries for `chunk_file` property (v2.0)
- Fallback to individual files if neither present (v1.0)

### Performance Considerations
- **Small datasets (<100k packets)**: Use CSV upload (attack_timearcs.html)
- **Medium (100k-1M packets)**: Use folder loading with default chunks
- **Large (1M+ packets)**: Increase chunk size (500-1000) or use tile-based system (src/)
- **Memory**: Each packet ~100-200 bytes in memory, flows ~500 bytes

## Common Tasks

### Adding a New Attack Type
1. Update event_type_mapping.json with new type and color
2. Regenerate data with updated mapping
3. Legend auto-updates from mapping file

### Adjusting Visualization Performance
1. Reduce `GLOBAL_BIN_COUNT` in config.js (fewer time bins)
2. Increase `FLOW_LIST_RENDER_BATCH` for larger DOM updates
3. Increase chunk size in data generation (fewer files to load)

### Customizing Lensing Magnification
1. Edit `lensingMul` in attack_timearcs.js (line 62)
2. Or use slider in UI (range: 2x to 200x)
3. Adjust `lensingRange` for wider/narrower focus area

## File Naming Conventions

- `*_loader.py` - Python data processors
- `*_loader.js` - JavaScript data loading modules
- `*_worker.js/*.ts` - Web Worker implementations
- `*_diagram.js` - D3.js visualization renderers
- `*_integration.js` - Module bridges/connectors
- `README_*.md` - Feature-specific documentation
- `set*_*.csv` - Network traffic datasets (numbered by capture session)

## Browser Compatibility

| Feature | Chrome | Edge | Firefox | Safari |
|---------|--------|------|---------|--------|
| CSV Upload | ✅ | ✅ | ✅ | ✅ |
| Folder Loading | ✅ 86+ | ✅ 86+ | ❌ | ❌ |
| Worker Pool | ✅ | ✅ | ✅ | ✅ |
| OPFS Storage | ✅ 102+ | ✅ 102+ | ⚠️ 111+ | ❌ |
| Lensing | ✅ | ✅ | ✅ | ✅ |

**Fallbacks**: IDB for OPFS, CSV for folder loading
