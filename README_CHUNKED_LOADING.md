# TCP TimeArcs - Chunked File Loading (v2.0)

## Overview

**UPDATED**: Instead of creating individual files for each flow (which could result in thousands of files), the new chunked loader groups flows into manageable chunk files (default: 200 flows per chunk).

## Why Chunked Files?

### Problem with Individual Files
- 10,000 flows = 10,000 files ❌
- File system overhead
- Slow directory listing
- Many small files = inefficient

### Solution: Chunked Files
- 10,000 flows = ~50 chunk files ✅ (200 flows/chunk)
- Much more efficient
- Faster loading
- Better file system performance

## File Structure (v2.0 Chunked Format)

```
dataset_folder/
├── manifest.json                    # Dataset metadata (includes format version)
├── packets.csv                      # All packets for timearcs
├── flows/
│   ├── flows_index.json            # Complete flow index with chunk references
│   ├── chunk_00000.json            # Flows 0-199 with all packets
│   ├── chunk_00001.json            # Flows 200-399 with all packets
│   ├── chunk_00002.json            # Flows 400-599 with all packets
│   └── ...
├── indices/
│   └── bins.json                   # Time-based bins for range queries
├── ips/
│   ├── ip_stats.json              # IP statistics
│   ├── flag_stats.json            # Flag statistics
│   └── unique_ips.json            # List of IPs
└── overview/
    └── (future: density data)
```

## Data Generation

### Using the Chunked Loader

```bash
python tcp_data_loader_chunked.py \
  --data input_data.csv \
  --ip-map ip_mapping.json \
  --output-dir output_folder
```

### Options

```bash
# Default (200 flows per chunk)
python tcp_data_loader_chunked.py --data data.csv --ip-map ip_map.json --output-dir out/

# Larger chunks (500 flows per chunk) - for smaller flows
python tcp_data_loader_chunked.py --data data.csv --ip-map ip_map.json --output-dir out/ --chunk-size 500

# Smaller chunks (100 flows per chunk) - for large flows with many packets
python tcp_data_loader_chunked.py --data data.csv --ip-map ip_map.json --output-dir out/ --chunk-size 100

# Limit records
python tcp_data_loader_chunked.py --data data.csv --ip-map ip_map.json --output-dir out/ --max-records 100000
```

## File Formats

### manifest.json
```json
{
  "version": "2.0",
  "format": "chunked",
  "total_flows": 10000,
  "flows_per_chunk": 200,
  "total_chunks": 50,
  "structure": {
    "flows_index": "flows/flows_index.json",
    "flow_chunks": "flows/chunk_*.json"
  }
}
```

### flows/flows_index.json
```json
[
  {
    "id": "flow_000001",
    "key": "192.168.1.1:12345<->192.168.1.2:80",
    "initiator": "192.168.1.1",
    "responder": "192.168.1.2",
    "state": "closed",
    "startTime": 1000000,
    "endTime": 1050000,
    "totalPackets": 25,
    "totalBytes": 5120,
    "chunk_file": "chunk_00000.json",  // ← Reference to chunk file
    "chunk_index": 0                    // ← Index within chunk
  },
  ...
]
```

### flows/chunk_00000.json
```json
[
  {
    "id": "flow_000001",
    "key": "192.168.1.1:12345<->192.168.1.2:80",
    "initiator": "192.168.1.1",
    "responder": "192.168.1.2",
    "state": "closed",
    "packets": [
      { "timestamp": 1000000, "src_ip": "192.168.1.1", "flags": 2, ... },
      { "timestamp": 1000100, "src_ip": "192.168.1.2", "flags": 18, ... },
      ...
    ],
    "phases": {
      "establishment": [...],
      "dataTransfer": [...],
      "closing": [...]
    }
  },
  // ... 199 more flows
]
```

## How It Works

### Loading Flow Details

1. User clicks on flow in UI
2. System looks up flow in `flows_index.json` → gets `chunk_file` and `chunk_index`
3. Load chunk file (if not cached): `flows/chunk_00042.json`
4. Extract flow at `chunk_index`: `chunk[15]`
5. Cache entire chunk for future requests
6. Display flow details

### Caching Strategy

- **Flow Index**: Loaded once, kept in memory (~100 bytes per flow)
- **Chunks**: Loaded on demand, cached
- **Cache Key**: `chunk:chunk_00042.json`
- **Benefits**: Loading one flow = loading 200 flows (reusable)

## Performance Comparison

### 10,000 Flows Example

| Metric | Individual Files (v1.0) | Chunked Files (v2.0) |
|--------|------------------------|---------------------|
| Number of files | 10,000 | 50 chunks |
| Directory listing | Slow | Fast |
| First flow load | 1 file | 1 chunk (200 flows) |
| Second flow (same chunk) | 1 file | Cached! |
| File system overhead | High | Low |
| **Overall** | ❌ Poor | ✅ Excellent |

### Memory Usage

- **Flow Index**: ~1 MB for 10k flows
- **One Chunk**: ~100-500 KB (depends on packets per flow)
- **Total Cache**: Grows as user explores, typically <50 MB

## Browser Compatibility

Same as before:
- ✅ Chrome 86+ (File System Access API)
- ✅ Edge 86+
- ✅ Opera 72+
- ❌ Firefox (use CSV fallback)
- ❌ Safari (use CSV fallback)

## Backward Compatibility

The folder loader (`folder_loader.js`) supports **both formats**:

- **v2.0 Chunked**: `flows/chunk_*.json` + `flows/flows_index.json`
- **v1.0 Individual**: `flows/*.json` + `flows_index.json` (root)

Detection is automatic based on:
1. `manifest.json` → `format: "chunked"` (v2.0)
2. Flow index entry → has `chunk_file` property (v2.0)
3. Otherwise → individual files (v1.0)

## Migration Guide

### From v1.0 (Individual) to v2.0 (Chunked)

Simply regenerate your data with the new loader:

```bash
# Old (v1.0 - creates 10,000 files)
python tcp_data_loader_split.py --data data.csv --ip-map ip_map.json --output-dir old/

# New (v2.0 - creates ~50 files)
python tcp_data_loader_chunked.py --data data.csv --ip-map ip_map.json --output-dir new/
```

The web interface automatically detects the format!

## Choosing Chunk Size

### Default: 200 flows/chunk
Good for most datasets

### Smaller (50-100 flows/chunk)
Use when:
- Flows have many packets (1000+ each)
- Limited memory
- Want fine-grained loading

### Larger (500-1000 flows/chunk)
Use when:
- Flows have few packets (<50 each)
- Lots of memory available
- Want fewer files

### Example
```bash
# Small flows, many flows
--chunk-size 500

# Large flows, fewer flows  
--chunk-size 100
```

## File Size Estimates

### 10,000 Flows, 50 packets/flow (typical)

| Component | Size |
|-----------|------|
| packets.csv | ~20 MB |
| flows_index.json | ~1 MB |
| chunk_*.json (50 files) | ~15 MB total |
| **Total** | **~36 MB** |

### 100,000 Flows, 50 packets/flow

| Component | Size |
|-----------|------|
| packets.csv | ~200 MB |
| flows_index.json | ~10 MB |
| chunk_*.json (500 files) | ~150 MB total |
| **Total** | **~360 MB** |

## Troubleshooting

### "Could not load chunk file"
- Check that `flows/` directory exists
- Verify chunk files are named correctly: `chunk_00000.json`
- Check browser console for specific error

### Slow loading
- Try larger chunk size (fewer files)
- Check if chunks are very large (>5MB each)
- Clear browser cache

### Out of memory
- Use smaller chunk size
- Clear cached chunks
- Reload page

## Examples

### Generate Test Data
```bash
# Small dataset
python tcp_data_loader_chunked.py \
  --data sample.csv \
  --ip-map ip_map.json \
  --output-dir test_chunked \
  --max-records 10000

# Output:
# - 10,000 packets
# - ~500 flows
# - 3 chunk files (200 flows each)
# - Total: ~7 files instead of 500!
```

### Large Dataset
```bash
python tcp_data_loader_chunked.py \
  --data large_data.csv.gz \
  --ip-map ip_map.json \
  --output-dir large_chunked

# Output:
# - 1,000,000 packets
# - ~50,000 flows
# - 250 chunk files (200 flows each)
# - Total: ~255 files instead of 50,000!
```

## Summary

✅ **Much better solution!**
- Far fewer files (50 vs 10,000)
- Better file system performance
- Efficient caching
- Backward compatible
- Same user experience

Use `tcp_data_loader_chunked.py` for new datasets!
