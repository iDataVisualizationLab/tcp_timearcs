# TCP TimeArcs - Folder-Based Loading

## Overview

This document describes the new folder-based loading feature that enables efficient loading and visualization of large TCP network datasets by splitting data into multiple files.

## Architecture

### File Structure

The folder-based loader expects the following structure:

```
dataset_folder/
├── manifest.json           # Dataset metadata
├── packets.csv            # All packets for timearcs visualization
├── flows_index.json       # Flow summaries for quick lookup
├── ip_stats.json          # IP statistics
├── flag_stats.json        # TCP flag statistics
└── flows/                 # Individual flow files
    ├── flow_xxxxx_000001.json
    ├── flow_xxxxx_000002.json
    └── ...
```

### Components

#### 1. Data Generation (`tcp_data_loader_split.py`)

**Purpose**: Process raw TCP data and generate split file structure.

**Usage**:
```bash
python tcp_data_loader_split.py \
  --data input_data.csv \
  --ip-map ip_mapping.json \
  --output-dir output_folder \
  --max-records 100000  # optional
```

**Output Files**:

- **manifest.json**: Contains dataset metadata
  - Version, creation time, source file
  - Total packets, TCP packets, unique IPs, flows
  - Time range information
  - List of IP addresses

- **packets.csv**: Minimal packet data for visualization
  - timestamp, src_ip, dst_ip, src_port, dst_port
  - flags, flag_type, length, protocol

- **flows_index.json**: Array of flow summaries
  - Flow ID, connection key, initiator/responder
  - State, close type, time range
  - Packet/byte counts
  - Phase statistics

- **flows/[flow_id].json**: Full flow details
  - Complete flow metadata
  - All packets in the flow
  - Phase breakdown (establishment, data transfer, closing)
  - State machine information

- **ip_stats.json**: Per-IP statistics
  - Sent/received packets and bytes
  - Time range of activity

- **flag_stats.json**: TCP flag distribution

#### 2. Folder Loader (`folder_loader.js`)

**Purpose**: Handle loading of split files using File System Access API.

**Key Methods**:
```javascript
// Open folder picker
await folderLoader.openFolder()

// Load specific files
await folderLoader.loadManifest()
await folderLoader.loadPackets(onProgress)
await folderLoader.loadFlowsIndex()
await folderLoader.loadIPStats()
await folderLoader.loadFlagStats()

// Load individual flows on demand
await folderLoader.loadFlow(flowId)
await folderLoader.loadFlows([flowId1, flowId2, ...])

// Filter flows
folderLoader.filterFlowsByIPs(selectedIPs)
folderLoader.filterFlowsByTimeRange(startTime, endTime)
```

**Features**:
- Progressive loading with progress callbacks
- Caching of loaded flows
- Filtering capabilities
- Error handling

#### 3. Integration (`folder_integration.js`)

**Purpose**: Bridge folder loader with existing visualization.

**Key Features**:
- Handles data source switching (CSV vs Folder)
- Triggers visualization updates
- Manages flow list modals
- Handles time range interactions
- Shows detailed flow information

**User Interactions**:
1. User clicks on overview bar chart → Shows flows in that time range
2. User clicks on flow in list → Shows detailed flow information
3. User selects IPs → Filters flows accordingly

#### 4. UI Integration (`index.html`, `viewer_loader.js`)

**Changes**:
- Added data source selector (CSV vs Folder)
- Added "Open Folder" button
- Added folder info display
- Enhanced progress indicator
- Integrated with existing controls

## Usage Guide

### For End Users

1. **Generate Split Files**:
   ```bash
   python tcp_data_loader_split.py \
     --data tcp_data_90min_day5.csv.gz \
     --ip-map combined_pcap_data_90min_compressed_day5_ip_map.json \
     --output-dir tcp_data_90min_day5
   ```

2. **Open Web Interface**:
   - Open `index.html` in a modern browser (Chrome, Edge)
   - Select "Folder (Split Files)" as data source
   - Click "📁 Open Folder" button
   - Navigate to and select the generated folder
   - Wait for data to load

3. **Interact with Visualization**:
   - Select IPs from the sidebar
   - View timearcs and overview chart
   - Click on overview bars to see flows in that time range
   - Click on flows to see detailed information

### For Developers

**Adding New File Types**:

1. Add generator to `tcp_data_loader_split.py`:
   ```python
   def generate_new_data(records):
       # Process data
       return new_data
   
   # In process_tcp_data_split():
   new_data = generate_new_data(records)
   with open(output_path / 'new_data.json', 'w') as f:
       json.dump(new_data, f)
   ```

2. Add loader to `folder_loader.js`:
   ```javascript
   async loadNewData() {
       const file = await this.folderHandle.getFileHandle('new_data.json');
       const content = await file.getFile();
       const text = await content.text();
       this.newData = JSON.parse(text);
       return this.newData;
   }
   ```

3. Update manifest schema in both files

**Extending Interactions**:

Add to `folder_integration.js`:
```javascript
export function onNewInteraction(data) {
    // Handle new interaction
    // Load additional flow data if needed
    // Update UI
}
```

## Performance Considerations

### Memory Management

- **Packets**: Loaded once, kept in memory (~100-200 bytes per packet)
- **Flows Index**: Loaded once, small memory footprint (~200 bytes per flow)
- **Individual Flows**: Loaded on demand, cached (configurable)

### Loading Strategy

1. **Initial Load**:
   - Manifest (instant)
   - Packets (progressive with progress bar)
   - Flows index (instant)
   - Statistics (instant)

2. **On Demand**:
   - Individual flow files (loaded when user clicks)
   - Cached for subsequent access

### Scalability

- **100K packets**: Fast, smooth
- **1M packets**: Good performance with chunked loading
- **10M+ packets**: Consider further optimizations:
  - Binned packet files by time range
  - Indexed flow lookup
  - Virtual scrolling for large lists

## Browser Compatibility

**Required**: File System Access API

- ✅ Chrome 86+
- ✅ Edge 86+
- ✅ Opera 72+
- ❌ Firefox (not supported yet)
- ❌ Safari (not supported yet)

**Fallback**: Traditional CSV file upload still available

## Troubleshooting

### "Could not load manifest.json"
- Ensure you selected the correct folder
- Verify folder contains all required files
- Check file permissions

### Slow loading
- Large datasets may take time to parse
- Check browser console for progress
- Consider using smaller dataset for testing

### Flow not loading
- Check browser console for errors
- Verify flow file exists in flows/ directory
- Check file naming format

### Memory issues
- Reduce dataset size
- Clear browser cache
- Reload page to reset state

## Future Enhancements

1. **Indexed Search**: Add search index for faster flow lookup
2. **Pagination**: Implement virtual scrolling for large flow lists
3. **Compression**: Support compressed flow files
4. **Streaming**: Stream large packet files
5. **Export**: Export filtered data back to files
6. **Multiple Folders**: Compare multiple datasets
7. **Server Mode**: Optional HTTP server for large datasets

## Examples

### Example 1: Basic Usage
```bash
# Generate data
python tcp_data_loader_split.py \
  --data sample.csv \
  --ip-map ip_map.json \
  --output-dir sample_split

# Output:
# sample_split/
#   manifest.json (metadata)
#   packets.csv (10,000 packets)
#   flows_index.json (250 flows)
#   flows/ (250 flow files)
#   ip_stats.json
#   flag_stats.json
```

### Example 2: Large Dataset
```bash
# Process 1M packets
python tcp_data_loader_split.py \
  --data large_dataset.csv.gz \
  --ip-map ip_map.json \
  --output-dir large_split \
  --max-records 1000000
```

### Example 3: Programmatic Access
```javascript
import { folderLoader } from './folder_loader.js';

// Open folder
await folderLoader.openFolder();

// Load data
const packets = await folderLoader.loadPackets();
const flows = await folderLoader.loadFlowsIndex();

// Filter
const filtered = folderLoader.filterFlowsByIPs(['192.168.1.1', '192.168.1.2']);

// Load specific flow
const flow = await folderLoader.loadFlow('flow_123456_000001');
console.log(flow.packets.length);
```

## License

Same as main project.

## Support

For issues, please check:
1. Browser compatibility
2. File structure integrity
3. Console error messages
4. GitHub Issues
