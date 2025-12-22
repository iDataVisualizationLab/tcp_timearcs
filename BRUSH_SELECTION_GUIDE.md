# Brush Selection Feature - Usage Guide

## Overview

The brush selection feature allows you to interactively select a region of network traffic arcs in the TimeArcs visualization and export the selection parameters for processing with `tcp_data_loader_streaming.py`. This enables focused analysis of specific time periods, IP addresses, and attack patterns.

## How to Use

### 1. Enable Brush Selection

**Option A: Click the button**
- Click the "📐 Enable Brush" button in the toolbar

**Option B: Keyboard shortcut**
- Press `Shift + B` to toggle brush mode

When enabled, the button turns green and shows "✓ Brush Active"

### 2. Select Arcs

1. Click and drag on the visualization to create a selection rectangle
2. The brush will highlight all arcs that intersect with the rectangle
3. Selected arcs will appear at full opacity while others are dimmed
4. The status bar shows: `Selection: X arcs, Y IPs, time range: min-max`

**Tips:**
- Select horizontally to focus on a time window
- Select vertically to focus on specific IPs
- Select diagonally to capture both time and IP constraints
- You can adjust the selection by dragging again

### 3. Clear Selection (if needed)

- Click "✕ Clear" button to remove the current selection
- Or drag a new selection to replace it

### 4. Export Selection

Click the "⬇ Export Selection" button to open the export dialog.

## Export Dialog

The export dialog provides comprehensive information about your selection:

### Selection Summary
- **Arcs**: Total number of network connections selected
- **Unique IPs**: Number of distinct IP addresses involved
- **Time Range**: Start and end timestamps in data units
- **Duration**: Length of the selected time period
- **Primary Attack**: The most frequent attack type in the selection

### Attack Distribution
Shows the breakdown of attack types in your selection with arc counts.

### Command Line
Pre-generated command to run `tcp_data_loader_streaming.py` with appropriate filters:

```bash
python tcp_data_loader_streaming.py \
  --data <INPUT_CSV_FILES> \
  --ip-map <IP_MAP_JSON> \
  --output-dir <OUTPUT_DIR> \
  --filter-ips "1.2.3.4,5.6.7.8,..." \
  --filter-time-start 1234567890000000 \
  --filter-time-end 1234567899999999 \
  --attack-context "ddos" \
  --chunk-size 200 \
  --flow-timeout-seconds 300
```

**Actions:**
- Click "Copy to Clipboard" to copy the command
- Paste into your terminal and replace placeholders:
  - `<INPUT_CSV_FILES>`: Your source CSV file(s)
  - `<IP_MAP_JSON>`: Path to your IP mapping file
  - `<OUTPUT_DIR>`: Where to save the processed data

### Filter Parameters (JSON)
Complete filter parameters in JSON format for programmatic use or record-keeping:

```json
{
  "selection": {
    "arcs": 150,
    "ips": ["1.2.3.4", "5.6.7.8", ...],
    "ip_count": 25,
    "time_range": {
      "min": 1234567890000000,
      "max": 1234567899999999,
      "min_us": 1234567890000000,
      "max_us": 1234567899999999,
      "duration": 9999999
    },
    "primary_attack": "ddos",
    "attack_distribution": {
      "ddos": 120,
      "normal": 30
    }
  },
  "command_line": "...",
  "filter_parameters": {
    "filter_ips": "1.2.3.4,5.6.7.8,...",
    "filter_time_start": 1234567890000000,
    "filter_time_end": 1234567899999999,
    "attack_context": "ddos"
  }
}
```

**Actions:**
- Click "Copy to Clipboard" to copy the JSON
- Click "Download JSON" to save as a file

### Selected IP Addresses
List of all IP addresses involved in the selection (comma-separated).

## Processing the Selection

### Step 1: Prepare the Command

1. Copy the command from the export dialog
2. Replace the placeholders with actual file paths:

```bash
python tcp_data_loader_streaming.py \
  --data /path/to/your/network_data.csv \
  --ip-map /path/to/full_ip_map.json \
  --output-dir ./tcp_data_selected_attack \
  --filter-ips "192.168.1.10,192.168.1.20,10.0.0.5" \
  --filter-time-start 1234567890000000 \
  --filter-time-end 1234567899999999 \
  --attack-context "ddos" \
  --chunk-size 200 \
  --flow-timeout-seconds 300
```

### Step 2: Run the Script

Execute the command in your terminal. The script will:
- Read only packets matching the selected IPs (either as source OR destination)
- Filter to the selected time range
- Process TCP flows incrementally (memory-efficient)
- Generate a chunked output structure suitable for the TCP flow viewer

### Step 3: Output Structure

The script creates a directory with:
```
tcp_data_selected_attack/
├── manifest.json          # Metadata including filter parameters
├── packets.csv           # All selected packets
├── flows/
│   ├── flows_index.json  # Flow index
│   └── chunk_*.json      # Flow data chunks
├── ips/
│   ├── ip_stats.json     # IP statistics
│   ├── flag_stats.json   # TCP flag statistics
│   └── unique_ips.json   # List of IPs
└── indices/
    └── bins.json         # Time bins for queries
```

### Step 4: Load in Flow Viewer

Use the generated data in your TCP flow visualization tool by pointing it to the output directory.

## Filter Parameter Details

### --filter-ips
- **Format**: Comma-separated list of IP addresses
- **Matching**: Packets where EITHER source OR destination matches any listed IP
- **Example**: `--filter-ips "192.168.1.10,192.168.1.20,10.0.0.5"`
- **Note**: IPs are in dotted-quad format as they appear in the visualization

### --filter-time-start / --filter-time-end
- **Format**: Integer timestamps in **microseconds since epoch**
- **Matching**: Packets with timestamp >= start AND <= end
- **Example**: `--filter-time-start 1234567890000000 --filter-time-end 1234567899999999`
- **Note**: The export dialog automatically converts from the visualization's time units

### --attack-context
- **Format**: String label for the attack type
- **Purpose**: Stored in manifest.json for documentation and UI display
- **Example**: `--attack-context "ddos"`
- **Default**: Automatically set to the most frequent attack type in selection

### --chunk-size
- **Format**: Integer (default: 200)
- **Purpose**: Number of flows per output chunk file
- **Recommendation**: Keep default unless memory constraints require adjustment

### --flow-timeout-seconds
- **Format**: Integer (default: 300 = 5 minutes)
- **Purpose**: Flows without FIN/RST are completed after this many seconds of inactivity
- **Common values**:
  - `60`: 1 minute (aggressive, more flows marked as complete)
  - `300`: 5 minutes (recommended, balances completeness and memory)
  - `1800`: 30 minutes (conservative, fewer timeout completions)
  - `999999`: Effectively disable timeout (only FIN/RST complete flows)

## Use Cases

### 1. Analyze a Specific Attack Incident
Select arcs during a known attack period to:
- Generate focused dataset for detailed flow analysis
- Identify all IPs involved in the attack
- Study attack patterns and characteristics

### 2. Extract Normal Baseline Traffic
Select a period of normal traffic to:
- Create a baseline dataset for comparison
- Train anomaly detection models
- Understand typical network behavior

### 3. Focus on Specific IP Interactions
Select vertically to capture:
- All traffic involving specific hosts
- Communication patterns for key servers
- Lateral movement in security incidents

### 4. Time-Window Analysis
Select horizontally to:
- Extract traffic from specific time periods
- Compare behavior across different times of day
- Study temporal evolution of attacks

### 5. Multi-Attack Correlation
Select regions with multiple attack types to:
- Study attack combinations
- Analyze coordinated attack campaigns
- Understand attack sequencing

## Tips and Best Practices

### Selection Strategies
1. **Start broad, then refine**: Make a large selection first, review the statistics, then narrow down if needed
2. **Check the attack distribution**: Ensure you're capturing the attacks you intend to study
3. **Consider IP count**: Very large IP sets may result in extensive data processing
4. **Mind the time range**: Longer periods = more data to process

### Performance Considerations
- **Memory efficiency**: The streaming script processes large datasets efficiently, but still consider:
  - Narrower time ranges for initial exploration
  - Fewer IPs for faster processing
  - Adjust `--chunk-read-size` if memory is constrained
- **Processing time**: Proportional to the amount of data matching your filters

### Data Quality
- **Verify IP mappings**: Ensure the IP map JSON file covers all IPs in your selection
- **Check timestamp consistency**: Verify time range makes sense for your dataset
- **Review attack labels**: Confirm attack types are correctly identified in the visualization

### Workflow Integration
1. **Iterative analysis**: Use brush selection to progressively narrow focus
2. **Document selections**: Save JSON exports to track what you've analyzed
3. **Naming convention**: Use descriptive output directory names (e.g., `tcp_data_ddos_2024_01_15`)
4. **Version control**: Keep selection JSON files with your analysis results

## Keyboard Shortcuts

- `Shift + B`: Toggle brush mode on/off
- `Shift + L`: Toggle lensing mode (disable brush when active)
- `Escape`: Close export dialog

## Troubleshooting

### "No arcs selected" alert
- Make sure you've drawn a selection rectangle with the brush tool
- Verify brush mode is enabled (button should be green)

### Missing IPs in output
- Check that IP mapping file contains all IPs in selection
- Verify IP format matches between visualization and CSV

### Incorrect time range
- Ensure your source CSV uses the same timestamp format
- Check that time conversion is correct for your data's time units

### Empty output
- Verify source CSV file path is correct
- Check that filter parameters match data in your CSV
- Review filtering statistics in script output

## Related Documentation

- `tcp_data_loader_streaming.py`: Python script documentation
- `PLAN_ATTACK_IP_INTEGRATION.md`: Integration architecture
- `README_FOLDER_LOADING.md`: TCP flow viewer documentation

## Examples

### Example 1: DDoS Attack Analysis
```bash
# Selection: 250 arcs, 15 IPs, 10-minute window
python tcp_data_loader_streaming.py \
  --data full_network_capture.csv \
  --ip-map full_ip_map.json \
  --output-dir ./tcp_data_ddos_incident_2024_01_15 \
  --filter-ips "192.168.1.100,192.168.1.101,..." \
  --filter-time-start 1705320000000000 \
  --filter-time-end 1705320600000000 \
  --attack-context "ddos" \
  --chunk-size 200
```

### Example 2: Normal Traffic Baseline
```bash
# Selection: 500 arcs, 50 IPs, 1-hour window
python tcp_data_loader_streaming.py \
  --data full_network_capture.csv \
  --ip-map full_ip_map.json \
  --output-dir ./tcp_data_baseline_normal \
  --filter-ips "192.168.1.10,192.168.1.20,..." \
  --filter-time-start 1705316400000000 \
  --filter-time-end 1705320000000000 \
  --attack-context "normal" \
  --chunk-size 200
```

### Example 3: Multi-Attack Window
```bash
# Selection: 180 arcs, 25 IPs, mixed attacks
python tcp_data_loader_streaming.py \
  --data full_network_capture.csv \
  --ip-map full_ip_map.json \
  --output-dir ./tcp_data_multi_attack_analysis \
  --filter-ips "10.0.0.5,10.0.0.10,..." \
  --filter-time-start 1705323000000000 \
  --filter-time-end 1705324800000000 \
  --attack-context "mixed" \
  --chunk-size 200
```

## Advanced Usage

### Programmatic Processing
Save the JSON export and process multiple selections:

```python
import json
import subprocess

# Load selection
with open('brush_selection_1705320000.json') as f:
    selection = json.load(f)

# Extract filter parameters
params = selection['filter_parameters']

# Build command
cmd = [
    'python', 'tcp_data_loader_streaming.py',
    '--data', 'network_data.csv',
    '--ip-map', 'ip_map.json',
    '--output-dir', f'./tcp_data_{params["attack_context"]}',
    '--filter-ips', params['filter_ips'],
    '--filter-time-start', str(params['filter_time_start']),
    '--filter-time-end', str(params['filter_time_end']),
    '--attack-context', params['attack_context']
]

# Execute
subprocess.run(cmd, check=True)
```

### Batch Processing Multiple Selections
```bash
#!/bin/bash
# Process multiple saved selections

for selection_file in brush_selection_*.json; do
    # Extract parameters from JSON and process
    python process_selection.py "$selection_file"
done
```

## Support

For issues or questions:
1. Check console logs in browser developer tools
2. Verify file paths and formats
3. Review script output for filtering statistics
4. Check that CSV data matches expected format

---

**Version**: 1.0  
**Last Updated**: 2024-01-15  
**Compatible With**: tcp_data_loader_streaming.py v2.0

