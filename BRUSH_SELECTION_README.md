# Brush Selection Feature - Quick Start

## What is it?

The brush selection feature allows you to **select arcs in the TimeArcs visualization** and **export filter parameters** for processing with `tcp_data_loader_streaming.py`. This enables focused analysis of specific time periods, IPs, and attack patterns.

## Quick Start

### 1. Enable Brush Mode
- Press `Shift + B` or click "📐 Enable Brush" button

### 2. Select Arcs
- Click and drag on the visualization to select a region
- Selected arcs highlight; status bar shows selection info

### 3. Export Selection
- Click "⬇ Export Selection" button
- Copy the pre-generated command line
- Replace placeholders with your file paths
- Run the command to process the filtered data

## Example Workflow

```bash
# 1. In the browser, select arcs using brush tool
# 2. Click "Export Selection" and copy command
# 3. Run in terminal (after replacing placeholders):

python tcp_data_loader_streaming.py \
  --data /path/to/network_data.csv \
  --ip-map /path/to/ip_map.json \
  --output-dir ./tcp_data_selected_attack \
  --filter-ips "192.168.1.10,192.168.1.20,10.0.0.5" \
  --filter-time-start 1705320000000000 \
  --filter-time-end 1705320600000000 \
  --attack-context "ddos" \
  --chunk-size 200 \
  --flow-timeout-seconds 300

# 4. Output is ready for TCP flow viewer
```

## Key Features

✅ **Interactive selection**: Drag to select arcs in the visualization  
✅ **Smart filtering**: Automatically extracts IPs and time ranges  
✅ **Pre-generated commands**: Copy-paste ready for terminal  
✅ **Attack context**: Identifies primary attack type in selection  
✅ **JSON export**: Download selection parameters for automation  
✅ **Visual feedback**: Selected arcs highlighted in real-time  

## UI Controls

| Control | Action | Shortcut |
|---------|--------|----------|
| Enable Brush | Toggle brush selection mode | `Shift + B` |
| Clear | Remove current selection | - |
| Export Selection | Open export dialog | - |
| Close Dialog | Close export modal | `Escape` |

## Export Dialog Contents

The export dialog provides:

1. **Selection Summary**: Arc count, IPs, time range, primary attack
2. **Attack Distribution**: Breakdown of attack types
3. **Command Line**: Pre-generated command (copy button)
4. **Filter Parameters (JSON)**: Complete parameters (copy/download buttons)
5. **Selected IPs**: List of IP addresses involved

## What Gets Filtered?

When you run the exported command, the Python script will:

- ✅ **Include packets** where **source OR destination** matches any selected IP
- ✅ **Include packets** within the selected **time range**
- ✅ Process TCP flows involving the filtered packets
- ✅ Generate chunked output compatible with the TCP flow viewer

## Filter Parameters Explained

```bash
--filter-ips "IP1,IP2,..."          # Comma-separated IPs (source OR dest)
--filter-time-start MICROSECONDS    # Start timestamp (inclusive)
--filter-time-end MICROSECONDS      # End timestamp (inclusive)
--attack-context "TYPE"             # Attack label (for documentation)
--chunk-size 200                    # Flows per chunk file
--flow-timeout-seconds 300          # Flow timeout (5 minutes)
```

## Use Cases

### 🎯 Attack Investigation
Select arcs during an attack to generate a focused dataset for detailed flow analysis.

### 📊 Baseline Creation
Select normal traffic periods to create baseline datasets for comparison.

### 🔍 IP-Specific Analysis
Select vertically to capture all traffic involving specific hosts.

### ⏱️ Time-Window Analysis
Select horizontally to extract traffic from specific time periods.

## Tips

💡 **Start broad, then refine** - Make a large selection first, review stats, then narrow down  
💡 **Check attack distribution** - Ensure you're capturing the intended attacks  
💡 **Save the JSON** - Download selection parameters for record-keeping  
💡 **Use descriptive output dirs** - Name output folders clearly (e.g., `tcp_data_ddos_2024_01_15`)  

## Keyboard Shortcuts

- `Shift + B` - Toggle brush mode
- `Shift + L` - Toggle lensing mode (disables brush)
- `Escape` - Close export dialog

## Troubleshooting

**"No arcs selected"** → Draw a selection rectangle with brush tool enabled  
**Missing IPs in output** → Check IP mapping file contains all selected IPs  
**Empty output** → Verify file paths and filter parameters match your data  

## Full Documentation

See `BRUSH_SELECTION_GUIDE.md` for comprehensive documentation including:
- Detailed parameter explanations
- Advanced usage examples
- Batch processing workflows
- Programmatic integration
- Performance optimization tips

## Files Modified

- `attack_timearcs2.js` - Added brush selection and export functionality
- `attack_timearcs.html` - Added brush UI controls and buttons
- `tcp_data_loader_streaming.py` - Already supports filter parameters (no changes needed)

## Version

- **Feature Version**: 1.0
- **Compatible With**: tcp_data_loader_streaming.py v2.0
- **Date**: 2024-01-15

---

**Ready to use!** Load your data in `attack_timearcs.html` and start selecting arcs.

