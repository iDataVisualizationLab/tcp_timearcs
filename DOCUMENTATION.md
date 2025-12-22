# TCP TimeArcs: Network Traffic Visualization Tool

## Executive Summary

**TCP TimeArcs** is a specialized network security visualization application that extends the TimeArcs technique—originally developed for visualizing fluctuating relationships in temporal networks—to analyze TCP/IP network traffic data with a focus on **cyber attack detection and pattern analysis**.

The tool transforms raw network packet captures into interactive arc-based visualizations, enabling security analysts to identify attack patterns, understand traffic flows between IP addresses, and analyze temporal relationships in network activity.

---

## Table of Contents

1. [What Problem Does It Solve?](#what-problem-does-it-solve)
2. [What Is TimeArcs?](#what-is-timearcs)
3. [Application Architecture](#application-architecture)
4. [How It Works](#how-it-works)
5. [Key Features](#key-features)
6. [Data Pipeline](#data-pipeline)
7. [Visualization Components](#visualization-components)
8. [Use Cases](#use-cases)
9. [Technical Stack](#technical-stack)

---

## What Problem Does It Solve?

### The Challenge: Network Security Analysis at Scale

Modern network environments generate **millions of packets per hour**. Security analysts face several critical challenges:

1. **Volume Overload**: Raw packet captures are too large to analyze manually
2. **Temporal Complexity**: Attacks unfold over time—simple snapshots miss patterns
3. **Hidden Relationships**: Connections between compromised hosts aren't immediately visible
4. **Attack Pattern Recognition**: Different attack types (DDoS, phishing, scans, malware) have distinct temporal signatures
5. **Context Loss**: Traditional logs lose the "big picture" of network-wide activity

### The Solution: Visual Temporal Analysis

TCP TimeArcs addresses these challenges by:

- **Compressing time** into a single view where patterns emerge
- **Revealing relationships** between IP addresses through visual arcs
- **Color-coding attack types** for immediate threat recognition
- **Supporting interactive exploration** from overview to specific details
- **Handling large datasets** through progressive loading and aggregation

---

## What Is TimeArcs?

### Background: The TimeArcs Visualization Technique

TimeArcs was introduced in 2016 by **Tuan Nhon Dang, Angus G. Forbes, Kwan-Liu Ma, Giuseppe Santucci, and Jarke J. van Wijk** in the paper *"TimeArcs: Visualizing Fluctuations in Dynamic Networks"* (EuroVis 2016).

### Core Concept

Traditional network visualizations show a snapshot at a single point in time. TimeArcs solves a fundamental problem: **how do you show changing relationships over time in a single view?**

The technique:
1. **Computes layouts** for multiple time points using force-directed algorithms
2. **Merges layouts** into a unified spatial arrangement where similar entities cluster together
3. **Draws curved arcs** connecting related entities, with arc properties encoding temporal information
4. **Reveals patterns** like persistent clusters, transient groupings, and temporal fluctuations

### Visual Metaphor

```
         Time →
IP 1  ───────────────────────
         ╭──╮  ╭───╮    ╭──╮
IP 2  ───╯  ╰──╯   ╰────╯  ╰─
               ╭───────╮
IP 3  ─────────╯       ╰─────
```

Each arc represents a connection event between IP addresses at a specific time. The curvature and position create visual patterns that reveal:
- **Concentrated activity** (many arcs in a region)
- **Communication patterns** (recurring connections)
- **Attack campaigns** (coordinated activity across IPs)

---

## Application Architecture

TCP TimeArcs consists of two complementary visualization systems:

### 1. Attack TimeArcs System (Arc-Based Network Overview)
- **Entry Point**: `attack_timearcs.html` + `attack_timearcs2.js`
- **Best For**: Attack pattern analysis, network-wide traffic overview
- **Focus**: Visualizing **relationships between IP addresses** using curved arcs
- **Features**: 
  - Direct CSV upload with multiple files
  - Attack type color coding with interactive legend
  - Fisheye lensing for time/space magnification
  - Brush selection for data export
  - Force-directed IP clustering by attack group

### 2. IP Bar Diagram System (Flow-Centric Analysis)
- **Entry Point**: `index.html` + `ip_bar_diagram.js`
- **Best For**: TCP flow inspection, detailed packet analysis
- **Focus**: Visualizing **individual packets and TCP flows** with circles/bars
- **Features**:
  - Folder-based loading via File System Access API
  - Web Workers for parallel data processing
  - TCP flow reconstruction with state machine
  - Ground truth event overlay
  - Dual render modes (circles vs stacked bars)
  - Progressive rendering with zoom-based binning

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Browser Interface                                  │
├─────────────────────────────────┬───────────────────────────────────────────┤
│   Attack TimeArcs View          │      IP Bar Diagram View                  │
│   (attack_timearcs2.js)         │      (ip_bar_diagram.js)                  │
│   ┌─────────────────────┐       │      ┌─────────────────────┐              │
│   │  Arc-based network  │       │      │  Packet circles/    │              │
│   │  visualization      │       │      │  stacked bars       │              │
│   │  - IP clustering    │       │      │  - TCP flow arcs    │              │
│   │  - Attack coloring  │       │      │  - Ground truth     │              │
│   │  - Fisheye lens     │       │      │  - Overview chart   │              │
│   └─────────────────────┘       │      └─────────────────────┘              │
├─────────────────────────────────┴───────────────────────────────────────────┤
│                        Shared Infrastructure                                 │
│  ┌──────────────┐  ┌─────────────┐  ┌────────────┐  ┌───────────────────┐   │
│  │ src/config/  │  │ src/data/   │  │ src/tcp/   │  │ src/rendering/    │   │
│  │ constants    │  │ binning     │  │ flags      │  │ circles, bars,    │   │
│  │              │  │ csvParser   │  │            │  │ arcPath, tooltip  │   │
│  └──────────────┘  └─────────────┘  └────────────┘  └───────────────────┘   │
│  ┌──────────────┐  ┌─────────────┐  ┌────────────┐  ┌───────────────────┐   │
│  │ src/layout/  │  │src/interact/│  │src/scales/ │  │ src/workers/      │   │
│  │ force sim    │  │ zoom, drag  │  │ distortion │  │ packetWorker      │   │
│  └──────────────┘  └─────────────┘  └────────────┘  └───────────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Data Loading Layer                                   │
│  ┌───────────────────────┐     ┌────────────────────────────────────────┐   │
│  │ CSV Stream Parser     │     │ Folder Loader (folder_loader.js)       │   │
│  │ - Memory efficient    │     │ - File System Access API               │   │
│  │ - Progress tracking   │     │ - Chunked flow loading                 │   │
│  └───────────────────────┘     │ - Manifest-based structure             │   │
│                                └────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## IP Bar Diagram System (ip_bar_diagram.js)

The IP Bar Diagram is a **flow-centric visualization** that complements the arc-based TimeArcs view. While TimeArcs shows network-wide relationships, the Bar Diagram focuses on **individual packet inspection and TCP flow analysis**.

### Key Components

#### 1. Dual Render Modes

```javascript
// Toggle between visualization styles
let renderMode = 'circles'; // or 'bars'
```

| Mode | Visual | Best For |
|------|--------|----------|
| **Circles** | Individual dots for packets/bins | Sparse data, seeing density |
| **Stacked Bars** | Horizontal bars by flag type | Dense data, flag distribution |

#### 2. Smart Binning System

The system automatically adjusts packet aggregation based on zoom level:

```javascript
// Binning adapts to zoom and data density
const binnedPackets = binPackets(visiblePackets, {
    xScale,           // Current zoom domain
    timeExtent,       // Full data range
    binCount: 300,    // Target bins (configurable)
    useBinning,       // User toggle
    width             // Viewport width
});
```

- **Zoomed out**: Packets aggregated into bins, circle size = packet count
- **Zoomed in**: Individual packets shown, no aggregation
- **Toggle**: User can disable binning for raw packet view

#### 3. TCP Flow Reconstruction

Full TCP state machine implementation matching `tcp_analysis.py`:

```javascript
// TCP States (matching Python implementation)
const TCP_STATES = {
    S_NEW: 0, S_INIT: 1, S_SYN_RCVD: 2, S_EST: 3,
    S_FIN_1: 4, S_FIN_2: 5, S_CLOSING: 6,
    S_CLOSED: 7, S_ABORTED: 8
};

// Flow detection from packets
const flowsFromCSV = await reconstructFlowsFromCSVAsync(packets);
```

**Detects**:
- 3-way handshake (SYN → SYN+ACK → ACK)
- Data transfer phase
- Graceful close (FIN exchanges)
- Abortive close (RST)
- Invalid flows (orphan SYNs, bad sequences)

#### 4. Flow Selection and Filtering

```javascript
// Select specific flows to highlight
selectedFlowIds = new Set(['flow_123', 'flow_456']);

// Filter packets to only show selected flows
filterPacketsBySelectedFlows();  // Uses Web Worker
drawSelectedFlowArcs();          // Draw arc connections
```

When flows are selected:
- Unrelated packets are dimmed/hidden
- Arc paths connect flow packets
- Overview chart highlights flow time ranges

#### 5. Web Worker Packet Filtering

For large datasets, packet visibility filtering runs in a Web Worker:

```javascript
// Worker-enabled filtering (non-blocking)
workerManager.filterByKeys(selectedFlowKeys, showAll);

// Falls back to main thread if worker unavailable
legacyFilterPacketsBySelectedFlows();
```

#### 6. Ground Truth Integration

Overlay known attack events on the visualization:

```javascript
// Load labeled events
const groundTruthData = await loadGroundTruthData();

// Draw boxes for events matching selected IPs
drawGroundTruthBoxes(selectedIPs);
```

Ground truth boxes show:
- Event type (attack category)
- Time range (start → stop)
- Source and destination IPs
- Color-coded by event type

#### 7. Overview Timeline

A minimap below the main chart showing full data extent:

```javascript
createOverviewChart(packets, { timeExtent, width });
```

Features:
- Density histogram of packets over time
- Draggable brush for navigation
- Click to jump to time region
- Syncs with main chart zoom

#### 8. Force-Directed IP Layout

IPs are positioned vertically using force simulation:

```javascript
const { nodes, links } = buildForceLayoutData(packets, selectedIPs);
forceLayout = computeForceLayoutPositions(packets, selectedIPs, onComplete);
```

- **Highly connected IPs** cluster together
- **Drag to reorder** IP rows manually
- **Smooth animation** when positions change

### Visual Elements

```
┌────────────────────────────────────────────────────────────────────┐
│ [IP Sidebar]        [Main Chart Area]                              │
│ ┌──────────┐  ┌────────────────────────────────────────────────┐   │
│ │ □ IP A   │  │ IP A ─●───●●●──────●─────●●───────────────────│   │
│ │ ☑ IP B   │  │         ╲   ╲      │     ╱                    │   │
│ │ ☑ IP C   │  │ IP B ────●───●●────●────●──────────●──────────│   │
│ │ □ IP D   │  │              ╲           ╲        ╱           │   │
│ └──────────┘  │ IP C ─────────●───────────●──────●─────────────│   │
│               │                                                │   │
│ [Flag Stats]  │      ← Time →                                  │   │
│ SYN: 234      │ [████████░░░░░░░░░░░░░░░] Overview Timeline    │   │
│ ACK: 1,203    │        ▲ Brush selection                       │   │
│ PSH+ACK: 892  └────────────────────────────────────────────────┘   │
│               │                                                    │
│ [Flow List]   │ ●  = Individual packet / binned packets            │
│ Flow 1 [zoom] │ ╲  = Arc connecting src→dst for selected flow      │
│ Flow 2 [zoom] │ ██ = Ground truth event box                        │
└────────────────────────────────────────────────────────────────────┘
```

### TCP Flag Color Coding

```javascript
const flagColors = {
    'SYN': '#e74c3c',      // Red - Connection initiation
    'SYN+ACK': '#f39c12',  // Orange - Connection response  
    'ACK': '#3498db',      // Blue - Acknowledgment
    'PSH+ACK': '#2ecc71',  // Green - Data transfer
    'FIN': '#9b59b6',      // Purple - Connection close
    'FIN+ACK': '#8e44ad',  // Dark purple - Close acknowledgment
    'RST': '#c0392b',      // Dark red - Connection reset
    'OTHER': '#95a5a6'     // Gray - Other flags
};
```

### Performance Optimizations

1. **Layer Caching**: Full-domain bins cached, only recomputed on filter change
2. **Viewport Culling**: Only visible packets rendered
3. **Debounced Updates**: Zoom/scroll events throttled
4. **Web Workers**: Heavy filtering offloaded to background thread
5. **Progressive Loading**: Large folders loaded in chunks

---

## How It Works

### Step 1: Data Ingestion

Raw network data (from packet captures or NetFlow) is processed through Python scripts that:

1. **Parse packets** extracting: timestamp, source/destination IP, ports, protocol, TCP flags, packet length
2. **Map IP addresses** to numeric IDs for efficient storage (JSON mapping file)
3. **Detect TCP flows** using state machine logic:
   - 3-way handshake detection (SYN → SYN+ACK → ACK)
   - Data transfer phase (PSH+ACK packets)
   - Connection termination (FIN/RST handling)
4. **Label attack types** from ground truth data when available

**Input CSV Schema:**
```csv
timestamp,length,src_ip,dst_ip,protocol,src_port,dst_port,flags,attack,count
20954244,66,7204,7203,6,80,52784,16,25,1
```

Where:
- `timestamp`: Minutes since epoch (or relative time)
- `length`: Packet size in bytes
- `src_ip`/`dst_ip`: Numeric IP IDs (mapped to dotted notation via JSON)
- `protocol`: 6=TCP, 17=UDP, etc.
- `flags`: TCP flag bitmask (2=SYN, 16=ACK, 18=SYN+ACK, etc.)
- `attack`: Attack type ID (mapped via event_type_mapping.json)

### Step 2: Data Aggregation

The visualization aggregates packets into **links** grouped by:
- Source IP + Destination IP pair
- Time bucket (typically per-minute)
- Attack type

This transforms millions of packets into thousands of visual elements.

### Step 3: Layout Computation

A **force-directed simulation** arranges IP addresses vertically:

```javascript
// Force simulation parameters
d3.forceSimulation(nodes)
  .force('link', d3.forceLink(links).strength(1.0))
  .force('charge', d3.forceManyBody().strength(-12))
  .force('x', d3.forceX(0).strength(0.01))
```

The algorithm:
1. **Groups IPs by attack type** (primary grouping)
2. **Finds connected components** within each group
3. **Applies forces** to separate components while keeping related IPs close
4. **Converges** to stable positions

### Step 4: Arc Rendering

Each aggregated link becomes a **curved arc**:

```
           x = time position
           │
IP A  ─────┼─────────────
           │╲
           │ ╲ arc
           │  ╲
IP B  ─────┼───╲─────────
```

Arc properties:
- **X position**: Timestamp on timeline
- **Y endpoints**: Source and destination IP positions
- **Curvature**: Connects the two IPs with a smooth curve
- **Color**: Gradient from neutral gray (source) to attack color (destination)
- **Width**: Logarithmic scale based on packet/connection count

### Step 5: Interactive Exploration

Users can:
- **Filter by attack type**: Click legend items to show/hide categories
- **Zoom with lensing**: Magnify time regions for detail (Shift+L)
- **Brush selection**: Select regions to export data (Shift+B)
- **Hover for details**: See packet counts, IPs, timing

---

## Choosing Between Views

| Aspect | Attack TimeArcs | IP Bar Diagram |
|--------|-----------------|----------------|
| **Primary View** | Curved arcs between IPs | Packets as circles/bars on timeline |
| **Best For** | Attack pattern overview | TCP flow deep-dive |
| **IP Arrangement** | Clustered by attack group | Force-directed by connectivity |
| **Data Scale** | <100K packets optimal | Handles 1M+ packets |
| **Zoom Feature** | Fisheye distortion lens | Standard timeline zoom + overview |
| **Flow Support** | Implicit (via arcs) | Explicit flow selection & highlighting |
| **Ground Truth** | N/A | Event box overlays |
| **Export** | Brush selection to CSV | Individual flow export |

**Use Attack TimeArcs when**: You need to see network-wide patterns, identify attack clusters, or analyze which IPs are targeted together.

**Use IP Bar Diagram when**: You need to inspect individual TCP flows, verify handshake sequences, or correlate packets with ground truth events.

---

## Key Features

### 1. Attack Type Visualization

The system recognizes **47+ attack categories** including:

| Category | Examples |
|----------|----------|
| **Reconnaissance** | nmap scans, port sweeps |
| **Exploitation** | IIS buffer overflows, SSL PCT attacks |
| **Phishing** | Email phishing, post-phishing C2 |
| **Malware** | Client compromise, malicious downloads |
| **Exfiltration** | TCP control channels, ICMP exfil |
| **DDoS** | Distributed denial of service |
| **Spam** | Spambot activity |

Each attack type has a distinct color for immediate visual recognition.

### 2. Fisheye Lensing

A **distortion-based zoom** that magnifies areas of interest while maintaining context:

```
Before lensing:          After lensing (center magnified):
│──────────────│         │────────────────│
│ A B C D E F G│    →    │A  B C  D  E F G│
│──────────────│         │────────────────│
                              ↑ expanded
```

- **Horizontal lensing**: Expands time regions
- **Vertical fisheye**: Spreads IP rows for clarity
- Adjustable magnification (2x to 100x)

### 3. Ground Truth Integration

The system can overlay **known attack events** from ground truth data:

```csv
Event Type,Source,Destination,Start Time (UTC),Stop Time (UTC)
scan /usr/bin/nmap,151.243.222.89,172.28.52.6,2009-11-03 13:20:00,2009-11-03 13:20:00
phishing email exploit/malware/trawler,24.252.33.237,172.28.1.5,2009-11-03 14:01:00,2009-11-03 14:01:00
```

This enables validation of detection algorithms and training of analysts.

### 4. TCP Flow State Machine

Full TCP connection state tracking:

```
State Machine:
  CLOSED → SYN_SENT → ESTABLISHED → DATA_TRANSFER → CLOSING → CLOSED
              ↓                                          ↓
           SYN+ACK                                    FIN/RST
```

Visual indicators show:
- Connection establishment (dashed lines)
- Data transfer phase
- Connection termination

### 5. Progressive Loading

For large datasets:
1. **Manifest loading**: Quick metadata scan
2. **Packets streaming**: Progressive CSV parsing with Web Workers
3. **Chunked flows**: Load 200 flows per chunk, cached for reuse
4. **On-demand detail**: Full flow data loaded only when clicked

---

## Data Pipeline

### Python Processing Scripts

| Script | Purpose | Output |
|--------|---------|--------|
| `tcp_data_loader.py` | Basic single-file processing | JSON/CSV |
| `tcp_data_loader_chunked.py` | Chunked output for large datasets | Folder structure |
| `tcp_data_loader_split.py` | Individual flow files | Folder structure |
| `attack_extract.py` | Extract attack-specific data | Filtered CSV |
| `compress_for_timearcs.py` | Compress data for visualization | Optimized CSV |

### Generated Folder Structure

```
output_folder/
├── manifest.json           # Dataset metadata
├── packets.csv             # Minimal packet data for arcs
├── flows/
│   ├── flows_index.json    # Flow metadata with chunk references
│   ├── chunk_00000.json    # Flows 0-199
│   └── chunk_00001.json    # Flows 200-399
├── indices/
│   └── bins.json           # Time-based bins for queries
├── ips/
│   ├── ip_stats.json       # Per-IP statistics
│   └── unique_ips.json     # IP address list
└── overview/
    └── density.json        # Time density data
```

---

## Visualization Components

### Main Chart (`attack_timearcs2.js`)

The primary visualization with:
- **Timeline axis** (top): Absolute or relative time
- **IP rows**: Horizontal lines for each IP address
- **Arc paths**: Curved connections between IPs
- **Legend**: Color-coded attack types

### Overview Chart (`overview_chart.js`)

A minimap showing:
- **Packet density** over time (bar chart)
- **Navigation brush** for selecting time ranges
- **Time-range indicator** for current view
- **Invalid flow highlighting** with stacked colors

### Sidebar (`sidebar.js`)

Control panel with:
- **Data Source**: CSV file upload or folder selection
- **IP Selector**: Searchable list with select all/clear
- **Flag Statistics**: Distribution of TCP flags
- **IP Statistics**: Per-IP packet counts and bytes
- **TCP Flow Options**: Toggle phases (establishment, data, closing)
- **Ground Truth**: Toggle event box overlays
- **View Mode**: Circles vs stacked bars
- **Binning Toggle**: Aggregate or show raw packets

### Flow List Modal

When flows are detected, a modal allows selection:

```
┌─────────────────────────────────────────────────┐
│ Flows (342)                        [X]          │
├─────────────────────────────────────────────────┤
│ [Search flows...]        [Select All] [Clear]   │
├─────────────────────────────────────────────────┤
│ ☑ 192.168.1.5:443 ↔ 10.0.0.2:52341             │
│   ESTABLISHED | 1,234 pkts | 45.2 KB  [Zoom]   │
│                                                 │
│ ☐ 192.168.1.5:80 ↔ 10.0.0.3:48291              │
│   CLOSED (graceful) | 89 pkts | 12.1 KB [Zoom] │
│                                                 │
│ ☐ 172.16.0.1:22 ↔ 192.168.1.10:61234           │
│   INVALID (orphan_syn) | 3 pkts | 186 B [Zoom] │
└─────────────────────────────────────────────────┘
```

- **Checkbox**: Select/deselect flow for highlighting
- **Status Badge**: Flow state (established, closed, invalid)
- **Packet Count**: Total packets in flow
- **Byte Count**: Total bytes transferred
- **Zoom Button**: Jump to flow's time range

---

## Use Cases

### 1. Security Operations Center (SOC) Analysis

**Scenario**: Investigate a suspected DDoS attack

1. Load packet capture from incident timeframe
2. Filter to "DDoS" attack type in legend
3. Identify target IPs (many arcs converging)
4. Use lensing to zoom into attack start time
5. Export selection for incident report

### 2. Threat Hunting

**Scenario**: Find lateral movement patterns

1. Load internal network traffic
2. Look for unusual IP-to-IP communication patterns
3. Filter to specific subnets
4. Identify scanning activity (many arcs from single source)
5. Trace post-compromise communication chains

### 3. Network Forensics

**Scenario**: Reconstruct attack timeline

1. Load multiple data files spanning incident period
2. Use ground truth overlay to mark known events
3. Correlate packet activity with attack phases
4. Document timeline in export

### 4. Training and Education

**Scenario**: Teach attack pattern recognition

1. Load labeled dataset with various attack types
2. Students observe visual signatures:
   - Scans: Many thin arcs from single source
   - DDoS: Thick arcs to single target
   - Phishing campaigns: Clusters of email activity
   - Exfiltration: Regular heartbeat patterns

---

## Technical Stack

### Frontend

**Core Libraries**:
- **D3.js v7**: SVG-based visualization, scales, axes, zoom
- **Vanilla JavaScript**: ES6 modules, no framework dependencies

**Key JavaScript Modules**:

| File | Purpose |
|------|---------|
| `attack_timearcs2.js` | Main TimeArcs arc visualization |
| `ip_bar_diagram.js` | Flow-centric packet visualization (2,900+ lines) |
| `folder_loader.js` | File System Access API for folder loading |
| `overview_chart.js` | Timeline minimap with brush navigation |
| `sidebar.js` | IP selection, flow list, statistics panels |
| `legends.js` | Flag colors, size scale legends |
| `config.js` | Global settings (bin count, batch sizes) |

**Modular Source (`src/`):**

| Directory | Contents |
|-----------|----------|
| `src/config/` | Constants (colors, margins, defaults) |
| `src/data/` | Binning, CSV parsing, flow reconstruction |
| `src/tcp/` | TCP flag classification, phase detection |
| `src/rendering/` | Circles, bars, arcs, tooltips |
| `src/layout/` | Force simulation for IP positioning |
| `src/interaction/` | Zoom, drag-reorder, resize handlers |
| `src/scales/` | Distortion (fisheye), scale factories |
| `src/workers/` | Web Worker management for filtering |
| `src/groundTruth/` | Ground truth data loading & filtering |

**Browser APIs**:
- **Web Workers**: Parallel packet filtering
- **File System Access API**: Folder-based loading (Chrome/Edge)
- **Canvas/SVG**: Rendering (SVG for interactivity)

### Backend (Data Processing)

**Python Scripts**:
- **Python 3.8+**: Data transformation
- **Pandas**: DataFrame operations, CSV handling
- **JSON**: Mapping files and metadata

| Script | Input | Output |
|--------|-------|--------|
| `tcp_data_loader.py` | CSV + IP map | JSON/CSV |
| `tcp_data_loader_chunked.py` | CSV + IP map | Folder structure |
| `compress_for_timearcs.py` | Full CSV | Optimized CSV |
| `attack_extract.py` | CSV + labels | Filtered attack CSV |

### Data Sources

The tool is designed to work with data from:
- **PCAP files** (via conversion to CSV)
- **NetFlow/IPFIX** records  
- **Intrusion Detection System** logs
- **Research datasets** (VAST Challenge, CAIDA, CTU-13)

The example data includes labeled network captures with ground truth attack annotations from the **VAST 2009 Challenge** - a network security research dataset containing:
- Multi-day network captures
- Labeled attack events (scans, DDoS, phishing, malware)
- Ground truth timing and IP associations

---

## Summary

TCP TimeArcs transforms the challenge of analyzing massive network traffic datasets into an approachable visual exploration task. By leveraging the TimeArcs technique's ability to compress temporal relationships into a single view, combined with attack-type color coding and interactive features like lensing and filtering, security analysts can quickly identify patterns that would be invisible in traditional log analysis.

The tool bridges the gap between raw packet data and actionable security intelligence, supporting the full workflow from initial triage to detailed forensic investigation.

---

## References

1. Dang, T.N., Pendar, N., Forbes, A.G., Ma, K.L., Santucci, G., & van Wijk, J.J. (2016). *TimeArcs: Visualizing Fluctuations in Dynamic Networks*. Computer Graphics Forum, 35(3), 61-70. (EuroVis 2016)

2. D3.js - Data-Driven Documents: https://d3js.org/

3. Web Workers API: https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API

4. File System Access API: https://developer.mozilla.org/en-US/docs/Web/API/File_System_Access_API

