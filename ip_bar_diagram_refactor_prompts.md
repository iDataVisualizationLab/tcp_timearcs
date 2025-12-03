# Incremental Refactoring Prompts for ip_bar_diagram.js

**Each stage creates a working, testable version.** The original file gradually shrinks as modules are extracted and imported.

**Key Strategy:** Maximize reuse of existing modules from the attack_timearcs refactoring.

---

## Existing Modules Available for Reuse

| Module | Functions | Reuse Status |
|--------|-----------|--------------|
| `config/constants.js` | MARGIN, DEFAULT_WIDTH, PROTOCOL_COLORS, etc. | Extend |
| `utils/helpers.js` | toNumber, sanitizeId, canonicalizeName, showTooltip, hideTooltip, setStatus | Extend |
| `data/csvParser.js` | parseCSVLine, parseCSVStream | Direct reuse |
| `data/aggregation.js` | buildRelationships, computeLinks, findConnectedComponents | Partial reuse |
| `layout/forceSimulation.js` | createForceSimulation, runUntilConverged, etc. | Reference for new |
| `mappings/decoders.js` | decodeIp, decodeAttack, lookupAttackColor | Partial reuse |
| `mappings/loaders.js` | loadIpMap, loadColorMapping, loadAllMappings | Reference |
| `rendering/arcPath.js` | linkArc, gradientIdForLink | Extend |
| `rendering/rows.js` | renderRowLines, renderIpLabels, etc. | Reference |
| `scales/scaleFactory.js` | detectTimestampUnit, createTimeScale, createWidthScale | Partial reuse |
| `legends.js` | renderInvalidLegend, renderClosingLegend, drawFlagLegend, getFlowColors | Direct reuse |

---

## Before You Start

```bash
# 1. Verify existing module structure exists
ls -la src/config src/utils src/data src/rendering src/layout

# 2. Create new directories for bar-diagram specific modules
mkdir -p src/tcp src/workers src/groundTruth src/interaction

# 3. Copy original as backup
cp ip_bar_diagram.js ip_bar_diagram.js.backup

# 4. Ensure HTML loads as ES module
# <script type="module" src="ip_bar_diagram.js"></script>
```

---

## Stage 1: Extend Constants & Add Formatters

```
## STAGE 1: Extend Constants & Add Formatters — Produces Working Version

### Goal
Extend existing constants.js with bar-diagram specific values. Create new formatters.js for formatting utilities.

### Step 1: Extend `src/config/constants.js`

Add these constants to the EXISTING file:

```javascript
// === Bar Diagram Specific Constants ===

// Debug flag
export const DEBUG = false;

// Radius scaling
export const RADIUS_MIN = 3;
export const RADIUS_MAX = 30;

// Row layout
export const ROW_GAP = 50;
export const TOP_PAD = 30;

// TCP States (matching tcp_analysis.py)
export const TCP_STATES = {
    S_NEW: 0,
    S_INIT: 1,
    S_SYN_RCVD: 2,
    S_EST: 3,
    S_FIN_1: 4,
    S_FIN_2: 5,
    S_CLOSED: 6,
    S_ABORTED: 7
};

// Handshake detection tunables
export const HANDSHAKE_TIMEOUT_MS = 3000;
export const REORDER_WINDOW_PKTS = 6;
export const REORDER_WINDOW_MS = 500;

// Default TCP flag colors
export const DEFAULT_FLAG_COLORS = {
    'SYN': '#e74c3c',
    'SYN+ACK': '#f39c12',
    'ACK': '#27ae60',
    'FIN': '#8e44ad',
    'FIN+ACK': '#9b59b6',
    'RST': '#34495e',
    'PSH+ACK': '#3498db',
    'ACK+RST': '#c0392b',
    'OTHER': '#bdc3c7'
};

// Flag curvature for arc paths (pixels of horizontal offset)
export const FLAG_CURVATURE = {
    'SYN': 12,
    'SYN+ACK': 18,
    'ACK': 24,
    'PSH+ACK': 14,
    'FIN': 18,
    'FIN+ACK': 20,
    'ACK+RST': 28,
    'RST': 30,
    'OTHER': 0
};

// Protocol number to name map
export const PROTOCOL_MAP = {
    1: 'ICMP',
    2: 'IGMP',
    6: 'TCP',
    17: 'UDP',
    41: 'IPv6',
    47: 'GRE',
    50: 'ESP',
    51: 'AH',
    58: 'ICMPv6',
    89: 'OSPF',
    132: 'SCTP'
};

// Default flow colors
export const DEFAULT_FLOW_COLORS = {
    closing: {
        graceful: '#8e44ad',
        abortive: '#c0392b'
    },
    ongoing: {
        open: '#6c757d',
        incomplete: '#adb5bd'
    },
    invalid: {}
};

// Default event colors for ground truth
export const DEFAULT_EVENT_COLORS = {
    'normal': '#4B4B4B',
    'client compromise': '#D41159',
    'malware ddos': '#2A9D4F',
    'scan /usr/bin/nmap': '#C9A200',
    'ddos': '#264D99'
};
```

### Step 2: Create `src/utils/formatters.js` (NEW FILE)

```javascript
// src/utils/formatters.js
// Formatting utilities for bar diagram

import { DEBUG } from '../config/constants.js';

/**
 * Unified debug logger.
 * @param {...any} args
 */
export function LOG(...args) {
    if (DEBUG) console.log(...args);
}

/**
 * Format bytes to human readable string.
 * @param {number} bytes
 * @returns {string}
 */
export function formatBytes(bytes) {
    if (bytes === null || bytes === undefined || isNaN(bytes) || bytes < 0) return '0 B';
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    const index = Math.min(i, sizes.length - 1);
    return parseFloat((bytes / Math.pow(k, index)).toFixed(1)) + ' ' + sizes[index];
}

/**
 * Format timestamp to UTC and seconds.
 * @param {number} timestamp - Microseconds
 * @returns {{utcTime: string, timestampSec: string}}
 */
export function formatTimestamp(timestamp) {
    const timestampInt = Math.floor(timestamp);
    const timestampSec = (timestampInt / 1000000).toFixed(6);
    const date = new Date(timestampInt / 1000);
    const utcTime = date.toISOString().replace('T', ' ').replace('Z', ' UTC');
    return { utcTime, timestampSec };
}

/**
 * Format duration from microseconds.
 * @param {number} us - Microseconds
 * @returns {string}
 */
export function formatDuration(us) {
    const s = us / 1_000_000;
    if (s < 0.001) return `${(s * 1000 * 1000).toFixed(0)} μs`;
    if (s < 1) return `${(s * 1000).toFixed(0)} ms`;
    if (s < 60) return `${s.toFixed(3)} s`;
    const m = Math.floor(s / 60);
    const rem = s - m * 60;
    return `${m}m ${rem.toFixed(3)}s`;
}

/**
 * Convert UTC datetime string to epoch microseconds.
 * @param {string} utcString - e.g., "2009-11-03 13:36:00"
 * @returns {number}
 */
export function utcToEpochMicroseconds(utcString) {
    const date = new Date(utcString + ' UTC');
    return date.getTime() * 1000;
}

/**
 * Convert epoch microseconds to UTC datetime string.
 * @param {number} epochMicroseconds
 * @returns {string}
 */
export function epochMicrosecondsToUTC(epochMicroseconds) {
    const date = new Date(epochMicroseconds / 1000);
    return date.toISOString().replace('T', ' ').replace('Z', ' UTC');
}

/**
 * Create normalized connection key for flow matching.
 * Ensures consistent key regardless of direction.
 * @param {string} src_ip
 * @param {number} src_port
 * @param {string} dst_ip
 * @param {number} dst_port
 * @returns {string}
 */
export function makeConnectionKey(src_ip, src_port, dst_ip, dst_port) {
    const sp = (src_port === undefined || src_port === null || isNaN(src_port)) ? 0 : src_port;
    const dp = (dst_port === undefined || dst_port === null || isNaN(dst_port)) ? 0 : dst_port;
    const a = `${src_ip}:${sp}-${dst_ip}:${dp}`;
    const b = `${dst_ip}:${dp}-${src_ip}:${sp}`;
    return a < b ? a : b;
}

/**
 * Clamp a value between min and max.
 * @param {number} val
 * @param {number} min
 * @param {number} max
 * @returns {number}
 */
export function clamp(val, min, max) {
    return Math.max(min, Math.min(max, val));
}

/**
 * Normalize protocol value to readable string.
 * @param {any} raw
 * @param {Object} protocolMap
 * @returns {string}
 */
export function normalizeProtocolValue(raw, protocolMap) {
    if (raw === undefined || raw === null || raw === '') return 'TCP';
    if (Array.isArray(raw)) raw = raw[0];
    if (typeof raw === 'string') {
        const upper = raw.trim().toUpperCase();
        if (/^\d+$/.test(upper)) {
            const num = parseInt(upper, 10);
            return protocolMap[num] ? `${protocolMap[num]} (${num})` : `Unknown (${num})`;
        }
        return upper || 'TCP';
    }
    if (typeof raw === 'number') {
        return protocolMap[raw] ? `${protocolMap[raw]} (${raw})` : `Unknown (${raw})`;
    }
    return 'TCP';
}
```

### Step 3: Update `ip_bar_diagram.js`

At the TOP of the file, add these imports:

```javascript
import {
    DEBUG, RADIUS_MIN, RADIUS_MAX, ROW_GAP, TOP_PAD,
    TCP_STATES, HANDSHAKE_TIMEOUT_MS, REORDER_WINDOW_PKTS, REORDER_WINDOW_MS,
    DEFAULT_FLAG_COLORS, FLAG_CURVATURE, PROTOCOL_MAP,
    DEFAULT_FLOW_COLORS, DEFAULT_EVENT_COLORS
} from './src/config/constants.js';

import {
    LOG, formatBytes, formatTimestamp, formatDuration,
    utcToEpochMicroseconds, epochMicrosecondsToUTC,
    makeConnectionKey, clamp, normalizeProtocolValue
} from './src/utils/formatters.js';
```

DELETE these from the original file:
- Line ~4: `const DEBUG = false;`
- Lines ~5-6: `function LOG(...args) { ... }`
- Lines ~92-99: `const ROW_GAP = 50; const TOP_PAD = 30;`
- Lines ~101-104: `const RADIUS_MIN = 3; const RADIUS_MAX = 30;`
- Lines ~357-366: `const defaultFlagColors = { ... }`
- Lines ~378-392: `const flagCurvature = { ... }`
- Lines ~1086-1095: `function formatBytes(bytes) { ... }`
- Lines ~1414-1420: `function formatTimestamp(timestamp) { ... }`
- Lines ~1800-1810: `function utcToEpochMicroseconds(utcString) { ... }`
- Lines ~1812-1815: `function epochMicrosecondsToUTC(epochMicroseconds) { ... }`
- Lines ~2655-2662: `function makeConnectionKey(src_ip, src_port, dst_ip, dst_port) { ... }`
- Lines ~466-476: The S_NEW, S_INIT, etc. constants
- Lines ~468-471: HANDSHAKE_TIMEOUT_MS, REORDER_WINDOW_PKTS, REORDER_WINDOW_MS

REPLACE references:
- `defaultFlagColors` → `DEFAULT_FLAG_COLORS` (then assign: `let flagColors = { ...DEFAULT_FLAG_COLORS };`)
- `flagCurvature` → `FLAG_CURVATURE`
- `S_NEW`, `S_INIT`, etc. → `TCP_STATES.S_NEW`, `TCP_STATES.S_INIT`, etc.

### Step 4: Test

1. Refresh browser
2. Upload a CSV file
3. Verify visualization renders
4. Check console for import errors
5. Verify formatting (timestamps, bytes) displays correctly

### Verification Checklist
- [ ] No console errors
- [ ] CSV loads and displays
- [ ] Timestamps format correctly in tooltips
- [ ] Byte sizes format correctly (KB, MB, etc.)
- [ ] Flag colors display correctly
```

---

## Stage 2: Extract TCP Flag Analysis

```
## STAGE 2: Extract TCP Flag Analysis — Produces Working Version

### Prerequisites
- Stage 1 complete and working

### Goal
Extract TCP flag classification and phase detection into a dedicated module.

### Step 1: Create `src/tcp/flags.js` (NEW FILE)

```javascript
// src/tcp/flags.js
// TCP flag classification and phase detection

/**
 * Classify TCP flags bitmask to readable string.
 * @param {number} flags - TCP flags bitmask
 * @returns {string} - Flag type like 'SYN', 'SYN+ACK', 'ACK', etc.
 */
export function classifyFlags(flags) {
    if (flags === undefined || flags === null) return 'OTHER';
    const flagMap = { 0x01: 'FIN', 0x02: 'SYN', 0x04: 'RST', 0x08: 'PSH', 0x10: 'ACK' };
    const setFlags = Object.entries(flagMap)
        .filter(([val, _]) => (flags & parseInt(val)) > 0)
        .map(([_, name]) => name)
        .sort();
    if (setFlags.length === 0) return 'OTHER';
    const flagStr = setFlags.join('+');
    // Normalize common combinations
    if (flagStr === 'ACK+SYN') return 'SYN+ACK';
    if (flagStr === 'ACK+FIN') return 'FIN+ACK';
    if (flagStr === 'ACK+PSH') return 'PSH+ACK';
    return flagStr;
}

/**
 * Map flag type to TCP phase.
 * @param {string} flagType
 * @returns {'establishment'|'data'|'closing'}
 */
export function flagPhase(flagType) {
    switch (flagType) {
        case 'SYN':
        case 'SYN+ACK':
        case 'ACK':
            return 'establishment';
        case 'PSH+ACK':
        case 'OTHER':
            return 'data';
        case 'FIN':
        case 'FIN+ACK':
        case 'RST':
        case 'ACK+RST':
            return 'closing';
        default:
            return 'data';
    }
}

/**
 * Check if flag is visible based on phase toggle states.
 * @param {string} flagType
 * @param {Object} phaseToggles - {showEstablishment, showDataTransfer, showClosing}
 * @returns {boolean}
 */
export function isFlagVisibleByPhase(flagType, phaseToggles) {
    const { showEstablishment = true, showDataTransfer = true, showClosing = true } = phaseToggles || {};
    const phase = flagPhase(flagType);
    if (phase === 'establishment') return !!showEstablishment;
    if (phase === 'data') return !!showDataTransfer;
    if (phase === 'closing') return !!showClosing;
    return true;
}

/**
 * Flag helper: check if packet has specific flag.
 * @param {Object} p - Packet with flags object
 * @param {string} f - Flag name
 * @returns {boolean}
 */
export const has = (p, f) => p.flags?.[f] === true;

/**
 * Check if packet is a SYN (no ACK, no RST).
 */
export const isSYN = p => has(p, 'syn') && !has(p, 'ack') && !has(p, 'rst');

/**
 * Check if packet is a SYN+ACK (no RST).
 */
export const isSYNACK = p => has(p, 'syn') && has(p, 'ack') && !has(p, 'rst');

/**
 * Check if packet is ACK only (no SYN, FIN, RST).
 */
export const isACKonly = p => has(p, 'ack') && !has(p, 'syn') && !has(p, 'fin') && !has(p, 'rst');

/**
 * Get colored flag badges HTML for stats display.
 * @param {Object} flagStats - {flagType: count}
 * @param {Object} flagColors - {flagType: color}
 * @returns {string} HTML string
 */
export function getColoredFlagBadges(flagStats, flagColors) {
    const flagsWithCounts = Object.entries(flagStats)
        .filter(([flag, count]) => count > 0)
        .sort(([, a], [, b]) => b - a);

    if (flagsWithCounts.length === 0) {
        return '<span style="color: #999; font-style: italic;">None</span>';
    }

    return flagsWithCounts.map(([flag, count]) => {
        const color = flagColors[flag] || '#bdc3c7';
        return `<span style="
            display: inline-block;
            background-color: ${color};
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: bold;
            text-shadow: 0 1px 2px rgba(0,0,0,0.3);
            min-width: 20px;
            text-align: center;
        " title="${flag}: ${count.toLocaleString()} packets">
            ${flag}: ${count.toLocaleString()}
        </span>`;
    }).join('');
}

/**
 * Get top N flags as summary string.
 * @param {Object} flagStats - {flagType: count}
 * @param {number} n - Number of top flags
 * @returns {string}
 */
export function getTopFlags(flagStats, n = 3) {
    return Object.entries(flagStats)
        .filter(([flag, count]) => count > 0)
        .sort(([, a], [, b]) => b - a)
        .slice(0, n)
        .map(([flag, count]) => `${flag}(${count})`)
        .join(', ') || 'None';
}
```

### Step 2: Update `ip_bar_diagram.js`

Add import at top:
```javascript
import {
    classifyFlags, flagPhase, isFlagVisibleByPhase,
    has, isSYN, isSYNACK, isACKonly,
    getColoredFlagBadges, getTopFlags
} from './src/tcp/flags.js';
```

DELETE these functions from original:
- `function classifyFlags(flags)` (around line ~409)
- `function flagPhase(flagType)` (around line ~420)
- `function isFlagVisibleByPhase(flagType)` (around line ~435) — note: signature changes, see update below
- `const has = (p, f) => ...` (around line ~473)
- `const isSYN = p => ...` (around line ~474)
- `const isSYNACK = p => ...` (around line ~475)
- `const isACKonly = p => ...` (around line ~476)
- `function getColoredFlags(flagStats, type)` (around line ~1100) — renamed to getColoredFlagBadges
- `function getTopFlags(flagStats)` (around line ~1120)

UPDATE usages of `isFlagVisibleByPhase`:
The old signature was `isFlagVisibleByPhase(flagType)` using global variables.
The new signature is `isFlagVisibleByPhase(flagType, { showEstablishment, showDataTransfer, showClosing })`.

Find all calls and update:
```javascript
// OLD:
isFlagVisibleByPhase(ftype)

// NEW:
isFlagVisibleByPhase(ftype, { showEstablishment, showDataTransfer, showClosing })
```

### Step 3: Test

1. Refresh browser
2. Upload CSV
3. Toggle phase checkboxes (Establishment, Data Transfer, Closing)
4. Verify packets show/hide based on phase
5. Hover over packets - verify flag classification in tooltip

### Verification Checklist
- [ ] Flag colors display correctly
- [ ] Phase toggles work (show/hide establishment, data, closing)
- [ ] Flag badges in stats panel render
- [ ] Tooltips show correct flag types
```

---

## Stage 3: Extract Data Binning

```
## STAGE 3: Extract Data Binning — Produces Working Version

### Prerequisites
- Stages 1-2 complete and working

### Goal
Extract packet binning logic for visualization performance.

### Step 1: Create `src/data/binning.js` (NEW FILE)

```javascript
// src/data/binning.js
// Packet binning and aggregation for visualization

import { classifyFlags } from '../tcp/flags.js';

/**
 * Calculate zoom level from scale and time extent.
 * @param {Function} xScale - D3 scale function
 * @param {Array} timeExtent - [min, max] time in microseconds
 * @returns {number} Zoom level (1 = full view, higher = zoomed in)
 */
export function calculateZoomLevel(xScale, timeExtent) {
    const domain = xScale.domain();
    const originalRange = timeExtent[1] - timeExtent[0];
    const currentRange = domain[1] - domain[0];
    return originalRange / currentRange;
}

/**
 * Calculate bin size based on zoom level and time range.
 * @param {number} zoomLevel
 * @param {number} timeRangeMicroseconds
 * @param {number} binCount - Target number of bins
 * @param {boolean} useBinning - Whether binning is enabled
 * @returns {number} Bin size in microseconds (0 = no binning)
 */
export function getBinSize(zoomLevel, timeRangeMicroseconds, binCount, useBinning = true) {
    if (!useBinning) return 0;
    const timeRangeSeconds = Math.max(1, timeRangeMicroseconds / 1000000);
    const binSeconds = timeRangeSeconds / binCount;
    return Math.max(1, Math.floor(binSeconds * 1000000));
}

/**
 * Get packets visible in current scale domain.
 * @param {Array} packets - All packets
 * @param {Function} xScale - D3 scale with current domain
 * @returns {Array} Visible packets
 */
export function getVisiblePackets(packets, xScale) {
    if (!packets || packets.length === 0) return [];
    const [minTime, maxTime] = xScale.domain();
    return packets.filter(d => {
        const timestamp = Math.floor(d.timestamp);
        return timestamp >= minTime && timestamp <= maxTime;
    });
}

/**
 * Bin packets for efficient visualization.
 * @param {Array} packets - Packets to bin
 * @param {Object} options - Binning options
 * @returns {Array} Binned packet data
 */
export function binPackets(packets, options) {
    const {
        xScale,
        timeExtent,
        findIPPosition,
        ipPositions,
        pairs,
        binCount = 300,
        useBinning = true,
        width = 800
    } = options;

    if (!packets || packets.length === 0) return [];

    const zoomLevel = calculateZoomLevel(xScale, timeExtent);
    const currentDomain = xScale.domain();
    const currentTimeRange = currentDomain[1] - currentDomain[0];
    const relevantTimeRange = Math.max(1, currentTimeRange);

    const binSize = getBinSize(zoomLevel, relevantTimeRange, binCount, useBinning);
    const microsPerPixel = Math.max(1, Math.floor(relevantTimeRange / Math.max(1, width)));
    const estBins = Math.max(1, Math.min(binCount, Math.floor(width)));
    const expectedPktsPerBin = packets.length / estBins;
    const disableBinning = (binSize === 0) || (binSize <= microsPerPixel) || (expectedPktsPerBin < 1.15);

    if (disableBinning) {
        return groupByPosition(packets, { findIPPosition, ipPositions, pairs });
    }

    return binByTime(packets, binSize, { findIPPosition, ipPositions, pairs });
}

/**
 * Group overlapping packets by position (no time binning).
 * @private
 */
function groupByPosition(packets, { findIPPosition, ipPositions, pairs }) {
    const positionGroups = new Map();

    packets.forEach(packet => {
        const timestamp = Math.floor(packet.timestamp);
        const yPos = findIPPosition(packet.src_ip, packet.src_ip, packet.dst_ip, pairs, ipPositions);
        const flagType = classifyFlags(packet.flags);
        const positionKey = `${timestamp}_${yPos}_${flagType}`;

        if (!positionGroups.has(positionKey)) {
            positionGroups.set(positionKey, {
                timestamp: packet.timestamp,
                src_ip: packet.src_ip,
                dst_ip: packet.dst_ip,
                flags: packet.flags,
                flagType,
                yPos,
                count: 0,
                originalPackets: [],
                binned: false,
                totalBytes: 0
            });
        }

        const group = positionGroups.get(positionKey);
        group.count++;
        group.originalPackets.push(packet);
        group.totalBytes += (packet.length || 0);
    });

    return Array.from(positionGroups.values());
}

/**
 * Bin packets by time intervals.
 * @private
 */
function binByTime(packets, binSize, { findIPPosition, ipPositions, pairs }) {
    // Analyze sparsity to adjust bin size
    const connectionCounts = new Map();
    packets.forEach(packet => {
        const key = `${packet.src_ip}-${packet.dst_ip}`;
        connectionCounts.set(key, (connectionCounts.get(key) || 0) + 1);
    });

    const totalConnections = connectionCounts.size;
    const sparseConnections = Array.from(connectionCounts.values()).filter(count => count <= 3).length;
    const sparseRatio = totalConnections > 0 ? sparseConnections / totalConnections : 0;

    let adjustedBinSize = binSize;
    if (sparseRatio > 0.7) adjustedBinSize = Math.max(binSize / 4, 100000);
    else if (sparseRatio > 0.5) adjustedBinSize = Math.max(binSize / 2, 200000);

    const bins = new Map();

    packets.forEach(packet => {
        const timestamp = Math.floor(packet.timestamp);
        const timeBin = Math.floor(timestamp / adjustedBinSize) * adjustedBinSize;
        const yPos = findIPPosition(packet.src_ip, packet.src_ip, packet.dst_ip, pairs, ipPositions);
        const flagType = classifyFlags(packet.flags);
        const binKey = `${timeBin}_${yPos}_${flagType}`;

        if (!bins.has(binKey)) {
            bins.set(binKey, {
                timestamp: packet.timestamp,
                binTimestamp: timeBin,
                binCenter: timeBin + Math.floor(adjustedBinSize / 2),
                src_ip: packet.src_ip,
                dst_ip: packet.dst_ip,
                flags: packet.flags,
                flagType,
                yPos,
                count: 0,
                originalPackets: [],
                binned: true,
                totalBytes: 0
            });
        }

        const bin = bins.get(binKey);
        bin.count++;
        bin.originalPackets.push(packet);
        bin.totalBytes += (packet.length || 0);
    });

    const binnedData = Array.from(bins.values());

    // Mark single-packet bins as unbinned
    binnedData.forEach(bin => {
        if (bin.count === 1) {
            bin.binned = false;
            bin.originalPackets = [bin.originalPackets[0]];
        }
    });

    return binnedData;
}

/**
 * Compute bar width in pixels from binned data.
 * @param {Array} binned - Binned packet data
 * @param {Function} xScale - D3 scale
 * @param {number} binCount - Target bin count
 * @returns {number} Bar width in pixels
 */
export function computeBarWidthPx(binned, xScale, binCount = 300) {
    try {
        if (!Array.isArray(binned) || binned.length === 0 || !xScale) return 4;

        const centers = Array.from(new Set(
            binned.filter(d => d.binned && Number.isFinite(d.binCenter))
                .map(d => Math.floor(d.binCenter))
        )).sort((a, b) => a - b);

        let gap = 0;
        for (let i = 1; i < centers.length; i++) {
            const d = centers[i] - centers[i - 1];
            if (d > 0) gap = (gap === 0) ? d : Math.min(gap, d);
        }

        if (gap <= 0) {
            const domain = xScale.domain();
            const microRange = Math.max(1, domain[1] - domain[0]);
            gap = Math.floor(microRange / Math.max(1, binCount));
        }

        const half = Math.max(1, Math.floor(gap / 2));
        const px = Math.max(2, xScale(centers[0] + half) - xScale(centers[0] - half));
        return Math.max(2, Math.min(24, px));
    } catch (_) {
        return 4;
    }
}

/**
 * Get effective bin count based on render mode and config.
 * @param {Object|number} globalBinCount - Config value
 * @param {string} renderMode - 'circles' or 'bars'
 * @returns {number}
 */
export function getEffectiveBinCount(globalBinCount, renderMode = 'bars') {
    if (typeof globalBinCount === 'object' && globalBinCount) {
        return globalBinCount.BAR || globalBinCount.BARS || 300;
    }
    return (typeof globalBinCount === 'number' ? globalBinCount : 300);
}
```

### Step 2: Update `ip_bar_diagram.js`

Add import:
```javascript
import {
    calculateZoomLevel, getBinSize, getVisiblePackets,
    binPackets, computeBarWidthPx, getEffectiveBinCount
} from './src/data/binning.js';
```

DELETE these functions from original:
- `function calculateZoomLevel(xScale, timeExtent)` (around line ~1340)
- `function getBinSize(zoomLevel, timeRangeMicroseconds, basePixelSize)` (around line ~1348)
- `function getVisiblePackets(packets, xScale)` (around line ~1398)
- `function binPackets(packets, xScale, yScale, timeExtent)` (around line ~1360)
- `function computeBarWidthPx(binned)` (around line ~116)
- `function getEffectiveBinCount()` (around line ~108)

UPDATE all `binPackets` calls - the signature changed:
```javascript
// OLD:
binPackets(visiblePackets, xScale, yScale, timeExtent)

// NEW:
binPackets(visiblePackets, {
    xScale,
    timeExtent,
    findIPPosition,
    ipPositions,
    pairs,
    binCount: getEffectiveBinCount(GLOBAL_BIN_COUNT, renderMode),
    useBinning,
    width
})
```

### Step 3: Test

1. Refresh browser
2. Upload CSV with many packets
3. Zoom in/out - verify binning changes
4. Toggle "Use Binning" checkbox
5. Verify circle sizes reflect bin counts

### Verification Checklist
- [ ] Binning works at full zoom
- [ ] Individual packets shown when zoomed in
- [ ] Bar widths calculate correctly
- [ ] Circle sizes scale with bin counts
```

---

## Stage 4: Extract Flow Reconstruction

```
## STAGE 4: Extract Flow Reconstruction — Produces Working Version

### Prerequisites
- Stages 1-3 complete and working

### Goal
Extract TCP flow reconstruction from CSV packets.

### Step 1: Create `src/data/flowReconstruction.js` (NEW FILE)

```javascript
// src/data/flowReconstruction.js
// TCP flow reconstruction from packet data

import { makeConnectionKey } from '../utils/formatters.js';

/**
 * Reconstruct flows from CSV packets asynchronously with progress.
 * @param {Array} packets - All packets
 * @param {Function} onProgress - Progress callback (processed, total) => void
 * @param {number} batchSize - Packets per batch
 * @returns {Promise<Array>} Reconstructed flows
 */
export async function reconstructFlowsFromCSVAsync(packets, onProgress, batchSize = 5000) {
    const flowMap = new Map();
    const total = Array.isArray(packets) ? packets.length : 0;
    let processed = 0;

    for (let start = 0; start < total; start += batchSize) {
        const end = Math.min(total, start + batchSize);

        for (let i = start; i < end; i++) {
            const packet = packets[i];
            const flowId = packet.flow_id;
            if (!flowId || flowId === '') continue;

            if (!flowMap.has(flowId)) {
                flowMap.set(flowId, {
                    id: flowId,
                    key: makeConnectionKey(packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port),
                    initiator: packet.src_ip,
                    responder: packet.dst_ip,
                    initiatorPort: parseInt(packet.src_port) || 0,
                    responderPort: parseInt(packet.dst_port) || 0,
                    state: packet.flow_state || 'unknown',
                    establishmentComplete: packet.establishment_complete === true,
                    dataTransferStarted: packet.data_transfer_started === true,
                    closingStarted: packet.closing_started === true,
                    closeType: packet.flow_close_type || null,
                    startTime: parseInt(packet.flow_start_time) || packet.timestamp,
                    endTime: parseInt(packet.flow_end_time) || packet.timestamp,
                    totalPackets: parseInt(packet.flow_total_packets) || 1,
                    totalBytes: parseInt(packet.flow_total_bytes) || 0,
                    invalidReason: packet.flow_invalid_reason || null,
                    phases: { establishment: [], dataTransfer: [], closing: [] }
                });
            } else {
                const flow = flowMap.get(flowId);
                flow.startTime = Math.min(flow.startTime, packet.timestamp);
                flow.endTime = Math.max(flow.endTime, packet.timestamp);
                if (packet.flow_total_packets) {
                    const newPackets = parseInt(packet.flow_total_packets);
                    if (!isNaN(newPackets)) flow.totalPackets = newPackets;
                }
                if (packet.flow_total_bytes) {
                    const newBytes = parseInt(packet.flow_total_bytes);
                    if (!isNaN(newBytes)) flow.totalBytes = newBytes;
                }
            }
        }

        processed = end;
        if (typeof onProgress === 'function') onProgress(processed, total);
        await new Promise(r => setTimeout(r, 0)); // Yield to event loop
    }

    return Array.from(flowMap.values());
}

/**
 * Build selected flow key set for filtering.
 * @param {Array} tcpFlows - All flows
 * @param {Set} selectedFlowIds - Set of selected flow IDs (as strings)
 * @returns {Set} Set of connection keys
 */
export function buildSelectedFlowKeySet(tcpFlows, selectedFlowIds) {
    const keys = new Set();
    if (!tcpFlows || tcpFlows.length === 0 || selectedFlowIds.size === 0) return keys;

    tcpFlows.forEach(flow => {
        if (selectedFlowIds.has(String(flow.id))) {
            const key = flow.key || makeConnectionKey(
                flow.initiator, flow.initiatorPort,
                flow.responder, flow.responderPort
            );
            if (key) keys.add(key);
        }
    });

    return keys;
}

/**
 * Verify flow-packet connection for debugging.
 * @param {Array} packets
 * @param {Array} flows
 */
export function verifyFlowPacketConnection(packets, flows) {
    console.log('=== Flow-Packet Connection Verification ===');

    const packetKeys = new Set();
    const packetKeyCount = new Map();

    packets.forEach(packet => {
        const key = makeConnectionKey(packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port);
        packetKeys.add(key);
        packetKeyCount.set(key, (packetKeyCount.get(key) || 0) + 1);
    });

    console.log(`Found ${packetKeys.size} unique packet connection keys`);

    let matchedFlows = 0;
    let unmatchedFlows = 0;

    flows.forEach(flow => {
        const flowKey = flow.key;
        if (packetKeys.has(flowKey)) {
            matchedFlows++;
        } else {
            unmatchedFlows++;
        }
    });

    console.log(`Flow verification: ${matchedFlows} matched, ${unmatchedFlows} unmatched`);
}

/**
 * Export flow packets to CSV file.
 * @param {Object} flow - Flow object
 * @param {Array} fullData - All packet data
 * @param {Object} helpers - {classifyFlags, formatTimestamp}
 */
export function exportFlowToCSV(flow, fullData, helpers) {
    const { classifyFlags, formatTimestamp } = helpers;

    try {
        const key = flow.key || makeConnectionKey(
            flow.initiator, flow.initiatorPort,
            flow.responder, flow.responderPort
        );
        const packets = (fullData || []).filter(p => {
            if (!(p.src_ip && p.dst_ip && p.src_port && p.dst_port)) return false;
            return makeConnectionKey(p.src_ip, p.src_port, p.dst_ip, p.dst_port) === key;
        });

        if (packets.length === 0) {
            alert('No packets found for this flow.');
            return;
        }

        // Deduplicate
        const dedupMap = new Map();
        packets.forEach(p => {
            const k = [
                Math.floor(p.timestamp), p.src_ip, p.src_port, p.dst_ip, p.dst_port,
                p.flags, p.seq_num ?? '', p.ack_num ?? '', p.length ?? ''
            ].join('|');
            if (!dedupMap.has(k)) dedupMap.set(k, p);
        });
        const deduped = Array.from(dedupMap.values()).sort((a, b) => a.timestamp - b.timestamp);

        // Build CSV
        const headers = [
            'timestamp', 'utc_time', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
            'flags', 'flag_type', 'seq_num', 'ack_num', 'length'
        ];
        const lines = [headers.join(',')];

        deduped.forEach(p => {
            const { utcTime } = formatTimestamp(Math.floor(p.timestamp));
            const row = [
                Math.floor(p.timestamp),
                `"${utcTime}"`,
                p.src_ip,
                p.src_port,
                p.dst_ip,
                p.dst_port,
                p.flags ?? '',
                `"${(p.flag_type || classifyFlags(p.flags) || '').toString()}"`,
                p.seq_num ?? '',
                p.ack_num ?? '',
                p.length ?? ''
            ].join(',');
            lines.push(row);
        });

        const csvContent = lines.join('\n');
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        const safeInit = (flow.initiator || 'unknown').replace(/[^\w.:-]/g, '_');
        const safeResp = (flow.responder || 'unknown').replace(/[^\w.:-]/g, '_');
        a.href = url;
        a.download = `flow_${safeInit}_${flow.initiatorPort}_to_${safeResp}_${flow.responderPort}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (err) {
        console.error('Failed to export CSV:', err);
        alert('Failed to export CSV. See console for details.');
    }
}
```

### Step 2: Update `ip_bar_diagram.js`

Add import:
```javascript
import {
    reconstructFlowsFromCSVAsync,
    buildSelectedFlowKeySet,
    verifyFlowPacketConnection,
    exportFlowToCSV
} from './src/data/flowReconstruction.js';
```

DELETE these functions:
- `async function reconstructFlowsFromCSVAsync(packets, onProgress)` (around line ~1590)
- `function reconstructFlowsFromCSV(packets)` (around line ~1560)
- `function buildSelectedFlowKeySet()` (around line ~680)
- `function verifyFlowPacketConnection(packets, flows)` (around line ~1645)
- `function exportFlowToCSV(flow)` (around line ~2665)

UPDATE `exportFlowToCSV` calls:
```javascript
// OLD:
exportFlowToCSV(flow)

// NEW:
exportFlowToCSV(flow, fullData, { classifyFlags, formatTimestamp })
```

UPDATE `buildSelectedFlowKeySet` calls:
```javascript
// OLD (using global variables):
buildSelectedFlowKeySet()

// NEW:
buildSelectedFlowKeySet(tcpFlows, selectedFlowIds)
```

### Step 3: Test

1. Refresh browser
2. Upload CSV with flow data
3. Select flows in the flow list
4. Verify flow filtering works
5. Export a flow to CSV - verify download

### Verification Checklist
- [ ] Flows reconstruct from CSV
- [ ] Flow selection filters packets
- [ ] CSV export downloads correctly
- [ ] Progress indicator shows during load
```

---

## Stage 5: Extract Rendering Functions

```
## STAGE 5: Extract Rendering Functions — Produces Working Version

### Prerequisites
- Stages 1-4 complete and working

### Goal
Extract circle and bar rendering into modules.

### Step 1: Create `src/rendering/circles.js` (NEW FILE)

```javascript
// src/rendering/circles.js
// Circle rendering for packet visualization

import { classifyFlags } from '../tcp/flags.js';

/**
 * Render circles for binned items into a layer.
 * @param {Object} layer - D3 selection (g element)
 * @param {Array} binned - Binned packet data
 * @param {Object} options - Rendering options
 */
export function renderCircles(layer, binned, options) {
    const {
        xScale,
        rScale,
        flagColors,
        RADIUS_MIN,
        mainGroup,
        arcPathGenerator,
        findIPPosition,
        pairs,
        ipPositions,
        d3
    } = options;

    if (!layer) return;

    // Clear bar segments in this layer
    try { layer.selectAll('.bin-bar-segment').remove(); } catch {}

    const tooltip = d3.select('#tooltip');

    layer.selectAll('.direction-dot')
        .data(binned, d => d.binned
            ? `bin_${d.timestamp}_${d.yPos}_${d.flagType}`
            : `${d.src_ip}-${d.dst_ip}-${d.timestamp}`)
        .join(
            enter => enter.append('circle')
                .attr('class', d => `direction-dot ${d.binned && d.count > 1 ? 'binned' : ''}`)
                .attr('r', d => d.binned && d.count > 1 ? rScale(d.count) : RADIUS_MIN)
                .attr('data-orig-r', d => d.binned && d.count > 1 ? rScale(d.count) : RADIUS_MIN)
                .attr('fill', d => flagColors[d.binned ? d.flagType : classifyFlags(d.flags)] || flagColors.OTHER)
                .attr('cx', d => xScale(Math.floor(d.binned && Number.isFinite(d.binCenter) ? d.binCenter : d.timestamp)))
                .attr('cy', d => d.binned ? d.yPos : findIPPosition(d.src_ip, d.src_ip, d.dst_ip, pairs, ipPositions))
                .style('cursor', 'pointer'),
            update => update
                .attr('class', d => `direction-dot ${d.binned && d.count > 1 ? 'binned' : ''}`)
                .attr('r', d => d.binned && d.count > 1 ? rScale(d.count) : RADIUS_MIN)
                .attr('data-orig-r', d => d.binned && d.count > 1 ? rScale(d.count) : RADIUS_MIN)
                .attr('fill', d => flagColors[d.binned ? d.flagType : classifyFlags(d.flags)] || flagColors.OTHER)
                .attr('cx', d => xScale(Math.floor(d.binned && Number.isFinite(d.binCenter) ? d.binCenter : d.timestamp)))
                .attr('cy', d => d.binned ? d.yPos : findIPPosition(d.src_ip, d.src_ip, d.dst_ip, pairs, ipPositions))
                .style('cursor', 'pointer')
        );
}
```

### Step 2: Create `src/rendering/bars.js` (NEW FILE)

```javascript
// src/rendering/bars.js
// Stacked bar rendering for packet visualization

import { classifyFlags } from '../tcp/flags.js';
import { computeBarWidthPx } from '../data/binning.js';

/**
 * Render stacked bars for binned items into a layer.
 * @param {Object} layer - D3 selection (g element)
 * @param {Array} binned - Binned packet data
 * @param {Object} options - Rendering options
 */
export function renderBars(layer, binned, options) {
    const {
        xScale,
        flagColors,
        globalMaxBinCount,
        ROW_GAP,
        formatBytes,
        formatTimestamp,
        d3
    } = options;

    if (!layer) return;

    // Clear circles in this layer
    try { layer.selectAll('.direction-dot').remove(); } catch {}

    // Build stacks per (timeBin, yPos)
    const stacks = new Map();
    const items = (binned || []).filter(d => d && d.binned);
    const globalFlagTotals = new Map();

    for (const d of items) {
        const ft = d.flagType || classifyFlags(d.flags);
        const c = Math.max(1, d.count || 1);
        globalFlagTotals.set(ft, (globalFlagTotals.get(ft) || 0) + c);
    }

    for (const d of items) {
        const t = Number.isFinite(d.binCenter) ? Math.floor(d.binCenter) :
            (Number.isFinite(d.binTimestamp) ? Math.floor(d.binTimestamp) : Math.floor(d.timestamp));
        const key = `${t}|${d.yPos}`;
        let s = stacks.get(key);
        if (!s) {
            s = { center: t, yPos: d.yPos, byFlag: new Map(), total: 0 };
            stacks.set(key, s);
        }
        const ft = d.flagType || classifyFlags(d.flags);
        const prev = s.byFlag.get(ft) || { count: 0, packets: [] };
        prev.count += Math.max(1, d.count || 1);
        if (Array.isArray(d.originalPackets)) {
            prev.packets = prev.packets.concat(d.originalPackets);
        }
        s.byFlag.set(ft, prev);
        s.total += Math.max(1, d.count || 1);
    }

    const data = Array.from(stacks.values());
    const barWidth = computeBarWidthPx(items, xScale);
    const MAX_BAR_H = Math.max(6, Math.min(ROW_GAP - 28, 16));
    const hScale = d3.scaleLinear()
        .domain([0, Math.max(1, globalMaxBinCount)])
        .range([1, MAX_BAR_H]);

    const toSegments = (s) => {
        const parts = Array.from(s.byFlag.entries()).map(([flag, info]) => ({
            flagType: flag,
            count: info.count,
            packets: info.packets
        }));
        parts.sort((a, b) => {
            const ga = globalFlagTotals.get(a.flagType) || 0;
            const gb = globalFlagTotals.get(b.flagType) || 0;
            if (gb !== ga) return gb - ga;
            return b.count - a.count;
        });
        let acc = 0;
        return parts.map(p => {
            const h = hScale(Math.max(1, p.count));
            const yTop = s.yPos - acc - h;
            acc += h;
            return {
                x: xScale(Math.floor(s.center)) - barWidth / 2,
                y: yTop,
                w: barWidth,
                h,
                datum: {
                    binned: true,
                    count: p.count,
                    flagType: p.flagType,
                    yPos: s.yPos,
                    binCenter: s.center,
                    originalPackets: p.packets || []
                }
            };
        });
    };

    // Stack groups
    const stackJoin = layer.selectAll('.bin-stack').data(data, d => `${Math.floor(d.center)}_${d.yPos}`);
    const stackEnter = stackJoin.enter().append('g').attr('class', 'bin-stack');
    const stackMerge = stackEnter.merge(stackJoin)
        .attr('data-anchor-x', d => xScale(Math.floor(d.center)))
        .attr('data-anchor-y', d => d.yPos)
        .attr('transform', null);

    // Add hover handlers for scale effect
    stackMerge
        .on('mouseenter', function(event, d) {
            const g = d3.select(this);
            const ax = +g.attr('data-anchor-x') || xScale(Math.floor(d.center));
            const ay = +g.attr('data-anchor-y') || d.yPos;
            const sx = 1.4, sy = 1.8;
            g.raise().attr('transform', `translate(${ax},${ay}) scale(${sx},${sy}) translate(${-ax},${-ay})`);
        })
        .on('mouseleave', function() {
            d3.select(this).attr('transform', null);
            d3.select('#tooltip').style('display', 'none');
        });

    // Segments within each stack
    stackMerge.each(function(s) {
        const segs = toSegments(s);
        const segJoin = d3.select(this).selectAll('.bin-bar-segment')
            .data(segs, d => `${Math.floor(d.datum.binCenter || d.datum.timestamp || 0)}_${d.datum.yPos}_${d.datum.flagType}`);

        segJoin.enter().append('rect')
            .attr('class', 'bin-bar-segment')
            .attr('x', d => d.x)
            .attr('y', d => d.y)
            .attr('width', d => d.w)
            .attr('height', d => d.h)
            .style('fill', d => flagColors[d.datum.flagType] || flagColors.OTHER)
            .style('opacity', 0.8)
            .style('stroke', 'none')
            .style('cursor', 'pointer')
            .on('mousemove', (event, d) => {
                const datum = d.datum || {};
                const center = Math.floor(datum.binCenter || datum.timestamp || 0);
                const { utcTime: cUTC } = formatTimestamp(center);
                const count = datum.count || 0;
                const ft = datum.flagType || 'OTHER';
                const bytes = formatBytes(datum.totalBytes || 0);
                const tooltipHTML = `<b>${ft}</b><br>Count: ${count}<br>Center: ${cUTC}<br>Bytes: ${bytes}`;
                d3.select('#tooltip')
                    .style('display', 'block')
                    .html(tooltipHTML)
                    .style('left', `${event.pageX + 40}px`)
                    .style('top', `${event.pageY - 40}px`);
            })
            .on('mouseleave', () => {
                d3.select('#tooltip').style('display', 'none');
            })
            .merge(segJoin)
            .attr('x', d => d.x)
            .attr('y', d => d.y)
            .attr('width', d => d.w)
            .attr('height', d => d.h)
            .style('fill', d => flagColors[d.datum.flagType] || flagColors.OTHER);

        segJoin.exit().remove();
    });

    stackJoin.exit().remove();
}

/**
 * Unified render function - dispatches to bars or circles.
 * @param {Object} layer - D3 selection
 * @param {Array} data - Binned data
 * @param {Object} options - Must include renderMode
 */
export function renderMarksForLayer(layer, data, options) {
    if (options.renderMode === 'bars') {
        return renderBars(layer, data, options);
    }
    // Import renderCircles dynamically or call it
    return options.renderCircles(layer, data, options);
}
```

### Step 3: Create `src/rendering/tooltip.js` (NEW FILE)

```javascript
// src/rendering/tooltip.js
// Tooltip HTML generation for packet visualization

import { classifyFlags } from '../tcp/flags.js';
import { formatBytes, formatTimestamp, normalizeProtocolValue } from '../utils/formatters.js';
import { PROTOCOL_MAP } from '../config/constants.js';

/**
 * Create tooltip HTML for packet or bin data.
 * @param {Object} data - Packet or binned data
 * @returns {string} HTML string for tooltip
 */
export function createTooltipHTML(data) {
    function extractProtocol(p) {
        if (!p) return 'TCP';
        const raw = p.protocol ?? p.ip_proto ?? p.ipProtocol ?? p.proto ?? p.ipProtocolNumber;
        return normalizeProtocolValue(raw, PROTOCOL_MAP);
    }

    if (data.binned && data.count > 1) {
        // Binned data tooltip
        const { utcTime } = formatTimestamp(data.timestamp);
        let tooltipContent = `<b>${data.flagType} (Binned)</b><br>`;
        tooltipContent += `Count: ${data.count} packets<br>`;
        tooltipContent += `From: ${data.src_ip}<br>To: ${data.dst_ip}<br>`;

        if (data.originalPackets && data.originalPackets.length) {
            const protocols = Array.from(new Set(data.originalPackets.map(extractProtocol)));
            tooltipContent += `Protocol: ${protocols.join(', ')}<br>`;
        } else {
            tooltipContent += `Protocol: ${extractProtocol(data)}<br>`;
        }

        tooltipContent += `Time Bin: ${utcTime}<br>`;
        tooltipContent += `Total Bytes: ${formatBytes(data.totalBytes)}`;

        // Show range of sequence numbers if available
        const seqNums = data.originalPackets
            .map(p => p.seq_num)
            .filter(s => s !== undefined && s !== null);
        if (seqNums.length > 0) {
            const minSeq = Math.min(...seqNums);
            const maxSeq = Math.max(...seqNums);
            tooltipContent += `<br>Seq Range: ${minSeq} - ${maxSeq}`;
        }

        return tooltipContent;
    } else {
        // Single packet tooltip
        const packet = data.originalPackets ? data.originalPackets[0] : data;
        const { utcTime } = formatTimestamp(packet.timestamp);
        let tooltipContent = `<b>${classifyFlags(packet.flags)}</b><br>`;
        tooltipContent += `From: ${packet.src_ip}<br>To: ${packet.dst_ip}<br>`;
        tooltipContent += `Protocol: ${extractProtocol(packet)}<br>`;
        tooltipContent += `Time: ${utcTime}`;

        if (packet.seq_num !== undefined && packet.seq_num !== null) {
            tooltipContent += `<br>Seq: ${packet.seq_num}`;
        }
        if (packet.ack_num !== undefined && packet.ack_num !== null) {
            tooltipContent += `<br>Ack: ${packet.ack_num}`;
        }

        return tooltipContent;
    }
}
```

### Step 4: Update `ip_bar_diagram.js`

Add imports:
```javascript
import { renderCircles } from './src/rendering/circles.js';
import { renderBars, renderMarksForLayer } from './src/rendering/bars.js';
import { createTooltipHTML } from './src/rendering/tooltip.js';
```

DELETE these functions:
- `function renderCircles(layer, binned, rScale)` (around line ~210)
- `function renderBars(layer, binned)` (around line ~130)
- `function renderMarksForLayer(layer, data, rScale)` (around line ~276)
- `function createTooltipHTML(data)` (around line ~1422)

UPDATE `renderCircles` calls to pass options object.
UPDATE `renderMarksForLayer` calls to pass options object including `renderCircles` function reference.

### Step 5: Test

1. Refresh browser
2. Upload CSV
3. Toggle render mode between circles and bars
4. Hover over elements - verify tooltips
5. Zoom in/out - verify rendering updates

### Verification Checklist
- [ ] Circles render correctly
- [ ] Bars render correctly
- [ ] Mode toggle works
- [ ] Tooltips display correct info
- [ ] Hover effects work on bars
```

---

## Stage 6: Extract Arc Path Generator

```
## STAGE 6: Extract Arc Path Generator — Produces Working Version

### Prerequisites
- Stages 1-5 complete and working

### Goal
Extend existing arcPath.js with bar-diagram specific arc generator.

### Step 1: Add to existing `src/rendering/arcPath.js`

Add these functions to the EXISTING file:

```javascript
// === Bar Diagram Arc Generator ===

import { FLAG_CURVATURE } from '../config/constants.js';
import { classifyFlags } from '../tcp/flags.js';

/**
 * Generate curved arc path for bar diagram visualization.
 * Uses flag-based curvature to distinguish different packet types.
 * @param {Object} d - Packet data with timestamp, src_ip, dst_ip, flags
 * @param {Object} options - {xScale, ipPositions, pairs, findIPPosition, flagCurvature}
 * @returns {string} SVG path string
 */
export function arcPathGenerator(d, options) {
    const {
        xScale,
        ipPositions,
        pairs,
        findIPPosition,
        flagCurvature = FLAG_CURVATURE
    } = options;

    if (!xScale || !ipPositions) return "";

    const timestampInt = Math.floor(d.timestamp);
    const x = xScale(timestampInt);
    const y1 = findIPPosition(d.src_ip, d.src_ip, d.dst_ip, pairs, ipPositions);
    const y2 = findIPPosition(d.dst_ip, d.src_ip, d.dst_ip, pairs, ipPositions);

    if (y1 === 0 || y2 === 0 || y1 === y2) return "";

    // Curvature by TCP flag type (pixels of horizontal offset)
    const flagType = classifyFlags(d.flags);
    const base = (flagCurvature[flagType] !== undefined) ? flagCurvature[flagType] : flagCurvature.OTHER;
    const vert = Math.abs(y2 - y1);

    // Scale curvature slightly with vertical distance so long arcs remain visible
    const scale = Math.min(1, vert / 200);
    const dx = base * (0.5 + 0.5 * scale);

    // If no curvature for this flag, draw straight line
    if (dx <= 0) {
        return `M${x},${y1} L${x},${y2}`;
    }

    // Curve everything to the right regardless of direction
    const cx1 = x + dx;
    const cy1 = y1;
    const cx2 = x + dx;
    const cy2 = y2;

    return `M${x},${y1} C${cx1},${cy1} ${cx2},${cy2} ${x},${y2}`;
}
```

### Step 2: Update `ip_bar_diagram.js`

Add import:
```javascript
import { arcPathGenerator } from './src/rendering/arcPath.js';
```

DELETE the function:
- `function arcPathGenerator(d)` (around line ~350)

UPDATE all calls to pass options:
```javascript
// OLD:
arcPathGenerator(d)

// NEW:
arcPathGenerator(d, { xScale, ipPositions, pairs, findIPPosition, flagCurvature: FLAG_CURVATURE })
```

### Step 3: Test

1. Refresh browser
2. Upload CSV
3. Select flows and view arcs
4. Verify arc curvature varies by flag type
5. Hover over arcs - verify tooltip

### Verification Checklist
- [ ] Arcs render with correct curvature
- [ ] SYN arcs curve less than RST arcs
- [ ] Straight lines for OTHER flags
- [ ] Arc tooltips work
```

---

## Stage 7: Extract Force Layout

```
## STAGE 7: Extract Force Layout — Produces Working Version

### Prerequisites
- Stages 1-6 complete and working

### Goal
Extract bar-diagram specific force layout (different from attack_timearcs).

### Step 1: Create `src/layout/barForceLayout.js` (NEW FILE)

```javascript
// src/layout/barForceLayout.js
// Force layout for IP positioning in bar diagram

import { TOP_PAD, ROW_GAP } from '../config/constants.js';

/**
 * Build force layout data from packets.
 * @param {Array} packets - Packet data
 * @param {Array} selectedIPs - Selected IP addresses
 * @param {Object} options - {width, height}
 * @returns {{nodes: Array, links: Array}}
 */
export function buildForceLayoutData(packets, selectedIPs, options = {}) {
    const { width = 800, height = 600 } = options;

    if (!packets || packets.length === 0 || !selectedIPs || selectedIPs.length === 0) {
        return { nodes: [], links: [] };
    }

    const ipSet = new Set(selectedIPs);

    // Calculate connectivity
    const ipConnectivity = new Map();
    selectedIPs.forEach(ip => ipConnectivity.set(ip, new Set()));

    packets.forEach(packet => {
        if (!packet.src_ip || !packet.dst_ip) return;
        if (packet.src_ip === packet.dst_ip) return;
        if (!ipSet.has(packet.src_ip) || !ipSet.has(packet.dst_ip)) return;

        ipConnectivity.get(packet.src_ip).add(packet.dst_ip);
        ipConnectivity.get(packet.dst_ip).add(packet.src_ip);
    });

    // Create nodes
    const nodes = selectedIPs.map((ip, idx) => ({
        id: ip,
        ip: ip,
        index: idx,
        degree: ipConnectivity.get(ip).size,
        x: width / 2,
        y: TOP_PAD + idx * ROW_GAP,
        vx: 0,
        vy: 0
    }));

    // Build links
    const linkMap = new Map();
    packets.forEach(packet => {
        if (!packet.src_ip || !packet.dst_ip) return;
        if (packet.src_ip === packet.dst_ip) return;
        if (!ipSet.has(packet.src_ip) || !ipSet.has(packet.dst_ip)) return;

        const key = packet.src_ip < packet.dst_ip
            ? `${packet.src_ip}|${packet.dst_ip}`
            : `${packet.dst_ip}|${packet.src_ip}`;

        if (!linkMap.has(key)) {
            linkMap.set(key, { count: 0, bytes: 0 });
        }
        const link = linkMap.get(key);
        link.count++;
        link.bytes += (packet.length || 0);
    });

    const links = [];
    linkMap.forEach((data, key) => {
        const [src, dst] = key.split('|');
        links.push({
            source: src,
            target: dst,
            count: data.count,
            bytes: data.bytes
        });
    });

    return { nodes, links };
}

/**
 * Compute force layout positions for IPs.
 * @param {Array} packets
 * @param {Array} selectedIPs
 * @param {Object} options - {d3, width, height, onComplete}
 * @returns {Object|null} D3 force simulation or null
 */
export function computeForceLayoutPositions(packets, selectedIPs, options) {
    const { d3, width = 800, height = 600, onComplete } = options;

    const { nodes, links } = buildForceLayoutData(packets, selectedIPs, { width, height });

    if (nodes.length === 0) {
        if (onComplete) onComplete({ ipOrder: [], ipPositions: new Map() });
        return null;
    }

    const simulation = d3.forceSimulation(nodes)
        .force('charge', d3.forceManyBody().strength(-120))
        .force('link', d3.forceLink(links)
            .id(d => d.id)
            .distance(80)
            .strength(0.5))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .alphaDecay(0.02)
        .velocityDecay(0.1)
        .alpha(0.3)
        .on('end', () => {
            const result = applyForceLayoutPositions(nodes);
            if (onComplete) onComplete(result);
        });

    return simulation;
}

/**
 * Apply computed force layout positions.
 * @param {Array} nodes - Simulation nodes with computed positions
 * @returns {{ipOrder: Array, ipPositions: Map}}
 */
export function applyForceLayoutPositions(nodes) {
    if (!nodes || nodes.length === 0) {
        return { ipOrder: [], ipPositions: new Map() };
    }

    // Sort by Y position
    const sortedNodes = nodes.slice().sort((a, b) => a.y - b.y);

    const ipOrder = sortedNodes.map(n => n.ip);
    const ipPositions = new Map();

    ipOrder.forEach((ip, idx) => {
        ipPositions.set(ip, TOP_PAD + idx * ROW_GAP);
    });

    return { ipOrder, ipPositions };
}
```

### Step 2: Update `ip_bar_diagram.js`

Add import:
```javascript
import {
    buildForceLayoutData,
    computeForceLayoutPositions,
    applyForceLayoutPositions
} from './src/layout/barForceLayout.js';
```

DELETE these functions:
- `function buildForceLayoutData(packets, selectedIPs)` (around line ~1130)
- `function computeForceLayoutPositions(packets, selectedIPs, onComplete)` (around line ~1175)
- `function applyForceLayoutPositions()` (around line ~1205)

### Step 3: Test

1. Refresh browser
2. Upload CSV
3. Select multiple IPs
4. Verify IPs are positioned by connectivity
5. Check that high-connectivity IPs cluster

### Verification Checklist
- [ ] Force layout runs without errors
- [ ] IPs reorder by connectivity
- [ ] Animation smooth during layout
- [ ] Positions persist after layout completes
```

---

## Stage 8: Extract Interaction Handlers

```
## STAGE 8: Extract Interaction Handlers — Produces Working Version

### Prerequisites
- Stages 1-7 complete and working

### Goal
Extract zoom, drag-reorder, and resize handlers.

### Step 1: Create `src/interaction/zoom.js` (NEW FILE)

```javascript
// src/interaction/zoom.js
// Zoom behavior for bar diagram

/**
 * Create D3 zoom behavior with custom filter.
 * @param {Object} options - {d3, scaleExtent, onZoom}
 * @returns {Object} D3 zoom behavior
 */
export function createZoomBehavior(options) {
    const { d3, scaleExtent = [1, 1e9], onZoom } = options;

    return d3.zoom()
        .filter((event) => {
            if (!event) return true;
            // Only zoom on wheel with modifier key
            if (event.type === 'wheel') {
                return event.ctrlKey || event.metaKey || event.shiftKey;
            }
            return true;
        })
        .scaleExtent(scaleExtent)
        .on('zoom', onZoom);
}

/**
 * Apply zoom domain to scale (programmatic zoom).
 * @param {Array} newDomain - [start, end] time domain
 * @param {Object} options - {zoom, zoomTarget, xScale, timeExtent, width, d3}
 * @param {string} source - Source of zoom ('brush', 'flow', 'reset', 'program')
 */
export function applyZoomDomain(newDomain, options, source = 'program') {
    const { zoom, zoomTarget, xScale, timeExtent, width, d3 } = options;

    if (!zoom || !zoomTarget || !xScale || !timeExtent || timeExtent.length !== 2) return;

    let [a, b] = newDomain;
    const [min, max] = timeExtent;

    // Clamp and normalize
    a = Math.max(min, Math.min(max, Math.floor(a)));
    b = Math.max(min, Math.min(max, Math.floor(b)));
    if (b <= a) b = Math.min(max, a + 1);

    const fullRange = max - min;
    const selectedRange = b - a;
    const k = fullRange / selectedRange;

    const originalScale = d3.scaleLinear().domain(timeExtent).range([0, width]);
    // Correct transform math: x = -k * S0(a)
    const tx = -k * originalScale(a);

    zoomTarget.call(zoom.transform, d3.zoomIdentity.translate(tx, 0).scale(k));
}
```

### Step 2: Create `src/interaction/dragReorder.js` (NEW FILE)

```javascript
// src/interaction/dragReorder.js
// Drag-to-reorder for IP rows

import { clamp } from '../utils/formatters.js';
import { TOP_PAD, ROW_GAP } from '../config/constants.js';

/**
 * Create drag behavior for IP row reordering.
 * @param {Object} options - {d3, svg, ipOrder, ipPositions, onReorder}
 * @returns {Object} D3 drag behavior
 */
export function createDragReorderBehavior(options) {
    const { d3, svg, ipOrder, ipPositions, onReorder } = options;

    return d3.drag()
        .on('start', function(event, ip) {
            try { d3.select(this).raise(); } catch (_) {}
            d3.select(this).style('cursor', 'grabbing');
        })
        .on('drag', function(event, ip) {
            const maxY = TOP_PAD + ROW_GAP * (ipOrder.length - 1);
            const y = clamp(event.y, TOP_PAD, maxY);
            d3.select(this).attr('transform', `translate(0,${y})`);
        })
        .on('end', function(event, ip) {
            const maxY = TOP_PAD + ROW_GAP * (ipOrder.length - 1);
            const y = clamp(event.y, TOP_PAD, maxY);
            let targetIdx = Math.round((y - TOP_PAD) / ROW_GAP);
            targetIdx = Math.max(0, Math.min(ipOrder.length - 1, targetIdx));

            const fromIdx = ipOrder.indexOf(ip);
            if (fromIdx === -1) return;

            if (fromIdx !== targetIdx) {
                // Reorder array
                ipOrder.splice(fromIdx, 1);
                ipOrder.splice(targetIdx, 0, ip);
                // Rebuild positions
                ipOrder.forEach((p, i) => ipPositions.set(p, TOP_PAD + i * ROW_GAP));
            }

            // Animate labels
            svg.selectAll('.node')
                .transition()
                .duration(150)
                .attr('transform', d => `translate(0,${ipPositions.get(d)})`)
                .on('end', function() {
                    d3.select(this).style('cursor', 'grab');
                });

            if (onReorder) onReorder();
        });
}
```

### Step 3: Create `src/interaction/resize.js` (NEW FILE)

```javascript
// src/interaction/resize.js
// Window resize handler with debouncing

/**
 * Setup window resize handler.
 * @param {Object} options - {debounceMs, onResize}
 * @returns {Function} Cleanup function
 */
export function setupWindowResizeHandler(options) {
    const { debounceMs = 150, onResize } = options;

    let resizeTimeout;

    const handleResize = () => {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(() => {
            if (onResize) onResize();
        }, debounceMs);
    };

    window.addEventListener('resize', handleResize);

    // Browser zoom detection (Ctrl+wheel)
    const wheelHandler = (event) => {
        if (event.ctrlKey || event.metaKey) {
            setTimeout(handleResize, 100);
        }
    };
    window.addEventListener('wheel', wheelHandler, { passive: true });

    // Keyboard zoom shortcuts
    const keyHandler = (event) => {
        if ((event.ctrlKey || event.metaKey) &&
            (event.key === '+' || event.key === '-' || event.key === '0')) {
            setTimeout(handleResize, 100);
        }
    };
    document.addEventListener('keydown', keyHandler);

    // Return cleanup function
    return () => {
        window.removeEventListener('resize', handleResize);
        window.removeEventListener('wheel', wheelHandler);
        document.removeEventListener('keydown', keyHandler);
        clearTimeout(resizeTimeout);
    };
}
```

### Step 4: Update `ip_bar_diagram.js`

Add imports:
```javascript
import { createZoomBehavior, applyZoomDomain } from './src/interaction/zoom.js';
import { createDragReorderBehavior } from './src/interaction/dragReorder.js';
import { setupWindowResizeHandler } from './src/interaction/resize.js';
```

DELETE/REPLACE these sections:
- The inline `zoom = d3.zoom()...` configuration (around line ~2380)
- The `applyZoomDomain` function (around line ~622)
- The `dragBehavior = d3.drag()...` configuration (around line ~2530)
- The `setupWindowResizeHandler` function (around line ~570)

UPDATE usages with new function calls.

### Step 5: Test

1. Refresh browser
2. Upload CSV
3. Zoom with Ctrl+scroll - verify zoom works
4. Drag IP labels to reorder - verify reordering
5. Resize window - verify chart resizes

### Verification Checklist
- [ ] Zoom with modifier keys works
- [ ] Programmatic zoom (Reset View) works
- [ ] Drag reorder works
- [ ] Window resize handled smoothly
```

---

## Stage 9: Extract Ground Truth

```
## STAGE 9: Extract Ground Truth — Produces Working Version

### Prerequisites
- Stages 1-8 complete and working

### Goal
Extract ground truth data loading and visualization.

### Step 1: Create `src/groundTruth/groundTruth.js` (NEW FILE)

```javascript
// src/groundTruth/groundTruth.js
// Ground truth event data handling

import { utcToEpochMicroseconds, epochMicrosecondsToUTC } from '../utils/formatters.js';

/**
 * Load ground truth data from CSV file.
 * @param {string} url - URL to CSV file
 * @returns {Promise<Array>} Ground truth events
 */
export async function loadGroundTruthData(url = 'GroundTruth_UTC_naive.csv') {
    try {
        const response = await fetch(url);
        const csvText = await response.text();
        const lines = csvText.split('\n');

        const groundTruthData = [];

        for (let i = 1; i < lines.length; i++) {
            if (lines[i].trim()) {
                const values = lines[i].split(',');
                if (values.length >= 8) {
                    groundTruthData.push({
                        eventType: values[0],
                        c2sId: values[1],
                        source: values[2],
                        sourcePorts: values[3],
                        destination: values[4],
                        destinationPorts: values[5],
                        startTime: values[6],
                        stopTime: values[7],
                        startTimeMicroseconds: utcToEpochMicroseconds(values[6]),
                        stopTimeMicroseconds: utcToEpochMicroseconds(values[7])
                    });
                }
            }
        }

        console.log(`Loaded ${groundTruthData.length} ground truth events`);
        return groundTruthData;
    } catch (error) {
        console.warn('Could not load ground truth data:', error);
        return [];
    }
}

/**
 * Filter ground truth events by selected IPs.
 * @param {Array} groundTruthData - All events
 * @param {Array} selectedIPs - Selected IP addresses
 * @returns {Array} Filtered events
 */
export function filterGroundTruthByIPs(groundTruthData, selectedIPs) {
    if (!groundTruthData || groundTruthData.length === 0 || selectedIPs.length < 2) {
        return [];
    }

    return groundTruthData.filter(event => {
        return selectedIPs.includes(event.source) && selectedIPs.includes(event.destination);
    });
}

/**
 * Prepare ground truth box data for visualization.
 * @param {Array} events - Filtered events
 * @param {Object} options - {xScale, findIPPosition, pairs, ipPositions, eventColors}
 * @returns {Array} Box data for D3
 */
export function prepareGroundTruthBoxData(events, options) {
    const { xScale, findIPPosition, pairs, ipPositions, eventColors } = options;

    const boxData = [];

    events.forEach(event => {
        const sourceY = findIPPosition(event.source, event.source, event.destination, pairs, ipPositions);
        const destY = findIPPosition(event.destination, event.source, event.destination, pairs, ipPositions);

        if (sourceY === 0 || destY === 0) return;

        // Add 59 seconds to stop time for all events
        const adjustedStopMicroseconds = event.stopTimeMicroseconds + 59 * 1_000_000;

        const startX = xScale(event.startTimeMicroseconds);
        const endX = xScale(adjustedStopMicroseconds);
        const width = Math.max(1, endX - startX);
        const boxHeight = 20;

        // Source box
        boxData.push({
            event,
            ip: event.source,
            x: startX,
            y: sourceY - boxHeight / 2,
            width,
            height: boxHeight,
            color: eventColors[event.eventType] || '#666',
            isSource: true,
            adjustedStartMicroseconds: event.startTimeMicroseconds,
            adjustedStopMicroseconds,
            wasExpanded: true
        });

        // Destination box
        boxData.push({
            event,
            ip: event.destination,
            x: startX,
            y: destY - boxHeight / 2,
            width,
            height: boxHeight,
            color: eventColors[event.eventType] || '#666',
            isSource: false,
            adjustedStartMicroseconds: event.startTimeMicroseconds,
            adjustedStopMicroseconds,
            wasExpanded: true
        });
    });

    return boxData;
}

/**
 * Update ground truth statistics display.
 * @param {Array} groundTruthData - All events
 * @param {Array} selectedIPs - Selected IPs
 * @param {Object} eventColors - Event color map
 * @returns {Object} Stats object {html, hasMatches}
 */
export function calculateGroundTruthStats(groundTruthData, selectedIPs, eventColors) {
    if (!groundTruthData || groundTruthData.length === 0) {
        return { html: 'Ground truth data not loaded', hasMatches: false };
    }

    if (selectedIPs.length < 2) {
        return {
            html: `Loaded ${groundTruthData.length} total events<br>Select 2+ IPs to view matching events`,
            hasMatches: false
        };
    }

    const matchingEvents = filterGroundTruthByIPs(groundTruthData, selectedIPs);

    if (matchingEvents.length === 0) {
        return {
            html: `No ground truth events found for selected IPs<br>Total events: ${groundTruthData.length}`,
            hasMatches: false
        };
    }

    // Group events by type
    const eventTypeCounts = {};
    matchingEvents.forEach(event => {
        eventTypeCounts[event.eventType] = (eventTypeCounts[event.eventType] || 0) + 1;
    });

    let statsHTML = `<strong>${matchingEvents.length} matching events found</strong><br>`;
    Object.entries(eventTypeCounts).forEach(([type, count]) => {
        const color = eventColors[type] || '#666';
        statsHTML += `<span style="color: ${color}; font-weight: bold;">${type}: ${count}</span><br>`;
    });

    return { html: statsHTML, hasMatches: true };
}
```

### Step 2: Update `ip_bar_diagram.js`

Add import:
```javascript
import {
    loadGroundTruthData,
    filterGroundTruthByIPs,
    prepareGroundTruthBoxData,
    calculateGroundTruthStats
} from './src/groundTruth/groundTruth.js';
```

DELETE these functions:
- `function loadGroundTruthData()` (around line ~1820)
- `function filterGroundTruthByIPs(selectedIPs)` (around line ~1880)
- `function updateGroundTruthStats(selectedIPs)` (around line ~1895)

UPDATE function calls and use return values from the new module.

### Step 3: Test

1. Refresh browser
2. Ensure GroundTruth_UTC_naive.csv exists
3. Upload packet CSV
4. Select IPs
5. Toggle "Show Ground Truth" - verify boxes appear
6. Hover over boxes - verify tooltips

### Verification Checklist
- [ ] Ground truth data loads
- [ ] Boxes render for matching events
- [ ] Boxes positioned at correct IPs
- [ ] Event type colors correct
- [ ] Tooltips show event details
```

---

## Stage 10: Extract Worker Management

```
## STAGE 10: Extract Worker Management — Produces Working Version

### Prerequisites
- Stages 1-9 complete and working

### Goal
Extract web worker management for packet filtering.

### Step 1: Create `src/workers/packetWorkerManager.js` (NEW FILE)

```javascript
// src/workers/packetWorkerManager.js
// Web worker management for packet filtering

import { LOG } from '../utils/formatters.js';

/**
 * Create packet worker manager.
 * @param {Object} options - {workerPath, onVisibilityApplied, onError}
 * @returns {Object} Worker manager API
 */
export function createPacketWorkerManager(options = {}) {
    const {
        workerPath = 'packet_worker.js',
        onVisibilityApplied,
        onError
    } = options;

    let worker = null;
    let ready = false;
    let lastVersion = 0;
    let pendingRequest = null;
    let visibilityMask = null;

    function init() {
        if (worker) return;

        try {
            worker = new Worker(workerPath);

            worker.onmessage = (e) => {
                const msg = e.data;
                switch (msg.type) {
                    case 'ready':
                        ready = true;
                        lastVersion = msg.version || 0;
                        LOG('[Worker] Ready. packets=', msg.packetCount);
                        if (pendingRequest) {
                            worker.postMessage(pendingRequest);
                            pendingRequest = null;
                        }
                        break;
                    case 'filtered':
                        if ((msg.version || 0) < lastVersion) return; // stale
                        lastVersion = msg.version || lastVersion;
                        visibilityMask = msg.visible;
                        if (onVisibilityApplied) {
                            onVisibilityApplied(visibilityMask);
                        }
                        break;
                    case 'error':
                        console.error('[Worker] error:', msg.message);
                        if (onError) onError(msg.message);
                        break;
                }
            };

            worker.onerror = (err) => {
                console.error('[Worker] onerror', err);
                if (onError) onError(err);
            };
        } catch (err) {
            console.error('Failed creating worker', err);
            if (onError) onError(err);
        }
    }

    function initPackets(packets) {
        if (!worker) init();
        ready = false;
        // Assign stable index for each packet
        packets.forEach((p, i) => p._packetIndex = i);
        worker.postMessage({ type: 'init', packets });
    }

    function filterByKeys(keys, showAllWhenEmpty = true) {
        const msg = { type: 'filterByKeys', keys, showAllWhenEmpty };
        if (!ready) {
            pendingRequest = msg;
        } else {
            try {
                worker.postMessage(msg);
            } catch (e) {
                console.error('postMessage failed', e);
            }
        }
    }

    function terminate() {
        if (worker) {
            worker.terminate();
            worker = null;
            ready = false;
        }
    }

    function isReady() {
        return ready;
    }

    function getVisibilityMask() {
        return visibilityMask;
    }

    return {
        init,
        initPackets,
        filterByKeys,
        terminate,
        isReady,
        getVisibilityMask
    };
}

/**
 * Apply visibility mask to DOM elements in batches.
 * @param {Uint8Array} mask - Visibility mask (1 = visible, 0 = hidden)
 * @param {Array} nodes - DOM nodes
 * @param {Object} options - {batchSize, onComplete}
 */
export function applyVisibilityToDots(mask, nodes, options = {}) {
    const { batchSize = 4000, onComplete } = options;

    if (!mask || !nodes || nodes.length !== mask.length) {
        console.warn('Mask length mismatch');
        return;
    }

    function batch(start) {
        const end = Math.min(nodes.length, start + batchSize);
        for (let i = start; i < end; i++) {
            nodes[i].style.display = mask[i] === 1 ? '' : 'none';
        }
        if (end < nodes.length) {
            requestAnimationFrame(() => batch(end));
        } else if (onComplete) {
            onComplete();
        }
    }

    requestAnimationFrame(() => batch(0));
}
```

### Step 2: Update `ip_bar_diagram.js`

Add import:
```javascript
import {
    createPacketWorkerManager,
    applyVisibilityToDots
} from './src/workers/packetWorkerManager.js';
```

DELETE these sections:
- Variables: `let packetWorker = null; let packetWorkerReady = false; ...` (around line ~10)
- `function initPacketWorker()` (around line ~20)
- `function applyVisibilityToDots(mask)` (around line ~55)

REPLACE worker initialization:
```javascript
// OLD:
initPacketWorker();

// NEW:
const workerManager = createPacketWorkerManager({
    onVisibilityApplied: (mask) => {
        const dots = mainGroup.selectAll('.direction-dot').nodes();
        applyVisibilityToDots(mask, dots, {
            onComplete: () => applyInvalidReasonFilter()
        });
    }
});
workerManager.initPackets(packets);
```

### Step 3: Test

1. Refresh browser
2. Upload large CSV (10K+ packets)
3. Select flows - verify filtering is fast
4. Check console for worker messages
5. Verify no UI freezing during filter

### Verification Checklist
- [ ] Worker initializes without error
- [ ] Packet filtering works
- [ ] Visibility mask applies correctly
- [ ] Performance acceptable with large datasets
```

---

## Stage 11: Final Cleanup & Integration

```
## STAGE 11: Final Cleanup & Integration — Final Stage

### Prerequisites
- Stages 1-10 complete and working

### Goal
Clean up remaining inline code, update index.js, update README.

### Step 1: Create `src/index.js` (Central Exports)

```javascript
// src/index.js
// Central re-export file for all bar diagram modules

// Config
export * from './config/constants.js';

// Utils
export * from './utils/helpers.js';
export * from './utils/formatters.js';

// TCP Analysis
export * from './tcp/flags.js';

// Data Processing
export * from './data/binning.js';
export * from './data/flowReconstruction.js';
export * from './data/csvParser.js';
export * from './data/aggregation.js';

// Rendering
export * from './rendering/arcPath.js';
export * from './rendering/bars.js';
export * from './rendering/circles.js';
export * from './rendering/tooltip.js';

// Layout
export * from './layout/barForceLayout.js';

// Workers
export * from './workers/packetWorkerManager.js';

// Ground Truth
export * from './groundTruth/groundTruth.js';

// Interaction
export * from './interaction/zoom.js';
export * from './interaction/dragReorder.js';
export * from './interaction/resize.js';

// Legends (reused from existing)
export * from './legends.js';
```

### Step 2: Update README.md

Add documentation for new modules:

```markdown
## Bar Diagram Modules (ip_bar_diagram.js)

### src/utils/formatters.js
- **Purpose**: Formatting utilities for timestamps, bytes, connection keys
- **Exports**: `LOG`, `formatBytes`, `formatTimestamp`, `formatDuration`, `utcToEpochMicroseconds`, `epochMicrosecondsToUTC`, `makeConnectionKey`, `clamp`, `normalizeProtocolValue`

### src/tcp/flags.js
- **Purpose**: TCP flag classification and phase detection
- **Exports**: `classifyFlags`, `flagPhase`, `isFlagVisibleByPhase`, `has`, `isSYN`, `isSYNACK`, `isACKonly`, `getColoredFlagBadges`, `getTopFlags`

### src/data/binning.js
- **Purpose**: Packet binning for visualization performance
- **Exports**: `calculateZoomLevel`, `getBinSize`, `getVisiblePackets`, `binPackets`, `computeBarWidthPx`, `getEffectiveBinCount`

### src/data/flowReconstruction.js
- **Purpose**: TCP flow reconstruction from packets
- **Exports**: `reconstructFlowsFromCSVAsync`, `buildSelectedFlowKeySet`, `verifyFlowPacketConnection`, `exportFlowToCSV`

### src/rendering/circles.js
- **Purpose**: Circle rendering for packets
- **Exports**: `renderCircles`

### src/rendering/bars.js
- **Purpose**: Stacked bar rendering for packets
- **Exports**: `renderBars`, `renderMarksForLayer`

### src/rendering/tooltip.js
- **Purpose**: Tooltip HTML generation
- **Exports**: `createTooltipHTML`

### src/layout/barForceLayout.js
- **Purpose**: Force-directed IP positioning
- **Exports**: `buildForceLayoutData`, `computeForceLayoutPositions`, `applyForceLayoutPositions`

### src/workers/packetWorkerManager.js
- **Purpose**: Web worker management for filtering
- **Exports**: `createPacketWorkerManager`, `applyVisibilityToDots`

### src/groundTruth/groundTruth.js
- **Purpose**: Ground truth event handling
- **Exports**: `loadGroundTruthData`, `filterGroundTruthByIPs`, `prepareGroundTruthBoxData`, `calculateGroundTruthStats`

### src/interaction/zoom.js
- **Purpose**: D3 zoom behavior
- **Exports**: `createZoomBehavior`, `applyZoomDomain`

### src/interaction/dragReorder.js
- **Purpose**: Drag-to-reorder IP rows
- **Exports**: `createDragReorderBehavior`

### src/interaction/resize.js
- **Purpose**: Window resize handling
- **Exports**: `setupWindowResizeHandler`
```

### Step 3: Final Cleanup in `ip_bar_diagram.js`

1. Remove any remaining dead code
2. Consolidate imports at top of file
3. Remove duplicate variable declarations
4. Verify all functions use imported modules

### Step 4: Final Test — Full Checklist

**Loading**
- [ ] Page loads without errors
- [ ] CSV uploads and parses
- [ ] Flows reconstruct correctly
- [ ] Ground truth loads (if available)

**Visualization**
- [ ] Circles render correctly
- [ ] Bars render correctly
- [ ] Mode toggle works
- [ ] Colors match flag types
- [ ] Arcs draw with correct curvature

**Interactions**
- [ ] Zoom works (Ctrl+scroll)
- [ ] Pan works (drag)
- [ ] Reset View works
- [ ] Drag reorder works
- [ ] Phase toggles work
- [ ] Flow selection works
- [ ] Flow zoom-to works

**Performance**
- [ ] Large CSV loads without freezing
- [ ] Zoom is smooth
- [ ] Worker filtering is fast

**Export**
- [ ] Flow CSV export works
- [ ] Downloaded file is valid

### You're Done! 🎉

Final structure:
```
src/
├── config/
│   └── constants.js          # Extended with bar diagram constants
├── utils/
│   ├── helpers.js            # Original helpers
│   └── formatters.js         # NEW: Formatting utilities
├── tcp/
│   └── flags.js              # NEW: Flag analysis
├── data/
│   ├── aggregation.js        # Original
│   ├── binning.js            # NEW: Packet binning
│   ├── csvParser.js          # Original
│   └── flowReconstruction.js # NEW: Flow reconstruction
├── rendering/
│   ├── arcPath.js            # Extended with arcPathGenerator
│   ├── bars.js               # NEW: Bar rendering
│   ├── circles.js            # NEW: Circle rendering
│   └── tooltip.js            # NEW: Tooltip HTML
├── layout/
│   ├── forceSimulation.js    # Original
│   └── barForceLayout.js     # NEW: Bar-specific force layout
├── workers/
│   └── packetWorkerManager.js # NEW: Worker management
├── groundTruth/
│   └── groundTruth.js        # NEW: Ground truth handling
├── interaction/
│   ├── zoom.js               # NEW: Zoom behavior
│   ├── dragReorder.js        # NEW: Drag reorder
│   └── resize.js             # NEW: Resize handling
├── legends.js                # Original (reused)
└── index.js                  # Central re-exports
```

**Main file reduction:** ~2800 lines → ~900-1100 lines (~60-65% reduction)
**New modules created:** 12 files, ~1200 lines
**Existing modules extended:** 2 files (constants.js, arcPath.js)
```

---

## Summary: All 11 Stages

| Stage | Module(s) | Lines | Risk | Reuses |
|-------|-----------|-------|------|--------|
| 1 | constants.js (extend), formatters.js | ~120 | Low | constants.js |
| 2 | tcp/flags.js | ~100 | Low | — |
| 3 | data/binning.js | ~180 | Medium | — |
| 4 | data/flowReconstruction.js | ~150 | Medium | — |
| 5 | rendering/circles.js, bars.js, tooltip.js | ~250 | Medium | — |
| 6 | rendering/arcPath.js (extend) | ~50 | Low | arcPath.js |
| 7 | layout/barForceLayout.js | ~120 | Medium | forceSimulation.js (reference) |
| 8 | interaction/zoom.js, dragReorder.js, resize.js | ~150 | Medium | — |
| 9 | groundTruth/groundTruth.js | ~120 | Low | — |
| 10 | workers/packetWorkerManager.js | ~100 | Medium | — |
| 11 | Cleanup & Integration | — | Low | All |

**Total new code:** ~1,340 lines across 12 new files
**Extended existing:** ~170 lines in 2 files
**Remaining main file:** ~900-1100 lines (orchestration + render flow)
