# Modularization Plan: attack_timearcs.js

## Executive Summary

This document outlines a comprehensive plan to refactor the monolithic `attack_timearcs.js` file (3,425 lines) into smaller, focused, single-responsibility modules. The goal is to improve maintainability, testability, and developer experience while preserving 100% functional parity.

---

## 1. Current Architecture Analysis

### 1.1 File Overview

| Metric | Value |
|--------|-------|
| Total Lines | 3,425 |
| Functions | ~45 |
| Global State Variables | ~35 |
| External Dependencies | D3.js v7 |
| Primary Pattern | IIFE (Immediately Invoked Function Expression) |

### 1.2 Identified Concerns (Current State)

The file mixes multiple concerns within a single IIFE closure:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    attack_timearcs.js (3,425 lines)                 │
├─────────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │ DOM References   │  │ State Management │  │ Event Handlers   │  │
│  │ (lines 7-18)     │  │ (lines 20-165)   │  │ (lines 335-513)  │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │ CSV Parsing      │  │ Data Transform   │  │ Mapping Loaders  │  │
│  │ (lines 182-293)  │  │ (lines 295-540)  │  │ (lines 3254-3423)│  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │              Main Render Function (lines 754-2882)           │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐             │  │
│  │  │ Scale Setup │ │ Arc Drawing │ │ Animations  │             │  │
│  │  └─────────────┘ └─────────────┘ └─────────────┘             │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐             │  │
│  │  │ Force Sim   │ │ Fisheye     │ │ Lensing     │             │  │
│  │  └─────────────┘ └─────────────┘ └─────────────┘             │  │
│  └──────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │ Legend UI        │  │ Tooltip          │  │ Graph Algorithms │  │
│  │ (lines 606-752)  │  │ (lines 2884-2897)│  │ (lines 2900-3235)│  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.3 Key Problems

1. **Massive Render Function**: The `render()` function spans ~2,100 lines with deeply nested closures
2. **Tightly Coupled State**: Global variables are accessed and mutated throughout
3. **No Separation of Concerns**: Data processing, UI rendering, and business logic intermixed
4. **Difficult to Test**: Heavy DOM dependencies make unit testing challenging
5. **Closure Dependencies**: Inner functions depend on outer scope variables
6. **Duplicate Code**: Data transformation logic appears in multiple places (lines 295-333, 518-540, 550-570)

---

## 2. Target Architecture

### 2.1 Proposed Module Structure

```
src/
├── index.js                    # Entry point - initializes app, exports public API
├── config/
│   └── constants.js            # Margins, colors, default values
├── state/
│   └── AppState.js             # Centralized state management class
├── data/
│   ├── csvParser.js            # Stream CSV parsing
│   ├── dataTransformer.js      # Raw data to processed records
│   └── aggregator.js           # Link/relationship aggregation
├── mappings/
│   ├── mapLoader.js            # Async loading of JSON mappings
│   ├── ipMapper.js             # IP ID ↔ address translation
│   ├── attackMapper.js         # Attack ID ↔ name translation
│   └── colorMapper.js          # Attack/group → color lookup
├── layout/
│   ├── forceSimulation.js      # D3 force layout setup
│   ├── nodeOrdering.js         # Attack-group-based ordering
│   └── componentDetection.js   # Connected component algorithms
├── scales/
│   ├── scaleFactory.js         # X/Y/width scale creation
│   ├── lensDistortion.js       # Horizontal lens transformation
│   └── fisheyeDistortion.js    # Vertical fisheye transformation
├── rendering/
│   ├── arcRenderer.js          # Arc path generation and updates
│   ├── gradientRenderer.js     # SVG gradient definitions
│   ├── axisRenderer.js         # Time axis rendering
│   ├── rowRenderer.js          # IP row lines and labels
│   └── animationController.js  # Transition orchestration
├── ui/
│   ├── legend.js               # Legend building and filtering
│   ├── tooltip.js              # Tooltip show/hide/positioning
│   ├── controls.js             # Slider, button, radio handlers
│   └── fileHandlers.js         # File input event handlers
└── utils/
    ├── domRefs.js              # DOM element references
    ├── dateUtils.js            # Timestamp conversion utilities
    └── validation.js           # Input validation helpers
```

### 2.2 Module Dependency Graph

```
                              ┌─────────────┐
                              │  index.js   │
                              └──────┬──────┘
                                     │
        ┌────────────────────────────┼────────────────────────────┐
        ▼                            ▼                            ▼
┌───────────────┐          ┌─────────────────┐          ┌─────────────────┐
│   ui/*        │          │  state/AppState │          │  data/*         │
│   controls    │◄────────►│                 │◄────────►│  csvParser      │
│   fileHandlers│          │  (Central Hub)  │          │  transformer    │
│   legend      │          │                 │          │  aggregator     │
│   tooltip     │          └────────┬────────┘          └─────────────────┘
└───────────────┘                   │
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
┌───────────────┐          ┌─────────────────┐          ┌─────────────────┐
│  layout/*     │          │  rendering/*    │          │  scales/*       │
│  forceSim     │◄────────►│  arcRenderer    │◄────────►│  scaleFactory   │
│  nodeOrdering │          │  gradientRender │          │  lensDistortion │
│  components   │          │  axisRenderer   │          │  fisheye        │
└───────────────┘          │  rowRenderer    │          └─────────────────┘
                           │  animationCtrl  │
                           └─────────────────┘
                                    ▲
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
┌───────────────┐          ┌─────────────────┐          ┌─────────────────┐
│  mappings/*   │          │  config/*       │          │  utils/*        │
│  mapLoader    │          │  constants      │          │  domRefs        │
│  ipMapper     │          │                 │          │  dateUtils      │
│  attackMapper │          │                 │          │  validation     │
│  colorMapper  │          │                 │          │                 │
└───────────────┘          └─────────────────┘          └─────────────────┘
```

---

## 3. Detailed Module Specifications

### 3.1 `config/constants.js`

**Responsibility**: Centralized configuration values

```javascript
// Example structure
export const MARGIN = { top: 40, right: 20, bottom: 30, left: 110 };
export const DEFAULT_WIDTH = 1200;
export const DEFAULT_HEIGHT = 600;
export const INNER_HEIGHT = 780;

export const PROTOCOL_COLORS = new Map([
  ['TCP', '#1f77b4'],
  ['UDP', '#2ca02c'],
  ['ICMP', '#ff7f0e'],
  ['GRE', '#9467bd'],
  ['ARP', '#8c564b'],
  ['DNS', '#17becf'],
]);

export const DEFAULT_COLOR = '#6c757d';
export const NEUTRAL_GREY = '#9e9e9e';

export const LENS_DEFAULTS = {
  magnification: 5,
  bandRadius: 0.045,
  effectRadius: 0.15,
};

export const FISHEYE_DEFAULTS = {
  distortion: 5,
  effectRadius: 0.5,
};
```

**Lines Extracted**: 110-141, various magic numbers throughout

---

### 3.2 `state/AppState.js`

**Responsibility**: Centralized, observable state management

```javascript
// Example structure
export class AppState {
  constructor() {
    // Visualization state
    this.labelMode = 'attack';
    this.isLensing = false;
    this.lensingMul = 5;
    this.lensCenter = 0;
    this.fisheyeEnabled = false;
    this.fisheyeDistortion = 5;
    
    // Mapping state
    this.ipIdToAddr = null;
    this.attackIdToName = null;
    this.colorByAttack = null;
    this.attackGroupIdToName = null;
    this.colorByAttackGroup = null;
    
    // Data state
    this.lastRawCsvRows = null;
    this.visibleAttacks = new Set();
    this.currentLabelMode = 'attack';
    
    // References
    this.currentArcPaths = null;
    this.updateLensVisualizationFn = null;
    this.resetFisheyeFn = null;
    
    // Observers
    this._observers = new Map();
  }
  
  subscribe(key, callback) { /* ... */ }
  notify(key) { /* ... */ }
  
  setLabelMode(mode) {
    this.labelMode = mode;
    this.notify('labelMode');
  }
  
  // ... getters/setters for all state
}

export const appState = new AppState();
```

**Lines Extracted**: 20-165, scattered global variables

---

### 3.3 `data/csvParser.js`

**Responsibility**: Stream parsing of CSV files

```javascript
/**
 * Stream-parse a CSV file incrementally.
 * @param {File} file - File object to parse
 * @param {Function} onRow - Callback for each valid row
 * @param {Object} options - Parsing options
 * @returns {Promise<{totalRows: number, validRows: number}>}
 */
export async function parseCSVStream(file, onRow, options = {}) { /* ... */ }

/**
 * Parse a single CSV line respecting quoted fields.
 * @param {string} line - Raw CSV line
 * @param {string} delimiter - Field delimiter
 * @returns {string[]} - Parsed fields
 */
export function parseCSVLine(line, delimiter = ',') { /* ... */ }
```

**Lines Extracted**: 182-293

---

### 3.4 `data/dataTransformer.js`

**Responsibility**: Transform raw CSV rows to typed records

```javascript
/**
 * Transform raw CSV row to typed record.
 * @param {Object} raw - Raw CSV row object
 * @param {number} index - Record index
 * @param {Object} mappers - IP and attack mappers
 * @returns {Object|null} - Processed record or null if invalid
 */
export function transformRow(raw, index, mappers) { /* ... */ }

/**
 * Validate a processed record.
 * @param {Object} record - Processed record
 * @returns {boolean} - True if valid
 */
export function isValidRecord(record) { /* ... */ }

/**
 * Batch transform with filtering.
 * @param {Object[]} rows - Raw rows
 * @param {Object} mappers - IP and attack mappers
 * @returns {Object[]} - Valid processed records
 */
export function transformRows(rows, mappers) { /* ... */ }
```

**Lines Extracted**: 295-333, 518-540, 550-570 (consolidated)

---

### 3.5 `data/aggregator.js`

**Responsibility**: Aggregate links and compute relationships

```javascript
/**
 * Build pairwise relationships with per-minute aggregation.
 * @param {Object[]} data - Processed records
 * @returns {Map} - Pair key → relationship data
 */
export function buildRelationships(data) { /* ... */ }

/**
 * Compute aggregated links per (src, dst, minute).
 * @param {Object[]} data - Processed records
 * @returns {Object[]} - Aggregated link objects
 */
export function computeLinks(data) { /* ... */ }

/**
 * Compute node connectivity metrics.
 * @param {Object[]} data - Processed records
 * @returns {{nodes: Object[], relationships: Map}}
 */
export function computeNodes(data) { /* ... */ }
```

**Lines Extracted**: 2900-3020, 2918-2983

---

### 3.6 `mappings/mapLoader.js`

**Responsibility**: Async loading of JSON mapping files

```javascript
/**
 * Load a JSON mapping file.
 * @param {string} path - File path
 * @returns {Promise<Object>} - Parsed JSON
 */
export async function loadJsonMap(path) { /* ... */ }

/**
 * Load all required mappings.
 * @returns {Promise<Object>} - All loaded mappings
 */
export async function loadAllMappings() { /* ... */ }
```

**Lines Extracted**: 3254-3281, 3345-3423

---

### 3.7 `mappings/ipMapper.js`

**Responsibility**: IP ID ↔ address translation

```javascript
/**
 * Create an IP mapper from loaded data.
 * @param {Object} rawMap - Raw IP map (ip→id or id→ip)
 * @returns {Map<number, string>} - ID → IP address map
 */
export function createIpMapper(rawMap) { /* ... */ }

/**
 * Decode an IP value (ID or string) to dotted quad.
 * @param {string|number} value - IP value
 * @param {Map} idToAddr - ID to address map
 * @returns {string} - Decoded IP address
 */
export function decodeIp(value, idToAddr) { /* ... */ }
```

**Lines Extracted**: 3237-3281

---

### 3.8 `mappings/attackMapper.js`

**Responsibility**: Attack ID ↔ name translation

```javascript
/**
 * Create attack name mapper from loaded data.
 * @param {Object} rawMap - Raw event type map
 * @returns {Map<number, string>} - ID → attack name
 */
export function createAttackMapper(rawMap) { /* ... */ }

/**
 * Decode attack value to name.
 * @param {string|number} value - Attack value
 * @param {Map} idToName - ID to name map
 * @returns {string} - Attack name
 */
export function decodeAttack(value, idToName) { /* ... */ }

/**
 * Decode attack group value.
 * @param {string|number} groupVal - Group value
 * @param {string|number} fallbackVal - Fallback attack value
 * @param {Map} groupIdToName - Group ID to name map
 * @param {Map} attackIdToName - Attack ID to name map
 * @returns {string} - Decoded group name
 */
export function decodeAttackGroup(groupVal, fallbackVal, groupIdToName, attackIdToName) { /* ... */ }
```

**Lines Extracted**: 3284-3308

---

### 3.9 `mappings/colorMapper.js`

**Responsibility**: Attack/group → color lookup

```javascript
/**
 * Create color mapper with canonical key lookup.
 * @param {Object} rawColorMap - Raw color mapping
 * @returns {{raw: Map, canonical: Map}}
 */
export function createColorMapper(rawColorMap) { /* ... */ }

/**
 * Canonicalize a name for color lookup.
 * @param {string} name - Original name
 * @returns {string} - Canonical form
 */
export function canonicalizeName(name) { /* ... */ }

/**
 * Look up color for attack name.
 * @param {string} name - Attack name
 * @param {Map} rawMap - Raw color map
 * @param {Map} canonicalMap - Canonical color map
 * @returns {string|null} - Color or null
 */
export function lookupColor(name, rawMap, canonicalMap) { /* ... */ }
```

**Lines Extracted**: 3310-3343

---

### 3.10 `layout/forceSimulation.js`

**Responsibility**: D3 force-directed layout configuration

```javascript
/**
 * Create and configure force simulation.
 * @param {Object[]} nodes - Node objects
 * @param {Object[]} links - Link objects
 * @param {Object} options - Simulation parameters
 * @returns {d3.Simulation} - Configured simulation
 */
export function createForceSimulation(nodes, links, options = {}) { /* ... */ }

/**
 * Run simulation until convergence.
 * @param {d3.Simulation} sim - Simulation to run
 * @param {number} maxIterations - Max iterations
 * @param {number} threshold - Energy threshold
 * @returns {number} - Iterations run
 */
export function runUntilConverged(sim, maxIterations = 300, threshold = 0.001) { /* ... */ }

/**
 * Create component separation force.
 * @param {Map} ipToComponent - IP → component index
 * @param {Object[]} nodes - Simulation nodes
 * @returns {Function} - Force function
 */
export function createComponentSeparationForce(ipToComponent, nodes) { /* ... */ }
```

**Lines Extracted**: 1440-1870, 3158-3180

---

### 3.11 `layout/nodeOrdering.js`

**Responsibility**: Attack-group-based node ordering

```javascript
/**
 * Compute nodes ordered by attack group then simulation Y.
 * @param {Object[]} links - Aggregated links
 * @returns {{nodes: Object[], simulation: d3.Simulation, yMap: Map}}
 */
export function computeNodesByAttackGrouping(links) { /* ... */ }

/**
 * Compact IP positions to eliminate gaps.
 * @param {Object[]} simNodes - Simulation nodes
 * @param {Map} yMap - IP → Y position map
 * @param {number} topMargin - Top margin
 * @param {number} innerHeight - Available height
 * @param {Object[]} components - Connected components
 * @param {Map} ipToComponent - IP → component index
 */
export function compactIPPositions(simNodes, yMap, topMargin, innerHeight, components, ipToComponent) { /* ... */ }
```

**Lines Extracted**: 3095-3235, 3063-3093

---

### 3.12 `layout/componentDetection.js`

**Responsibility**: Connected component algorithms

```javascript
/**
 * Find connected components in graph.
 * @param {Object[]} nodes - Node objects with id
 * @param {Object[]} links - Link objects with source/target
 * @returns {string[][]} - Array of component IP arrays
 */
export function findConnectedComponents(nodes, links) { /* ... */ }
```

**Lines Extracted**: 3022-3061

---

### 3.13 `scales/scaleFactory.js`

**Responsibility**: Create D3 scales for visualization

```javascript
/**
 * Create time scale for X axis.
 * @param {Date} minDate - Minimum date
 * @param {Date} maxDate - Maximum date
 * @param {number} xStart - Range start
 * @param {number} xEnd - Range end
 * @returns {d3.ScaleTime}
 */
export function createTimeScale(minDate, maxDate, xStart, xEnd) { /* ... */ }

/**
 * Create point scale for Y axis (IPs).
 * @param {string[]} domain - IP addresses
 * @param {number} rangeStart - Range start
 * @param {number} rangeEnd - Range end
 * @param {number} padding - Padding value
 * @returns {d3.ScalePoint}
 */
export function createIpScale(domain, rangeStart, rangeEnd, padding = 0.5) { /* ... */ }

/**
 * Create log scale for arc width.
 * @param {number} minCount - Minimum count
 * @param {number} maxCount - Maximum count
 * @returns {d3.ScaleLog}
 */
export function createWidthScale(minCount, maxCount) { /* ... */ }

/**
 * Detect timestamp unit from data range.
 * @param {number} tsMin - Minimum timestamp
 * @param {number} tsMax - Maximum timestamp
 * @returns {{unit: string, looksAbsolute: boolean, unitMs: number}}
 */
export function detectTimestampUnit(tsMin, tsMax) { /* ... */ }

/**
 * Create timestamp to Date converter.
 * @param {string} unit - Time unit
 * @param {boolean} looksAbsolute - Is absolute time
 * @param {number} base - Base offset for relative time
 * @returns {Function} - Converter function
 */
export function createToDateConverter(unit, looksAbsolute, base) { /* ... */ }
```

**Lines Extracted**: 754-900, 916-1035

---

### 3.14 `scales/lensDistortion.js`

**Responsibility**: Horizontal timeline lens distortion

```javascript
/**
 * Apply 1D lens transformation.
 * @param {number} normalized - Input position (0-1)
 * @param {number} lensCenterNorm - Lens center (0-1)
 * @param {number} bandRadiusNorm - Band radius (0-1)
 * @param {number} magnification - Magnification factor
 * @returns {number} - Distorted position (0-1)
 */
export function applyLens1D(normalized, lensCenterNorm, bandRadiusNorm, magnification) { /* ... */ }

/**
 * Create lens-aware X scale function.
 * @param {Object} params - Scale parameters
 * @returns {Function} - Lens X scale function
 */
export function createLensXScale(params) { /* ... */ }
```

**Lines Extracted**: 928-999

---

### 3.15 `scales/fisheyeDistortion.js`

**Responsibility**: Vertical fisheye distortion

```javascript
/**
 * Create fisheye scale for vertical distortion.
 * @param {string[]} sortedIps - Sorted IP list
 * @param {Map} originalPositions - Original Y positions
 * @param {Object} params - Fisheye parameters
 * @returns {Object} - Fisheye scale object
 */
export function createFisheyeScale(sortedIps, originalPositions, params) { /* ... */ }

/**
 * Create horizontal fisheye scale for timeline.
 * @param {Object} params - Scale parameters
 * @returns {Object} - Horizontal fisheye scale
 */
export function createHorizontalFisheyeScale(params) { /* ... */ }

/**
 * Apply fisheye distortion maintaining monotonicity.
 * @param {number} t - Input position (0-1)
 * @param {number} focus - Focus position (0-1)
 * @param {number} distortion - Distortion factor
 * @returns {number} - Distorted position
 */
export function fisheyeDistortion(t, focus, distortion) { /* ... */ }
```

**Lines Extracted**: 2320-2600

---

### 3.16 `rendering/arcRenderer.js`

**Responsibility**: Arc path generation and rendering

```javascript
/**
 * Generate arc path for link.
 * @param {Object} link - Link with source/target x/y
 * @returns {string} - SVG path string
 */
export function linkArc(link) { /* ... */ }

/**
 * Create arc paths selection.
 * @param {d3.Selection} container - Parent container
 * @param {Object[]} links - Link data
 * @param {Object} scales - Scale functions
 * @param {Object} options - Rendering options
 * @returns {d3.Selection} - Arc paths selection
 */
export function renderArcs(container, links, scales, options) { /* ... */ }

/**
 * Update arc positions.
 * @param {d3.Selection} arcPaths - Arc selection
 * @param {Function} xScale - X scale function
 * @param {Function} yScale - Y scale function
 * @param {number} duration - Transition duration
 */
export function updateArcPositions(arcPaths, xScale, yScale, duration = 250) { /* ... */ }

/**
 * Attach arc interaction handlers.
 * @param {d3.Selection} arcPaths - Arc selection
 * @param {Object} callbacks - Event callbacks
 */
export function attachArcHandlers(arcPaths, callbacks) { /* ... */ }
```

**Lines Extracted**: 1180-1360, 2076-2141, 2796-2820

---

### 3.17 `rendering/gradientRenderer.js`

**Responsibility**: SVG gradient definitions

```javascript
/**
 * Create gradient definitions for links.
 * @param {d3.Selection} svg - SVG element
 * @param {Object[]} links - Link data
 * @param {Function} colorFn - Color lookup function
 * @param {Function} xScale - X scale function
 * @param {Function} yScale - Y scale function
 * @param {string} labelMode - Current label mode
 * @returns {d3.Selection} - Gradients selection
 */
export function createGradients(svg, links, colorFn, xScale, yScale, labelMode) { /* ... */ }

/**
 * Generate unique gradient ID for link.
 * @param {Object} link - Link object
 * @returns {string} - Gradient ID
 */
export function gradientIdForLink(link) { /* ... */ }

/**
 * Update gradient positions.
 * @param {d3.Selection} svg - SVG element
 * @param {Object[]} links - Link data
 * @param {Function} xScale - X scale
 * @param {Function} yScale - Y scale
 * @param {number} duration - Transition duration
 */
export function updateGradientPositions(svg, links, xScale, yScale, duration = 250) { /* ... */ }
```

**Lines Extracted**: 1068-1076, 1197-1221

---

### 3.18 `rendering/axisRenderer.js`

**Responsibility**: Time axis rendering

```javascript
/**
 * Render time axis.
 * @param {d3.Selection} axisSvg - Axis SVG element
 * @param {d3.ScaleTime} scale - Time scale
 * @param {Object} options - Formatting options
 */
export function renderAxis(axisSvg, scale, options) { /* ... */ }

/**
 * Update axis with lens distortion.
 * @param {d3.Selection} axisSvg - Axis SVG
 * @param {Object[]} tickValues - Tick dates
 * @param {Function} xScaleLens - Lens X scale
 * @param {Object} params - Time params
 * @param {number} duration - Transition duration
 */
export function updateAxisWithLens(axisSvg, tickValues, xScaleLens, params, duration = 250) { /* ... */ }

/**
 * Reset axis to original positions.
 * @param {d3.Selection} axisSvg - Axis SVG
 * @param {d3.ScaleTime} originalScale - Original scale
 */
export function resetAxis(axisSvg, originalScale) { /* ... */ }
```

**Lines Extracted**: 1045-1066, 2744-2766, 2846-2877

---

### 3.19 `rendering/rowRenderer.js`

**Responsibility**: IP row lines and labels

```javascript
/**
 * Render row lines and labels.
 * @param {d3.Selection} container - Parent container
 * @param {string[]} ips - IP addresses
 * @param {Map} ipSpans - IP → {min, max} minute spans
 * @param {Function} xScale - X scale function
 * @param {Function} yScale - Y scale function
 * @param {Map} ipToNode - IP → node map
 * @returns {{lines: d3.Selection, labels: d3.Selection}}
 */
export function renderRows(container, ips, ipSpans, xScale, yScale, ipToNode) { /* ... */ }

/**
 * Attach label interaction handlers.
 * @param {d3.Selection} labels - Label selection
 * @param {Object} callbacks - Event callbacks
 */
export function attachLabelHandlers(labels, callbacks) { /* ... */ }

/**
 * Update row positions.
 * @param {d3.Selection} lines - Line selection
 * @param {d3.Selection} labels - Label selection
 * @param {Function} xScale - X scale
 * @param {Function} yScale - Y scale
 * @param {Map} ipToNode - IP → node map
 * @param {number} duration - Transition duration
 */
export function updateRowPositions(lines, labels, xScale, yScale, ipToNode, duration = 250) { /* ... */ }
```

**Lines Extracted**: 1078-1178, 1367-1438, 1959-2075, 2821-2844

---

### 3.20 `rendering/animationController.js`

**Responsibility**: Orchestrate transitions

```javascript
/**
 * Animate from force layout to timeline positions.
 * @param {Object} elements - {arcPaths, lines, labels}
 * @param {Map} startPositions - Initial Y positions
 * @param {Map} endPositions - Final Y positions
 * @param {Object} scales - Scale functions
 * @param {number} duration - Animation duration
 * @returns {Promise} - Resolves when animation completes
 */
export function animateToTimeline(elements, startPositions, endPositions, scales, duration = 1200) { /* ... */ }

/**
 * Animate auto-fit adjustment.
 * @param {Object} elements - Visualization elements
 * @param {Map} targetPositions - Target Y positions
 * @param {number} duration - Animation duration
 */
export function animateAutoFit(elements, targetPositions, duration = 800) { /* ... */ }
```

**Lines Extracted**: 1906-2142, 2143-2300

---

### 3.21 `ui/legend.js`

**Responsibility**: Legend building and interaction

```javascript
/**
 * Build legend UI.
 * @param {HTMLElement} container - Legend container
 * @param {string[]} items - Attack names
 * @param {Function} colorFn - Color lookup function
 * @param {Set} visibleAttacks - Currently visible attacks
 * @param {Object} callbacks - Click/dblclick callbacks
 */
export function buildLegend(container, items, colorFn, visibleAttacks, callbacks) { /* ... */ }

/**
 * Update legend visual state.
 * @param {HTMLElement} container - Legend container
 * @param {Set} visibleAttacks - Visible attacks
 */
export function updateLegendVisualState(container, visibleAttacks) { /* ... */ }

/**
 * Isolate single attack (toggle).
 * @param {string} attackName - Attack to isolate
 * @param {Set} visibleAttacks - Visible attacks set
 * @param {HTMLElement} container - Legend container
 * @returns {Set} - Updated visible attacks
 */
export function isolateAttack(attackName, visibleAttacks, container) { /* ... */ }
```

**Lines Extracted**: 605-752

---

### 3.22 `ui/tooltip.js`

**Responsibility**: Tooltip display and positioning

```javascript
/**
 * Show tooltip at event position.
 * @param {HTMLElement} tooltipEl - Tooltip element
 * @param {Event} evt - Mouse event
 * @param {string} html - Tooltip content
 */
export function showTooltip(tooltipEl, evt, html) { /* ... */ }

/**
 * Hide tooltip.
 * @param {HTMLElement} tooltipEl - Tooltip element
 */
export function hideTooltip(tooltipEl) { /* ... */ }

/**
 * Update tooltip position.
 * @param {HTMLElement} tooltipEl - Tooltip element
 * @param {Event} evt - Mouse event
 */
export function updateTooltipPosition(tooltipEl, evt) { /* ... */ }
```

**Lines Extracted**: 2884-2897

---

### 3.23 `ui/controls.js`

**Responsibility**: Control widget handlers

```javascript
/**
 * Initialize label mode radio buttons.
 * @param {NodeList} radios - Radio button elements
 * @param {Function} onChange - Change callback
 */
export function initLabelModeControls(radios, onChange) { /* ... */ }

/**
 * Initialize lens magnification slider.
 * @param {HTMLElement} slider - Slider element
 * @param {HTMLElement} valueDisplay - Value display element
 * @param {Function} onChange - Change callback
 */
export function initLensingSlider(slider, valueDisplay, onChange) { /* ... */ }

/**
 * Initialize lens toggle button.
 * @param {HTMLElement} button - Toggle button
 * @param {Function} onToggle - Toggle callback
 */
export function initLensingToggle(button, onToggle) { /* ... */ }

/**
 * Update lensing button visual state.
 * @param {HTMLElement} button - Toggle button
 * @param {boolean} enabled - Is lensing enabled
 */
export function updateLensingButtonState(button, enabled) { /* ... */ }

/**
 * Initialize keyboard shortcuts.
 * @param {Object} shortcuts - Key → callback map
 */
export function initKeyboardShortcuts(shortcuts) { /* ... */ }
```

**Lines Extracted**: 22-108

---

### 3.24 `ui/fileHandlers.js`

**Responsibility**: File upload event handling

```javascript
/**
 * Initialize CSV file input handler.
 * @param {HTMLElement} input - File input element
 * @param {Function} onLoad - Load callback
 * @param {Function} onError - Error callback
 */
export function initCsvFileHandler(input, onLoad, onError) { /* ... */ }

/**
 * Initialize IP map file handler.
 * @param {HTMLElement} input - File input element
 * @param {Function} onLoad - Load callback
 */
export function initIpMapHandler(input, onLoad) { /* ... */ }

/**
 * Initialize event type map handler.
 * @param {HTMLElement} input - File input element
 * @param {Function} onLoad - Load callback
 */
export function initEventMapHandler(input, onLoad) { /* ... */ }
```

**Lines Extracted**: 335-513

---

### 3.25 `utils/domRefs.js`

**Responsibility**: DOM element references

```javascript
/**
 * Get all required DOM element references.
 * @returns {Object} - Named element references
 */
export function getDomRefs() {
  return {
    fileInput: document.getElementById('fileInput'),
    ipMapInput: document.getElementById('ipMapInput'),
    eventMapInput: document.getElementById('eventMapInput'),
    statusEl: document.getElementById('status'),
    svg: d3.select('#chart'),
    container: document.getElementById('chart-container'),
    legendEl: document.getElementById('legend'),
    tooltip: document.getElementById('tooltip'),
    labelModeRadios: document.querySelectorAll('input[name="labelMode"]'),
    lensingMulSlider: document.getElementById('lensingMulSlider'),
    lensingMulValue: document.getElementById('lensingMulValue'),
    lensingToggleBtn: document.getElementById('lensingToggle'),
    axisSvg: d3.select('#axis-top'),
  };
}

/**
 * Update status message.
 * @param {HTMLElement} statusEl - Status element
 * @param {string} msg - Status message
 */
export function setStatus(statusEl, msg) {
  if (statusEl) statusEl.textContent = msg;
}
```

**Lines Extracted**: 7-18, 596

---

### 3.26 `utils/dateUtils.js`

**Responsibility**: Timestamp utilities

```javascript
/**
 * Safe conversion of value to number.
 * @param {*} value - Value to convert
 * @returns {number} - Numeric value or 0
 */
export function toNumber(value) { /* ... */ }

/**
 * Format date for tooltip display.
 * @param {Date} date - Date object
 * @param {boolean} absolute - Use absolute format
 * @param {string} unit - Time unit
 * @param {number} base - Base offset
 * @returns {string} - Formatted string
 */
export function formatTooltipDate(date, absolute, unit, base) { /* ... */ }
```

**Lines Extracted**: 592-594, various date formatting

---

### 3.27 `utils/validation.js`

**Responsibility**: Input validation

```javascript
/**
 * Validate processed record.
 * @param {Object} record - Record to validate
 * @returns {{valid: boolean, reason?: string}}
 */
export function validateRecord(record) { /* ... */ }

/**
 * Sanitize string for use in SVG ID.
 * @param {string} str - Input string
 * @returns {string} - Sanitized string
 */
export function sanitizeId(str) { /* ... */ }
```

**Lines Extracted**: 1070, scattered validation

---

### 3.28 `index.js` (Entry Point)

**Responsibility**: Initialize application, coordinate modules

```javascript
import { appState } from './state/AppState.js';
import { getDomRefs, setStatus } from './utils/domRefs.js';
import { loadAllMappings } from './mappings/mapLoader.js';
import { initCsvFileHandler, initIpMapHandler, initEventMapHandler } from './ui/fileHandlers.js';
import { initLabelModeControls, initLensingSlider, initLensingToggle, initKeyboardShortcuts } from './ui/controls.js';
import { render } from './rendering/orchestrator.js';

// Initialize application
(async function init() {
  const refs = getDomRefs();
  
  // Load mappings
  try {
    const mappings = await loadAllMappings();
    appState.setMappings(mappings);
  } catch (e) {
    console.warn('Mapping load failed (non-fatal):', e);
  }
  
  // Initialize UI controls
  initLabelModeControls(refs.labelModeRadios, (mode) => {
    appState.setLabelMode(mode);
    if (appState.lastRawCsvRows) {
      render(rebuildDataFromRawRows(appState.lastRawCsvRows));
    }
  });
  
  initLensingSlider(refs.lensingMulSlider, refs.lensingMulValue, (mul) => {
    appState.setLensingMul(mul);
    if (appState.isLensing && appState.updateLensVisualizationFn) {
      appState.updateLensVisualizationFn();
    }
  });
  
  // ... more initialization
  
  // Try loading default CSV
  await tryLoadDefaultCsv();
})();
```

---

## 4. Migration Strategy

### 4.1 Phase Overview

| Phase | Focus | Duration | Risk |
|-------|-------|----------|------|
| 1 | Extract utilities and constants | 2-3 days | Low |
| 2 | Extract data processing | 2-3 days | Low |
| 3 | Extract mappings | 1-2 days | Low |
| 4 | Extract layout algorithms | 2-3 days | Medium |
| 5 | Extract scale factories | 2-3 days | Medium |
| 6 | Extract rendering modules | 3-4 days | High |
| 7 | Extract UI modules | 2-3 days | Medium |
| 8 | Wire up and integration | 2-3 days | High |

### 4.2 Phase Details

#### Phase 1: Utilities and Constants (Low Risk)

**Scope**: Extract non-state-dependent pure functions and constants.

**Files Created**:
- `config/constants.js`
- `utils/domRefs.js`
- `utils/dateUtils.js`
- `utils/validation.js`

**Verification**:
- Existing functionality unchanged
- No runtime errors
- Constants match original values

#### Phase 2: Data Processing (Low Risk)

**Scope**: Extract CSV parsing and data transformation.

**Files Created**:
- `data/csvParser.js`
- `data/dataTransformer.js`
- `data/aggregator.js`

**Verification**:
- Parse same CSV files successfully
- Output records match original structure
- Link aggregation produces identical results

#### Phase 3: Mappings (Low Risk)

**Scope**: Extract mapping loaders and decoders.

**Files Created**:
- `mappings/mapLoader.js`
- `mappings/ipMapper.js`
- `mappings/attackMapper.js`
- `mappings/colorMapper.js`

**Verification**:
- All mappings load successfully
- IP/attack decoding matches original
- Color lookups return same values

#### Phase 4: Layout Algorithms (Medium Risk)

**Scope**: Extract force simulation and graph algorithms.

**Files Created**:
- `layout/forceSimulation.js`
- `layout/nodeOrdering.js`
- `layout/componentDetection.js`

**Verification**:
- Connected components detected correctly
- Force simulation converges
- Node ordering matches original

#### Phase 5: Scale Factories (Medium Risk)

**Scope**: Extract scale creation and distortion functions.

**Files Created**:
- `scales/scaleFactory.js`
- `scales/lensDistortion.js`
- `scales/fisheyeDistortion.js`

**Verification**:
- Scales produce correct ranges
- Lens distortion preserves monotonicity
- Fisheye distortion works correctly

#### Phase 6: Rendering Modules (High Risk)

**Scope**: Extract arc, gradient, axis, row rendering.

**Files Created**:
- `rendering/arcRenderer.js`
- `rendering/gradientRenderer.js`
- `rendering/axisRenderer.js`
- `rendering/rowRenderer.js`
- `rendering/animationController.js`

**Verification**:
- Visual output matches original
- All transitions smooth
- Interactions work correctly

#### Phase 7: UI Modules (Medium Risk)

**Scope**: Extract legend, tooltip, controls, file handlers.

**Files Created**:
- `ui/legend.js`
- `ui/tooltip.js`
- `ui/controls.js`
- `ui/fileHandlers.js`

**Verification**:
- All controls respond
- Legend filtering works
- Tooltips display correctly

#### Phase 8: Integration (High Risk)

**Scope**: Wire up all modules via state management.

**Files Created**:
- `state/AppState.js`
- `index.js`

**Verification**:
- Full E2E testing
- All features work
- Performance acceptable

---

## 5. Risk Analysis and Mitigation

### 5.1 Technical Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Closure variable dependencies | High | High | Map all closure vars before extraction; use state container |
| Animation timing issues | Medium | Medium | Preserve transition durations; test animation chains |
| Scale function scope | High | Medium | Pass all required params explicitly |
| Event handler `this` binding | Medium | Low | Use arrow functions or explicit bind |
| D3 selection scope loss | High | Medium | Pass selections explicitly between functions |

### 5.2 Mitigation Strategies

1. **Incremental Extraction**: Extract one module at a time; verify before proceeding
2. **Comprehensive State Mapping**: Document all state variables before starting
3. **Parallel Development**: Keep original file running alongside new modules
4. **Visual Regression Testing**: Screenshot comparison at each phase
5. **Performance Benchmarking**: Measure render times before/after

---

## 6. Testing Approach

### 6.1 Unit Tests (per module)

```javascript
// Example: data/csvParser.test.js
describe('csvParser', () => {
  describe('parseCSVLine', () => {
    it('handles simple comma-separated values', () => {
      expect(parseCSVLine('a,b,c')).toEqual(['a', 'b', 'c']);
    });
    
    it('handles quoted fields with commas', () => {
      expect(parseCSVLine('a,"b,c",d')).toEqual(['a', 'b,c', 'd']);
    });
    
    it('handles escaped quotes', () => {
      expect(parseCSVLine('a,"b""c",d')).toEqual(['a', 'b"c', 'd']);
    });
  });
});
```

### 6.2 Integration Tests

```javascript
// Example: Full render pipeline
describe('Render Pipeline', () => {
  it('renders correct number of arcs', async () => {
    const data = await loadTestCSV('test-data.csv');
    const elements = render(data);
    expect(elements.arcPaths.size()).toBe(expectedArcCount);
  });
  
  it('positions arcs correctly', async () => {
    const data = await loadTestCSV('test-data.csv');
    const elements = render(data);
    const firstArc = elements.arcPaths.nodes()[0];
    expect(firstArc.getAttribute('d')).toMatch(/^M\d+/);
  });
});
```

### 6.3 Visual Regression Tests

- Capture screenshots before refactoring
- Compare screenshots after each phase
- Flag any pixel differences > 0.1%

### 6.4 Performance Tests

```javascript
// Measure render time
const start = performance.now();
render(largeDataset);
const elapsed = performance.now() - start;
expect(elapsed).toBeLessThan(baselineMs * 1.1); // No more than 10% slower
```

---

## 7. File Structure Diagram

```
src/
├── index.js                          [~100 lines] Entry point
│
├── config/
│   └── constants.js                  [~50 lines]  Configuration values
│
├── state/
│   └── AppState.js                   [~150 lines] State management
│
├── data/
│   ├── csvParser.js                  [~150 lines] CSV stream parsing
│   ├── dataTransformer.js            [~80 lines]  Data transformation
│   └── aggregator.js                 [~180 lines] Link aggregation
│
├── mappings/
│   ├── mapLoader.js                  [~100 lines] Async map loading
│   ├── ipMapper.js                   [~60 lines]  IP translation
│   ├── attackMapper.js               [~70 lines]  Attack translation
│   └── colorMapper.js                [~80 lines]  Color lookup
│
├── layout/
│   ├── forceSimulation.js            [~200 lines] Force layout
│   ├── nodeOrdering.js               [~180 lines] Node ordering
│   └── componentDetection.js         [~60 lines]  Graph components
│
├── scales/
│   ├── scaleFactory.js               [~150 lines] Scale creation
│   ├── lensDistortion.js             [~120 lines] Horizontal lens
│   └── fisheyeDistortion.js          [~200 lines] Vertical fisheye
│
├── rendering/
│   ├── arcRenderer.js                [~250 lines] Arc rendering
│   ├── gradientRenderer.js           [~80 lines]  Gradient defs
│   ├── axisRenderer.js               [~100 lines] Time axis
│   ├── rowRenderer.js                [~200 lines] IP rows
│   └── animationController.js        [~250 lines] Transitions
│
├── ui/
│   ├── legend.js                     [~180 lines] Legend UI
│   ├── tooltip.js                    [~40 lines]  Tooltip
│   ├── controls.js                   [~120 lines] Widget handlers
│   └── fileHandlers.js               [~200 lines] File inputs
│
└── utils/
    ├── domRefs.js                    [~40 lines]  DOM references
    ├── dateUtils.js                  [~40 lines]  Date helpers
    └── validation.js                 [~30 lines]  Validation
                                      ──────────
                                      ~3,040 lines total
                                      (vs 3,425 original - 11% reduction
                                       through deduplication)
```

---

## 8. Backward Compatibility

### 8.1 API Preservation

The original file exposes no public API (IIFE). For backward compatibility with any external references:

```javascript
// index.js - maintain global exposure if needed
window.TimeArcsViz = {
  render,
  loadData: async (url) => { /* ... */ },
  setLabelMode: (mode) => appState.setLabelMode(mode),
  toggleLensing: () => appState.toggleLensing(),
};
```

### 8.2 Build Configuration

For non-module environments, provide bundled version:

```javascript
// rollup.config.js
export default {
  input: 'src/index.js',
  output: {
    file: 'dist/attack_timearcs.js',
    format: 'iife',
    name: 'TimeArcsViz',
  },
};
```

---

## 9. Summary

This refactoring transforms a 3,425-line monolithic file into ~25 focused modules averaging ~120 lines each. Key benefits:

1. **Maintainability**: Single-responsibility modules are easier to understand and modify
2. **Testability**: Pure functions can be unit tested in isolation
3. **Reusability**: Modules like `csvParser` and `colorMapper` can be reused elsewhere
4. **Performance**: Potential for tree-shaking unused code in future builds
5. **Onboarding**: New developers can understand one module at a time

The phased migration approach minimizes risk by allowing continuous verification at each step.

---

## Appendix: State Variable Inventory

| Variable | Type | Used In | Module Target |
|----------|------|---------|---------------|
| `labelMode` | string | render, legend | AppState |
| `isLensing` | boolean | render, controls | AppState |
| `lensingMul` | number | slider, render | AppState |
| `lensCenter` | number | render | AppState |
| `fisheyeEnabled` | boolean | render, controls | AppState |
| `fisheyeDistortion` | number | slider, render | AppState |
| `fisheyeScale` | object | render | Local to render |
| `horizontalFisheyeScale` | object | render | Local to render |
| `ipIdToAddr` | Map | decode, render | AppState |
| `attackIdToName` | Map | decode, render | AppState |
| `colorByAttack` | Map | color lookup | AppState |
| `attackGroupIdToName` | Map | decode | AppState |
| `colorByAttackGroup` | Map | color lookup | AppState |
| `visibleAttacks` | Set | legend, render | AppState |
| `currentArcPaths` | Selection | legend | AppState |
| `currentLabelMode` | string | legend | AppState |
| `lastRawCsvRows` | array | file handlers | AppState |
| `updateLensVisualizationFn` | function | slider | AppState (ref) |
| `resetFisheyeFn` | function | controls | AppState (ref) |
| `toggleLensingFn` | function | controls | AppState (ref) |
| `XGAP_BASE` | number | render | Local to render |
| `labelsCompressedMode` | boolean | render | Local to render |
| `originalRowPositions` | Map | fisheye | Local to render |
| `currentMouseX` | number | fisheye | Local to render |
