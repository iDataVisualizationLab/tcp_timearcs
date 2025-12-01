# Claude Code Stage Prompts for Refactoring attack_timearcs.js

Use these prompts sequentially. Each stage builds on the previous one. Copy and paste each prompt into Claude Code when ready to execute that phase.

---

## Stage 1: Extract Utilities, Constants, and State Foundation

```
## REFACTORING STAGE 1: Extract Utilities, Constants, and State Foundation

### Context
I'm refactoring a monolithic 3,425-line D3.js visualization file (attack_timearcs.js) into modular components. This is Stage 1 of 5 - extracting the foundational utilities and constants.

### Your Task
Create the following module files with the extracted code:

### 1. Create `src/config/constants.js`
Extract these from the original file:
- MARGIN object (line 110)
- DEFAULT_WIDTH, DEFAULT_HEIGHT, INNER_HEIGHT constants (lines 111-112, 861)
- PROTOCOL_COLORS Map (lines 132-139)
- DEFAULT_COLOR, NEUTRAL_GREY (lines 140, 1200)
- LENS_DEFAULTS object (magnification: 5, bandRadius: 0.045)
- FISHEYE_DEFAULTS object (distortion: 5, effectRadius: 0.5)

Export all as named exports.

### 2. Create `src/utils/domRefs.js`
Create a `getDomRefs()` function that returns an object with all DOM element references from lines 7-18:
- fileInput, ipMapInput, eventMapInput, statusEl
- svg (D3 selection), container, legendEl, tooltip
- labelModeRadios, lensingMulSlider, lensingMulValue, lensingToggleBtn
Also export a `setStatus(statusEl, msg)` helper.

### 3. Create `src/utils/dateUtils.js`
Extract:
- `toNumber(v)` function (line 592-593)
- Create `formatTooltipDate(date, absolute, unit, base)` for tooltip date formatting

### 4. Create `src/utils/validation.js`
Extract:
- `sanitizeId(s)` function (line 1070)
- Create `validateRecord(record)` that checks for valid timestamp, src_ip, dst_ip

### 5. Create `src/state/AppState.js`
Create a class that centralizes all global state variables from lines 20-165:
```javascript
export class AppState {
  constructor() {
    // Label mode
    this.labelMode = 'attack';
    
    // Lensing state
    this.isLensing = false;
    this.lensingMul = 5;
    this.lensCenter = 0;
    this.XGAP_BASE = null;
    this.labelsCompressedMode = false;
    
    // Fisheye state
    this.fisheyeEnabled = false;
    this.fisheyeDistortion = 5;
    
    // Mapping state
    this.ipIdToAddr = null;
    this.ipMapLoaded = false;
    this.attackIdToName = null;
    this.colorByAttack = null;
    this.rawColorByAttack = null;
    this.attackGroupIdToName = null;
    this.colorByAttackGroup = null;
    this.rawColorByAttackGroup = null;
    
    // Visibility state
    this.visibleAttacks = new Set();
    this.currentLabelMode = 'attack';
    
    // References (set during render)
    this.currentArcPaths = null;
    this.updateLensVisualizationFn = null;
    this.resetFisheyeFn = null;
    this.toggleLensingFn = null;
    this.lastRawCsvRows = null;
  }
  
  // Add getters/setters with validation
  setLabelMode(mode) {
    if (mode === 'attack' || mode === 'attack_group') {
      this.labelMode = mode;
    }
  }
  
  setMappings({ ipMap, attackMap, colorMap, groupMap, groupColorMap }) {
    this.ipIdToAddr = ipMap;
    this.ipMapLoaded = ipMap !== null && ipMap.size > 0;
    this.attackIdToName = attackMap;
    this.colorByAttack = colorMap?.canonical;
    this.rawColorByAttack = colorMap?.raw;
    this.attackGroupIdToName = groupMap;
    this.colorByAttackGroup = groupColorMap?.canonical;
    this.rawColorByAttackGroup = groupColorMap?.raw;
  }
}

export const appState = new AppState();
```

### Requirements
- Use ES6 module syntax (import/export)
- Keep D3.js as external dependency (import * as d3 from 'd3')
- Add JSDoc comments for all exports
- Preserve exact values from original code
- No runtime behavior changes

### Verification Steps
After creating files, verify:
1. All constants match original values
2. State class instantiates without errors
3. DOM refs function returns correct structure

Please create these 5 files now.
```

---

## Stage 2: Extract Data Processing Modules

```
## REFACTORING STAGE 2: Extract Data Processing Modules

### Context
Continuing refactoring of attack_timearcs.js. Stage 1 (utilities/constants/state) is complete. Now extracting data processing logic.

### Prerequisites
- src/config/constants.js exists
- src/utils/*.js files exist
- src/state/AppState.js exists

### Your Task
Create the following data processing modules:

### 1. Create `src/data/csvParser.js`
Extract the CSV parsing logic from lines 182-293:

```javascript
/**
 * Stream-parse a CSV file incrementally to avoid loading entire file into memory.
 * @param {File} file - File object to parse
 * @param {Function} onRow - Callback for each parsed row object
 * @param {Object} options - { hasHeader: boolean, delimiter: string }
 * @returns {Promise<{fileName: string, totalRows: number, validRows: number}>}
 */
export async function parseCSVStream(file, onRow, options = { hasHeader: true, delimiter: ',' }) {
  // Extract logic from lines 182-293
  // Include: emitLinesFromChunk, findNextBreak, stripBreakPrefix, parseCsvLine
}

/**
 * Parse a single CSV line respecting quoted fields.
 * @param {string} line - Raw CSV line
 * @param {string} delimiter - Field delimiter
 * @returns {string[]} - Array of parsed field values
 */
export function parseCSVLine(line, delimiter = ',') {
  // Extract logic from lines 216-243
}
```

### 2. Create `src/data/dataTransformer.js`
Consolidate the duplicate transformation logic from lines 295-333, 518-540, 550-570:

```javascript
import { toNumber } from '../utils/dateUtils.js';

/**
 * Transform a raw CSV row to a typed record.
 * @param {Object} raw - Raw CSV row with string values
 * @param {number} index - Record index
 * @param {Object} decoders - { decodeIp, decodeAttack, decodeAttackGroup }
 * @returns {Object} - Transformed record
 */
export function transformRow(raw, index, decoders) {
  const { decodeIp, decodeAttack, decodeAttackGroup } = decoders;
  return {
    idx: index,
    timestamp: toNumber(raw.timestamp),
    length: toNumber(raw.length),
    src_ip: decodeIp(raw.src_ip),
    dst_ip: decodeIp(raw.dst_ip),
    protocol: (raw.protocol || '').toUpperCase() || 'OTHER',
    count: toNumber(raw.count) || 1,
    attack: decodeAttack(raw.attack),
    attack_group: decodeAttackGroup(raw.attack_group, raw.attack),
  };
}

/**
 * Validate a processed record.
 * @param {Object} record - Processed record
 * @returns {boolean} - True if valid
 */
export function isValidRecord(record) {
  const hasValidTimestamp = isFinite(record.timestamp);
  const hasValidSrcIp = record.src_ip && 
                        record.src_ip !== 'N/A' && 
                        !String(record.src_ip).startsWith('IP_');
  const hasValidDstIp = record.dst_ip && 
                        record.dst_ip !== 'N/A' && 
                        !String(record.dst_ip).startsWith('IP_');
  return hasValidTimestamp && hasValidSrcIp && hasValidDstIp;
}

/**
 * Transform and filter a batch of rows.
 * @param {Object[]} rows - Raw CSV rows
 * @param {Object} decoders - Decoder functions
 * @returns {Object[]} - Valid transformed records
 */
export function transformRows(rows, decoders) {
  return rows
    .map((row, i) => transformRow(row, i, decoders))
    .filter(isValidRecord);
}
```

### 3. Create `src/data/aggregator.js`
Extract link and relationship aggregation from lines 2900-3020:

```javascript
/**
 * Build pairwise relationships with per-minute aggregation.
 * @param {Object[]} data - Processed records
 * @returns {Map} - Map of pair keys to relationship data
 */
export function buildRelationships(data) {
  // Extract from lines 2900-2916
}

/**
 * Compute connectivity from relationships.
 * @param {Map} relationships - Relationship map
 * @param {number} threshold - Minimum count threshold
 * @param {Set} allIps - Set of all IP addresses
 * @returns {Map} - IP to connectivity data
 */
export function computeConnectivity(relationships, threshold, allIps) {
  // Extract from lines 2968-2983
}

/**
 * Compute node metrics.
 * @param {Object[]} data - Processed records
 * @returns {{ nodes: Object[], relationships: Map }}
 */
export function computeNodes(data) {
  // Extract from lines 2918-2966
}

/**
 * Compute aggregated links per (src, dst, minute).
 * @param {Object[]} data - Processed records
 * @returns {Object[]} - Array of aggregated link objects
 */
export function computeLinks(data) {
  // Extract from lines 2986-3019
}
```

### Requirements
- Import from previously created modules where appropriate
- Use pure functions (no global state access)
- Add JSDoc comments for all exports
- Match original algorithm behavior exactly

### Verification
Test each function with sample data:
```javascript
// Test parseCSVLine
const fields = parseCSVLine('a,"b,c",d');
console.assert(fields.length === 3, 'Should parse 3 fields');
console.assert(fields[1] === 'b,c', 'Should handle quoted comma');

// Test transformRow
const record = transformRow({ timestamp: '100', src_ip: '1.2.3.4', dst_ip: '5.6.7.8', attack: 'test' }, 0, decoders);
console.assert(record.timestamp === 100, 'Should convert timestamp');

// Test computeLinks
const links = computeLinks(testData);
console.assert(Array.isArray(links), 'Should return array');
```

Please create these 3 files now.
```

---

## Stage 3: Extract Mapping Modules

```
## REFACTORING STAGE 3: Extract Mapping Modules

### Context
Continuing refactoring of attack_timearcs.js. Stages 1-2 (utilities, data processing) are complete. Now extracting mapping and decoding logic.

### Prerequisites
- src/config/constants.js exists
- src/utils/*.js files exist  
- src/state/AppState.js exists
- src/data/*.js files exist

### Your Task
Create the following mapping modules:

### 1. Create `src/mappings/mapLoader.js`
Extract async loading logic from lines 3254-3281, 3345-3423:

```javascript
/**
 * Load a JSON mapping file with caching disabled.
 * @param {string} path - Path to JSON file
 * @returns {Promise<Object>} - Parsed JSON object
 * @throws {Error} - If loading fails
 */
export async function loadJsonMap(path) {
  const res = await fetch(path, { cache: 'no-store' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

/**
 * Load IP mapping file.
 * @param {string} path - Path to ip_map.json (default: './full_ip_map.json')
 * @returns {Promise<Map<number, string>>} - ID to IP address map
 */
export async function loadIpMap(path = './full_ip_map.json') {
  // Extract logic from lines 3254-3281
  // Returns a Map<number, string> where key is ID, value is IP string
}

/**
 * Load event type mapping file.
 * @param {string} path - Path to event_type_mapping.json
 * @returns {Promise<Map<number, string>>} - ID to attack name map
 */
export async function loadEventTypeMap(path = './event_type_mapping.json') {
  // Extract logic from lines 3345-3359
}

/**
 * Load color mapping file.
 * @param {string} path - Path to color_mapping.json
 * @returns {Promise<{raw: Map, canonical: Map}>}
 */
export async function loadColorMapping(path = './color_mapping.json') {
  // Extract logic from lines 3362-3377
}

/**
 * Load attack group mapping file.
 * @param {string} path - Path to attack_group_mapping.json
 * @returns {Promise<Map<number, string>>} - ID to group name map
 */
export async function loadAttackGroupMap(path = './attack_group_mapping.json') {
  // Extract logic from lines 3379-3406
}

/**
 * Load attack group color mapping.
 * @param {string} path - Path to attack_group_color_mapping.json
 * @returns {Promise<{raw: Map, canonical: Map}>}
 */
export async function loadAttackGroupColorMapping(path = './attack_group_color_mapping.json') {
  // Extract logic from lines 3409-3422
}

/**
 * Load all mappings concurrently.
 * @returns {Promise<Object>} - All loaded mappings
 */
export async function loadAllMappings() {
  const [ipMap, attackMap, colorMap, groupMap, groupColorMap] = await Promise.all([
    loadIpMap().catch(() => null),
    loadEventTypeMap().catch(() => null),
    loadColorMapping().catch(() => null),
    loadAttackGroupMap().catch(() => null),
    loadAttackGroupColorMapping().catch(() => null),
  ]);
  return { ipMap, attackMap, colorMap, groupMap, groupColorMap };
}
```

### 2. Create `src/mappings/ipMapper.js`
Extract IP decoding logic from lines 3237-3252:

```javascript
/**
 * Decode an IP value to dotted quad format.
 * @param {string|number} value - IP value (ID or string)
 * @param {Map<number, string>|null} idToAddr - ID to address map
 * @returns {string} - Decoded IP address or placeholder
 */
export function decodeIp(value, idToAddr) {
  const v = (value ?? '').toString().trim();
  if (!v) return 'N/A';
  
  // If already looks like dotted quad, return as-is
  if (/^\d+\.\d+\.\d+\.\d+$/.test(v)) return v;
  
  // If numeric and ip map available, map id -> ip
  const n = Number(v);
  if (Number.isFinite(n) && idToAddr) {
    const ip = idToAddr.get(n);
    if (ip) return ip;
    console.warn(`IP ID ${n} not found in mapping`);
    return `IP_${n}`;
  }
  
  return v; // fallback to original string
}

/**
 * Create IP decoder function bound to a map.
 * @param {Map<number, string>|null} idToAddr - ID to address map
 * @returns {Function} - Bound decoder function
 */
export function createIpDecoder(idToAddr) {
  return (value) => decodeIp(value, idToAddr);
}
```

### 3. Create `src/mappings/attackMapper.js`
Extract attack decoding logic from lines 3284-3308:

```javascript
/**
 * Decode attack value to name.
 * @param {string|number} value - Attack value
 * @param {Map<number, string>|null} idToName - ID to name map
 * @returns {string} - Attack name
 */
export function decodeAttack(value, idToName) {
  const v = (value ?? '').toString().trim();
  if (!v) return 'normal';
  
  const n = Number(v);
  if (Number.isFinite(n) && idToName) {
    return idToName.get(n) || 'normal';
  }
  
  return v;
}

/**
 * Decode attack group value.
 * @param {string|number} groupVal - Group value
 * @param {string|number} fallbackVal - Fallback attack value
 * @param {Map<number, string>|null} groupIdToName - Group ID to name map
 * @param {Map<number, string>|null} attackIdToName - Attack ID to name map
 * @returns {string} - Decoded group name
 */
export function decodeAttackGroup(groupVal, fallbackVal, groupIdToName, attackIdToName) {
  const raw = (groupVal ?? '').toString().trim();
  if (!raw) {
    return decodeAttack(fallbackVal, attackIdToName);
  }
  
  const n = Number(raw);
  if (Number.isFinite(n) && groupIdToName) {
    return groupIdToName.get(n) || decodeAttack(fallbackVal, attackIdToName);
  }
  
  return raw;
}

/**
 * Create attack decoder functions bound to maps.
 * @param {Map|null} attackIdToName - Attack ID map
 * @param {Map|null} groupIdToName - Group ID map
 * @returns {{ decodeAttack: Function, decodeAttackGroup: Function }}
 */
export function createAttackDecoders(attackIdToName, groupIdToName) {
  return {
    decodeAttack: (v) => decodeAttack(v, attackIdToName),
    decodeAttackGroup: (gv, fv) => decodeAttackGroup(gv, fv, groupIdToName, attackIdToName),
  };
}
```

### 4. Create `src/mappings/colorMapper.js`
Extract color lookup logic from lines 3310-3343:

```javascript
/**
 * Canonicalize a name for color lookup.
 * @param {string} name - Original name
 * @returns {string} - Canonical form (lowercase, normalized spaces)
 */
export function canonicalizeName(name) {
  return name
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .replace(/\s*\+\s*/g, ' + ')
    .trim();
}

/**
 * Create color mapper from raw mapping.
 * @param {Object} rawColorMap - Raw color mapping object
 * @returns {{ raw: Map<string, string>, canonical: Map<string, string> }}
 */
export function createColorMapper(rawColorMap) {
  const raw = new Map(Object.entries(rawColorMap));
  const canonical = new Map();
  for (const [name, color] of Object.entries(rawColorMap)) {
    canonical.set(canonicalizeName(name), color);
  }
  return { raw, canonical };
}

/**
 * Look up color for attack/group name.
 * @param {string} name - Attack or group name
 * @param {Map<string, string>|null} rawMap - Raw color map
 * @param {Map<string, string>|null} canonicalMap - Canonical color map
 * @returns {string|null} - Color string or null
 */
export function lookupColor(name, rawMap, canonicalMap) {
  if (!name) return null;
  
  // Try exact match in raw map
  if (rawMap && rawMap.has(name)) return rawMap.get(name);
  
  // Try canonical match
  const key = canonicalizeName(name);
  if (canonicalMap && canonicalMap.has(key)) return canonicalMap.get(key);
  
  // Try partial match
  if (canonicalMap) {
    for (const [k, color] of canonicalMap.entries()) {
      if (k.includes(key) || key.includes(k)) return color;
    }
  }
  
  return null;
}

/**
 * Create color lookup function for attacks.
 * @param {Object} colorMaps - { attackRaw, attackCanonical, groupRaw, groupCanonical }
 * @param {string} labelMode - 'attack' or 'attack_group'
 * @param {string} defaultColor - Fallback color
 * @returns {Function} - Color lookup function
 */
export function createColorLookup(colorMaps, labelMode, defaultColor) {
  const { attackRaw, attackCanonical, groupRaw, groupCanonical } = colorMaps;
  
  return (name) => {
    if (labelMode === 'attack_group') {
      return lookupColor(name, groupRaw, groupCanonical) ||
             lookupColor(name, attackRaw, attackCanonical) ||
             defaultColor;
    }
    return lookupColor(name, attackRaw, attackCanonical) ||
           lookupColor(name, groupRaw, groupCanonical) ||
           defaultColor;
  };
}
```

### Requirements
- Use pure functions where possible
- Handle null/undefined gracefully
- Match original matching behavior exactly
- Add comprehensive JSDoc comments

### Verification
```javascript
// Test canonicalizeName
console.assert(canonicalizeName('DOS  Attack') === 'dos attack');
console.assert(canonicalizeName('A + B') === 'a + b');

// Test decodeIp
const ipMap = new Map([[1, '192.168.1.1']]);
console.assert(decodeIp('1', ipMap) === '192.168.1.1');
console.assert(decodeIp('10.0.0.1', ipMap) === '10.0.0.1');
console.assert(decodeIp('999', ipMap) === 'IP_999');

// Test lookupColor
const colorMap = createColorMapper({ 'DDoS Attack': '#ff0000' });
console.assert(lookupColor('ddos attack', null, colorMap.canonical) === '#ff0000');
```

Please create these 4 files now.
```

---

## Stage 4: Extract Layout and Scale Modules

```
## REFACTORING STAGE 4: Extract Layout and Scale Modules

### Context
Continuing refactoring of attack_timearcs.js. Stages 1-3 (utilities, data, mappings) are complete. Now extracting layout algorithms and scale factories.

### Prerequisites
All previous stage modules exist in src/

### Your Task
Create layout and scale modules:

### 1. Create `src/layout/componentDetection.js`
Extract connected component algorithm from lines 3022-3061:

```javascript
/**
 * Find connected components in a graph using DFS.
 * @param {Object[]} nodes - Nodes with 'id' property
 * @param {Object[]} links - Links with 'source' and 'target' properties
 * @returns {string[][]} - Array of component arrays (each contains IP strings)
 */
export function findConnectedComponents(nodes, links) {
  // Build index
  const ipToIndex = new Map();
  nodes.forEach((n, i) => ipToIndex.set(n.id, i));
  
  // Build adjacency list
  const adj = Array(nodes.length).fill(0).map(() => []);
  for (const link of links) {
    const srcIdx = ipToIndex.get(link.source);
    const tgtIdx = ipToIndex.get(link.target);
    if (srcIdx !== undefined && tgtIdx !== undefined) {
      adj[srcIdx].push(tgtIdx);
      adj[tgtIdx].push(srcIdx);
    }
  }
  
  // DFS
  const visited = new Set();
  const components = [];
  
  function dfs(nodeIdx, component) {
    visited.add(nodeIdx);
    component.push(nodeIdx);
    for (const neighbor of adj[nodeIdx]) {
      if (!visited.has(neighbor)) {
        dfs(neighbor, component);
      }
    }
  }
  
  for (let i = 0; i < nodes.length; i++) {
    if (!visited.has(i)) {
      const component = [];
      dfs(i, component);
      components.push(component.map(idx => nodes[idx].id));
    }
  }
  
  return components;
}

/**
 * Build IP to component index map.
 * @param {string[][]} components - Component arrays
 * @returns {Map<string, number>} - IP to component index
 */
export function buildIpToComponentMap(components) {
  const map = new Map();
  components.forEach((comp, idx) => {
    comp.forEach(ip => map.set(ip, idx));
  });
  return map;
}
```

### 2. Create `src/layout/forceSimulation.js`
Extract force simulation setup from lines 1440-1870, 3158-3180:

```javascript
import * as d3 from 'd3';

/**
 * Create force simulation for node layout.
 * @param {Object[]} nodes - Nodes with 'id' property
 * @param {Object[]} links - Links with source/target/value
 * @param {Object} options - Simulation parameters
 * @returns {d3.Simulation}
 */
export function createForceSimulation(nodes, links, options = {}) {
  const {
    chargeStrength = -12,
    linkDistance = 0,
    linkStrength = 1.0,
    xStrength = 0.01,
    alpha = 0.05,
    alphaDecay = 0.02,
    velocityDecay = 0.1,
  } = options;
  
  return d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(d => d.id).strength(linkStrength).distance(linkDistance))
    .force('charge', d3.forceManyBody().strength(chargeStrength))
    .force('x', d3.forceX(0).strength(xStrength))
    .alpha(alpha)
    .alphaDecay(alphaDecay)
    .velocityDecay(velocityDecay)
    .stop();
}

/**
 * Run simulation until energy converges.
 * @param {d3.Simulation} sim - Simulation to run
 * @param {number} maxIterations - Maximum iterations
 * @param {number} threshold - Energy change threshold
 * @returns {number} - Iterations run
 */
export function runUntilConverged(sim, maxIterations = 300, threshold = 0.001) {
  // Extract from lines 1474-1500
}

/**
 * Create component separation force.
 * @param {Map} ipToComponent - IP to component index
 * @param {Object[]} simNodes - Simulation nodes
 * @param {Object} params - Force parameters
 * @returns {Function} - Force function
 */
export function createComponentSeparationForce(ipToComponent, simNodes, params = {}) {
  // Extract from lines 1579-1673
}

/**
 * Create component cohesion force.
 * @param {Map} ipToComponent - IP to component index
 * @param {Object[]} simNodes - Simulation nodes
 * @returns {Function} - Force function
 */
export function createComponentCohesionForce(ipToComponent, simNodes) {
  // Extract from lines 1676-1730
}

/**
 * Initialize node positions deterministically.
 * @param {Object[]} nodes - Simulation nodes
 * @param {Map} ipToComponent - IP to component map
 * @param {Map} componentCenters - Component Y centers
 * @param {number} centerX - X center position
 */
export function initializeNodePositions(nodes, ipToComponent, componentCenters, centerX) {
  // Extract from lines 1547-1565
}
```

### 3. Create `src/layout/nodeOrdering.js`
Extract node ordering logic from lines 3095-3235:

```javascript
import { findConnectedComponents, buildIpToComponentMap } from './componentDetection.js';
import { createForceSimulation } from './forceSimulation.js';

/**
 * Compute nodes ordered by attack group then simulation Y.
 * @param {Object[]} links - Aggregated links
 * @returns {{ nodes: Object[], simulation: d3.Simulation, simNodes: Object[], yMap: Map, components: string[][], ipToComponent: Map }}
 */
export function computeNodesByAttackGrouping(links) {
  // Extract from lines 3100-3234
  // Returns nodes ordered by attack group, with simulation for visual layout
}

/**
 * Compact IP positions to eliminate gaps.
 * @param {Object[]} simNodes - Simulation nodes
 * @param {Map} yMap - IP to Y position map
 * @param {number} topMargin - Top margin
 * @param {number} innerHeight - Available height
 * @param {string[][]} components - Connected components
 * @param {Map} ipToComponent - IP to component map
 */
export function compactIPPositions(simNodes, yMap, topMargin, innerHeight, components, ipToComponent) {
  // Extract from lines 3063-3093
}

/**
 * Compute IP spans (first/last minute of activity).
 * @param {Object[]} links - Link data
 * @returns {Map<string, {min: number, max: number}>}
 */
export function computeIpSpans(links) {
  const spans = new Map();
  for (const l of links) {
    for (const ip of [l.source, l.target]) {
      const span = spans.get(ip) || { min: l.minute, max: l.minute };
      if (l.minute < span.min) span.min = l.minute;
      if (l.minute > span.max) span.max = l.minute;
      spans.set(ip, span);
    }
  }
  return spans;
}
```

### 4. Create `src/scales/scaleFactory.js`
Extract scale creation from lines 754-900, 916-1035:

```javascript
import * as d3 from 'd3';

/**
 * Detect timestamp unit from data range.
 * @param {number} tsMin - Minimum timestamp
 * @param {number} tsMax - Maximum timestamp
 * @returns {{ unit: string, looksAbsolute: boolean, unitMs: number, unitSuffix: string }}
 */
export function detectTimestampUnit(tsMin, tsMax) {
  // Extract from lines 765-786
}

/**
 * Create timestamp to Date converter.
 * @param {string} unit - Time unit
 * @param {boolean} looksAbsolute - Is absolute time
 * @param {number} base - Base offset for relative time
 * @param {number} unitMs - Milliseconds per unit
 * @returns {Function} - (timestamp) => Date
 */
export function createToDateConverter(unit, looksAbsolute, base, unitMs) {
  // Extract from lines 798-816
}

/**
 * Create X time scale.
 */
export function createTimeScale(minDate, maxDate, xStart, xEnd) {
  return d3.scaleTime().domain([minDate, maxDate]).range([xStart, xEnd]);
}

/**
 * Create Y point scale for IPs.
 */
export function createIpScale(ips, rangeStart, rangeEnd, padding = 0.5) {
  return d3.scalePoint().domain(ips).range([rangeStart, rangeEnd]).padding(padding);
}

/**
 * Create log scale for arc width.
 */
export function createWidthScale(minCount, maxCount) {
  const min = Math.max(1, minCount);
  const max = maxCount <= min ? min + 1 : maxCount;
  return d3.scaleLog().domain([min, max]).range([1, 4]);
}
```

### 5. Create `src/scales/lensDistortion.js`
Extract lens logic from lines 928-999:

```javascript
/**
 * Apply 1D lens transformation.
 * Expands a band around center, compresses outside.
 * @param {number} normalized - Input position (0-1)
 * @param {number} lensCenterNorm - Lens center (0-1)
 * @param {number} bandRadiusNorm - Band radius (0-1)
 * @param {number} magnification - Magnification factor
 * @returns {number} - Distorted position (0-1)
 */
export function applyLens1D(normalized, lensCenterNorm, bandRadiusNorm, magnification) {
  // Extract from lines 932-959
}

/**
 * Create lens-aware X scale function.
 */
export function createLensXScale(params) {
  const { xScale, tsMin, tsMax, xStart, xEnd, toDate, isLensing, lensCenter, lensingMul, horizontalFisheyeScale, fisheyeEnabled } = params;
  
  return (timestamp) => {
    // Extract from lines 962-999
  };
}
```

### 6. Create `src/scales/fisheyeDistortion.js`
Extract fisheye logic from lines 2320-2600:

```javascript
/**
 * Create fisheye scale for vertical distortion.
 */
export function createFisheyeScale(sortedIps, originalPositions, params) {
  // Extract from lines 2336-2427
}

/**
 * Create horizontal fisheye scale for timeline.
 */
export function createHorizontalFisheyeScale(params) {
  // Extract from lines 2436-2575
}

/**
 * Apply fisheye distortion maintaining monotonicity.
 */
export function fisheyeDistortion(t, focus, distortion) {
  // Extract fisheye math from lines 2389-2426, 2484-2575
}
```

### Requirements
- All D3 force/scale calls should match original exactly
- Simulation parameters must match original values
- Add comprehensive JSDoc comments
- Export clean interfaces

Please create these 6 files now.
```

---

## Stage 5: Extract Rendering and UI Modules, Wire Up Entry Point

```
## REFACTORING STAGE 5: Extract Rendering/UI Modules and Create Entry Point

### Context
Final stage of refactoring attack_timearcs.js. Stages 1-4 are complete. Now extracting rendering modules, UI components, and creating the main entry point.

### Prerequisites
All modules from stages 1-4 exist in src/

### Your Task
Create rendering, UI, and integration modules:

### Part A: Rendering Modules

### 1. Create `src/rendering/arcRenderer.js`

```javascript
import * as d3 from 'd3';

/**
 * Generate arc path SVG string.
 * @param {Object} link - Link with source/target having x/y
 * @returns {string} - SVG path string
 */
export function linkArc(link) {
  // Extract from lines 1182-1195
}

/**
 * Create arc paths selection.
 * @param {d3.Selection} container - Parent g element
 * @param {Object[]} links - Link data with nodes
 * @param {Object} options - { widthScale, gradIdFn, xScale, yScale, labelMode }
 * @returns {d3.Selection} - Arc paths selection
 */
export function renderArcs(container, links, options) {
  // Extract from lines 1223-1258
}

/**
 * Attach arc interaction handlers.
 */
export function attachArcHandlers(arcPaths, callbacks) {
  // Extract mouseover/mouseout from lines 1259-1359
}

/**
 * Update arc positions with animation.
 */
export function updateArcPositions(arcPaths, xScale, yScale, duration = 250) {
  // Extract from lines 2796-2807
}
```

### 2. Create `src/rendering/gradientRenderer.js`

```javascript
/**
 * Generate gradient ID for link.
 */
export function gradientIdForLink(link) {
  // Extract from lines 1071-1076
}

/**
 * Create gradient definitions.
 */
export function createGradients(svg, links, colorFn, xScale, yScale, labelMode) {
  // Extract from lines 1197-1221
}

/**
 * Update gradient positions.
 */
export function updateGradientPositions(svg, links, xScale, yScale, gradIdFn, duration = 250) {
  // Extract from lines 2809-2818
}
```

### 3. Create `src/rendering/axisRenderer.js`

```javascript
/**
 * Render time axis.
 */
export function renderAxis(axisSvg, scale, options) {
  // Extract from lines 1045-1066
}

/**
 * Update axis with lens distortion.
 */
export function updateAxisWithLens(axisSvg, tickValues, xScaleLens, params, duration = 250) {
  // Extract from lines 2846-2877
}

/**
 * Reset axis to original positions.
 */
export function resetAxis(axisSvg, originalScale, xStart) {
  // Extract from lines 2744-2766
}
```

### 4. Create `src/rendering/rowRenderer.js`

```javascript
/**
 * Render row lines and labels.
 */
export function renderRows(container, ips, ipSpans, xScale, yScale, ipToNode) {
  // Extract from lines 1078-1178
}

/**
 * Attach label interaction handlers.
 */
export function attachLabelHandlers(labels, callbacks) {
  // Extract from lines 1367-1438
}

/**
 * Update row positions.
 */
export function updateRowPositions(lines, labels, xScale, yScale, ipToNode, duration = 250) {
  // Extract from lines 2821-2844
}
```

### 5. Create `src/rendering/animationController.js`

```javascript
/**
 * Animate from force layout to timeline.
 */
export function animateToTimeline(elements, startY, endY, scales, duration = 1200) {
  // Extract from lines 1961-2141
}

/**
 * Animate auto-fit adjustment.
 */
export function animateAutoFit(elements, targetPositions, duration = 800) {
  // Extract from lines 2143-2300
}
```

### Part B: UI Modules

### 6. Create `src/ui/legend.js`

```javascript
/**
 * Build legend UI.
 */
export function buildLegend(container, items, colorFn, visibleAttacks, callbacks) {
  // Extract from lines 654-752
}

/**
 * Update legend visual state.
 */
export function updateLegendVisualState(container, visibleAttacks) {
  // Extract from lines 616-629
}

/**
 * Toggle attack visibility.
 */
export function toggleAttackVisibility(attackName, visibleAttacks) {
  if (visibleAttacks.has(attackName)) {
    visibleAttacks.delete(attackName);
  } else {
    visibleAttacks.add(attackName);
  }
  return visibleAttacks;
}

/**
 * Isolate single attack.
 */
export function isolateAttack(attackName, visibleAttacks, container) {
  // Extract from lines 631-652
}
```

### 7. Create `src/ui/tooltip.js`

```javascript
/**
 * Show tooltip.
 */
export function showTooltip(tooltipEl, evt, html) {
  // Extract from lines 2884-2893
}

/**
 * Hide tooltip.
 */
export function hideTooltip(tooltipEl) {
  // Extract from lines 2894-2897
}

/**
 * Update tooltip position.
 */
export function updateTooltipPosition(tooltipEl, evt) {
  if (!tooltipEl || tooltipEl.style.display === 'none') return;
  const pad = 10;
  tooltipEl.style.left = (evt.clientX + pad) + 'px';
  tooltipEl.style.top = (evt.clientY + pad) + 'px';
}
```

### 8. Create `src/ui/controls.js`

```javascript
/**
 * Initialize label mode controls.
 */
export function initLabelModeControls(radios, onChange) {
  // Extract from lines 22-28
}

/**
 * Initialize lensing slider.
 */
export function initLensingSlider(slider, valueDisplay, onChange) {
  // Extract from lines 31-51
}

/**
 * Initialize lensing toggle.
 */
export function initLensingToggle(button, onToggle) {
  // Extract from lines 71-87
}

/**
 * Update lensing button state.
 */
export function updateLensingButtonState(button, enabled) {
  // Extract from lines 55-66
}

/**
 * Initialize keyboard shortcuts.
 */
export function initKeyboardShortcuts(shortcuts) {
  // Extract from lines 89-108
}
```

### 9. Create `src/ui/fileHandlers.js`

```javascript
/**
 * Initialize CSV file input handler.
 */
export function initCsvFileHandler(input, processFn, statusFn) {
  // Extract from lines 336-422
}

/**
 * Initialize IP map file handler.
 */
export function initIpMapHandler(input, onLoad, statusFn) {
  // Extract from lines 425-467
}

/**
 * Initialize event map file handler.
 */
export function initEventMapHandler(input, onLoad, statusFn) {
  // Extract from lines 469-513
}
```

### Part C: Entry Point

### 10. Create `src/index.js`

```javascript
// Import all modules
import { appState } from './state/AppState.js';
import { getDomRefs, setStatus } from './utils/domRefs.js';
import { loadAllMappings } from './mappings/mapLoader.js';
import { createIpDecoder } from './mappings/ipMapper.js';
import { createAttackDecoders } from './mappings/attackMapper.js';
import { createColorLookup } from './mappings/colorMapper.js';
import { parseCSVStream } from './data/csvParser.js';
import { transformRow, isValidRecord } from './data/dataTransformer.js';
import { computeLinks } from './data/aggregator.js';
import { computeNodesByAttackGrouping, computeIpSpans } from './layout/nodeOrdering.js';
import { detectTimestampUnit, createToDateConverter, createTimeScale, createIpScale, createWidthScale } from './scales/scaleFactory.js';
import { createLensXScale } from './scales/lensDistortion.js';
import { createFisheyeScale, createHorizontalFisheyeScale } from './scales/fisheyeDistortion.js';
import { renderArcs, attachArcHandlers, updateArcPositions, linkArc } from './rendering/arcRenderer.js';
import { createGradients, gradientIdForLink, updateGradientPositions } from './rendering/gradientRenderer.js';
import { renderAxis, updateAxisWithLens, resetAxis } from './rendering/axisRenderer.js';
import { renderRows, attachLabelHandlers, updateRowPositions } from './rendering/rowRenderer.js';
import { animateToTimeline } from './rendering/animationController.js';
import { buildLegend, updateLegendVisualState, isolateAttack } from './ui/legend.js';
import { showTooltip, hideTooltip, updateTooltipPosition } from './ui/tooltip.js';
import { initLabelModeControls, initLensingSlider, initLensingToggle, updateLensingButtonState, initKeyboardShortcuts } from './ui/controls.js';
import { initCsvFileHandler, initIpMapHandler, initEventMapHandler } from './ui/fileHandlers.js';
import { MARGIN, DEFAULT_COLOR, INNER_HEIGHT } from './config/constants.js';

// Main render function
function render(data) {
  // Coordinate all rendering modules
  // This is the orchestration layer that ties everything together
  // Follow the structure from the original render() function
  // but delegate to imported modules
}

// Initialization
(async function init() {
  const refs = getDomRefs();
  
  // Load mappings
  try {
    const mappings = await loadAllMappings();
    appState.setMappings(mappings);
    setStatus(refs.statusEl, 'Mappings loaded. Upload CSV to render.');
  } catch (e) {
    console.warn('Mapping load failed:', e);
  }
  
  // Create decoders
  const decoders = {
    decodeIp: createIpDecoder(appState.ipIdToAddr),
    ...createAttackDecoders(appState.attackIdToName, appState.attackGroupIdToName),
  };
  
  // Initialize controls
  initLabelModeControls(refs.labelModeRadios, (mode) => {
    appState.setLabelMode(mode);
    if (appState.lastRawCsvRows) {
      render(transformRows(appState.lastRawCsvRows, decoders));
    }
  });
  
  initLensingSlider(refs.lensingMulSlider, refs.lensingMulValue, (mul) => {
    appState.lensingMul = mul;
    appState.fisheyeDistortion = mul;
    if (appState.isLensing && appState.updateLensVisualizationFn) {
      appState.updateLensVisualizationFn();
    }
  });
  
  initLensingToggle(refs.lensingToggleBtn, () => {
    appState.fisheyeEnabled = !appState.fisheyeEnabled;
    if (!appState.fisheyeEnabled && appState.resetFisheyeFn) {
      appState.resetFisheyeFn();
    }
    refs.svg.style('cursor', appState.fisheyeEnabled ? 'crosshair' : 'default');
    updateLensingButtonState(refs.lensingToggleBtn, appState.fisheyeEnabled);
  });
  
  initKeyboardShortcuts({
    'Shift+L': () => {
      appState.fisheyeEnabled = !appState.fisheyeEnabled;
      if (!appState.fisheyeEnabled && appState.resetFisheyeFn) {
        appState.resetFisheyeFn();
      }
      refs.svg.style('cursor', appState.fisheyeEnabled ? 'crosshair' : 'default');
      updateLensingButtonState(refs.lensingToggleBtn, appState.fisheyeEnabled);
    },
  });
  
  // Initialize file handlers
  initCsvFileHandler(refs.fileInput, async (files) => {
    // Process files using parseCSVStream
    // Transform and render
  }, setStatus.bind(null, refs.statusEl));
  
  initIpMapHandler(refs.ipMapInput, (map) => {
    appState.ipIdToAddr = map;
    appState.ipMapLoaded = true;
    // Update decoder and re-render
  }, setStatus.bind(null, refs.statusEl));
  
  initEventMapHandler(refs.eventMapInput, (map) => {
    appState.attackIdToName = map;
    // Update decoder and re-render
  }, setStatus.bind(null, refs.statusEl));
  
  // Try loading default CSV
  try {
    const res = await fetch('./set1_first90_minutes.csv', { cache: 'no-store' });
    if (res.ok) {
      const text = await res.text();
      const rows = d3.csvParse(text.trim());
      appState.lastRawCsvRows = rows;
      render(transformRows(rows, decoders));
    }
  } catch (e) {
    // Ignore if not found
  }
})();

// Export for potential external use
export { render, appState };
```

### Requirements
- All modules must be importable
- render() must produce identical visual output
- All interactions must work (hover, click, lens, fisheye)
- No circular dependencies

### Final Verification Checklist
1. [ ] File loads without errors
2. [ ] Default CSV renders correctly
3. [ ] Custom CSV upload works
4. [ ] IP/event map upload works
5. [ ] Label mode toggle works
6. [ ] Legend filtering works (click/dblclick)
7. [ ] Arc hover highlights work
8. [ ] IP label hover works
9. [ ] Tooltips display correctly
10. [ ] Lensing toggle works (button + Shift+L)
11. [ ] Lens magnification slider works
12. [ ] Fisheye distortion works
13. [ ] Animations are smooth
14. [ ] Force layout produces correct grouping
15. [ ] Visual output matches original pixel-for-pixel

Please create all files for this final stage.
```

---

## Post-Refactoring Cleanup Prompt

```
## POST-REFACTORING: Cleanup and Optimization

### Context
The refactoring of attack_timearcs.js into modular components is complete. Now perform cleanup and optimization.

### Tasks

1. **Remove the original file**: Once all tests pass, the original attack_timearcs.js can be archived/removed.

2. **Create bundle configuration**:
   - Add rollup.config.js for bundling back to single file if needed
   - Configure for both ES modules and IIFE output

3. **Add TypeScript types** (optional):
   - Create .d.ts files for each module
   - Add JSDoc type annotations where missing

4. **Performance audit**:
   - Profile render function
   - Identify any performance regressions
   - Optimize if needed

5. **Documentation**:
   - Create README.md for src/
   - Document module dependencies
   - Add usage examples

6. **Testing setup**:
   - Configure Jest or Vitest
   - Add unit tests for pure functions
   - Add integration tests for render pipeline

### Deliverables
- rollup.config.js
- src/README.md
- Basic test setup
- Performance comparison report
```

---

## Notes for Executing These Prompts

1. **Execute sequentially**: Each stage depends on previous stages being complete.

2. **Verify before proceeding**: After each stage, verify the extracted modules work correctly before moving to the next.

3. **Keep original file**: Don't delete the original attack_timearcs.js until all stages are complete and verified.

4. **Handle edge cases**: The original code has many edge cases and fallbacks - ensure they're preserved.

5. **Test incrementally**: After each stage, import the new modules and verify they work alongside the original code.

6. **Git commits**: Make a commit after each successful stage for easy rollback if needed.
