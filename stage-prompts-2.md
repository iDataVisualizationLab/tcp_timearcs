# Incremental Refactoring Prompts for attack_timearcs.js

**Each stage creates a working, testable version.** The original file gradually shrinks as modules are extracted and imported.

---

## Before You Start

```bash
# 1. Create project structure
mkdir -p src/{config,state,data,mappings,layout,scales,rendering,ui,utils}

# 2. Copy original as backup
cp attack_timearcs.js attack_timearcs.js.backup

# 3. Make sure you have a way to test (open the HTML page that uses this file)
```

---

## Stage 1: Extract Constants (Working Version)

```
## STAGE 1: Extract Constants — Produces Working Version

### Goal
Extract constants into a module, update original to import them, verify it still works.

### Step 1: Create `src/config/constants.js`

```javascript
// src/config/constants.js
// Extracted from attack_timearcs.js

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
};

export const FISHEYE_DEFAULTS = {
  distortion: 5,
  effectRadius: 0.5,
};
```

### Step 2: Update `attack_timearcs.js`

At the very TOP of the file (line 1), add:
```javascript
import { MARGIN, DEFAULT_WIDTH, DEFAULT_HEIGHT, INNER_HEIGHT, PROTOCOL_COLORS, DEFAULT_COLOR, NEUTRAL_GREY, LENS_DEFAULTS, FISHEYE_DEFAULTS } from './src/config/constants.js';
```

Then DELETE these lines from the original file:
- Line 110: `const margin = { top: 40, right: 20, bottom: 30, left: 110 };`
- Lines 111-112: `let width = 1200;` and `let height = 600;`
- Lines 132-140: The `protocolColors` Map and `defaultColor`

Replace usages:
- `margin` → `MARGIN`
- `protocolColors` → `PROTOCOL_COLORS`  
- `defaultColor` → `DEFAULT_COLOR`
- Find `const neutralGrey = '#9e9e9e'` (around line 1200) and delete it, use `NEUTRAL_GREY`
- Find `const innerHeight = 780` and delete it, use `INNER_HEIGHT`

### Step 3: Update HTML to use ES modules

In your HTML file, change:
```html
<script src="attack_timearcs.js"></script>
```
to:
```html
<script type="module" src="attack_timearcs.js"></script>
```

### Step 4: Test
1. Open the page in browser
2. Verify visualization loads
3. Check console for errors
4. Test basic interactions (hover, click legend)

### Verification Checklist
- [ ] Page loads without errors
- [ ] Visualization renders
- [ ] Colors match original
- [ ] Margins look correct

If anything fails, check the console and compare with your backup.
```

---

## Stage 2: Extract Utility Functions (Working Version)

```
## STAGE 2: Extract Utilities — Produces Working Version

### Prerequisites
- Stage 1 complete and working

### Step 1: Create `src/utils/helpers.js`

```javascript
// src/utils/helpers.js
// Pure utility functions extracted from attack_timearcs.js

/**
 * Safely convert value to number.
 * @param {*} v - Value to convert
 * @returns {number}
 */
export function toNumber(v) {
  const n = +v;
  return isFinite(n) ? n : 0;
}

/**
 * Sanitize string for SVG ID usage.
 * @param {string} s - Input string
 * @returns {string}
 */
export function sanitizeId(s) {
  return (s || '').toString().replace(/[^a-zA-Z0-9_-]+/g, '-');
}

/**
 * Canonicalize attack/group name for matching.
 * @param {string} s - Name to canonicalize
 * @returns {string}
 */
export function canonicalizeName(s) {
  return s
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .replace(/\s*\+\s*/g, ' + ')
    .trim();
}

/**
 * Show tooltip at event position.
 * @param {HTMLElement} tooltip - Tooltip element
 * @param {Event} evt - Mouse event
 * @param {string} html - Tooltip content
 */
export function showTooltip(tooltip, evt, html) {
  if (!tooltip) return;
  tooltip.style.display = 'block';
  if (html !== undefined) tooltip.innerHTML = html;
  const pad = 10;
  const x = (evt.pageX != null ? evt.pageX : evt.clientX) + pad;
  const y = (evt.pageY != null ? evt.pageY : evt.clientY) + pad;
  tooltip.style.left = x + 'px';
  tooltip.style.top = y + 'px';
}

/**
 * Hide tooltip.
 * @param {HTMLElement} tooltip - Tooltip element
 */
export function hideTooltip(tooltip) {
  if (!tooltip) return;
  tooltip.style.display = 'none';
}

/**
 * Update status message.
 * @param {HTMLElement} statusEl - Status element
 * @param {string} msg - Message to display
 */
export function setStatus(statusEl, msg) {
  if (statusEl) statusEl.textContent = msg;
}
```

### Step 2: Update `attack_timearcs.js`

Add to imports at top:
```javascript
import { toNumber, sanitizeId, canonicalizeName, showTooltip, hideTooltip, setStatus } from './src/utils/helpers.js';
```

DELETE these functions from original (search and remove):
- `function toNumber(v)` (around line 592)
- The `sanitizeId` arrow function (around line 1070)
- `function canonicalizeName(s)` (around line 3310)
- `function showTooltip(evt, html)` (around line 2884)
- `function hideTooltip()` (around line 2894)
- `function status(msg)` (around line 596)

UPDATE usages:
- `status(...)` → `setStatus(statusEl, ...)`
- `showTooltip(event, content)` → `showTooltip(tooltip, event, content)`
- `hideTooltip()` → `hideTooltip(tooltip)`

### Step 3: Test
1. Refresh browser
2. Upload a CSV - does status message appear?
3. Hover over arcs - do tooltips work?
4. Check console for errors

### Verification Checklist
- [ ] No console errors
- [ ] Status messages display
- [ ] Tooltips show/hide correctly
- [ ] All interactions still work
```

---

## Stage 3: Extract Mapping Decoders (Working Version)

```
## STAGE 3: Extract Mapping Decoders — Produces Working Version

### Prerequisites
- Stages 1-2 complete and working

### Step 1: Create `src/mappings/decoders.js`

```javascript
// src/mappings/decoders.js
// IP and attack decoding functions

import { canonicalizeName } from '../utils/helpers.js';

/**
 * Decode IP value to dotted quad.
 * @param {*} value - IP ID or string
 * @param {Map|null} idToAddr - ID to IP map
 * @returns {string}
 */
export function decodeIp(value, idToAddr) {
  const v = (value ?? '').toString().trim();
  if (!v) return 'N/A';
  if (/^\d+\.\d+\.\d+\.\d+$/.test(v)) return v;
  const n = Number(v);
  if (Number.isFinite(n) && idToAddr) {
    const ip = idToAddr.get(n);
    if (ip) return ip;
    console.warn(`IP ID ${n} not found in mapping`);
    return `IP_${n}`;
  }
  return v;
}

/**
 * Decode attack value to name.
 * @param {*} value - Attack ID or string
 * @param {Map|null} idToName - ID to name map
 * @returns {string}
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
 * Look up color for attack name.
 */
export function lookupAttackColor(name, rawColorMap, canonicalColorMap) {
  if (!name) return null;
  if (rawColorMap && rawColorMap.has(name)) return rawColorMap.get(name);
  const key = canonicalizeName(name);
  if (canonicalColorMap && canonicalColorMap.has(key)) return canonicalColorMap.get(key);
  if (canonicalColorMap) {
    for (const [k, col] of canonicalColorMap.entries()) {
      if (k.includes(key) || key.includes(k)) return col;
    }
  }
  return null;
}

/**
 * Look up color for attack group name.
 */
export function lookupAttackGroupColor(name, rawColorMap, canonicalColorMap) {
  if (!name) return null;
  if (rawColorMap && rawColorMap.has(name)) return rawColorMap.get(name);
  const key = canonicalizeName(name);
  if (canonicalColorMap && canonicalColorMap.has(key)) return canonicalColorMap.get(key);
  if (canonicalColorMap) {
    for (const [k, col] of canonicalColorMap.entries()) {
      if (k.includes(key) || key.includes(k)) return col;
    }
  }
  return null;
}
```

### Step 2: Update `attack_timearcs.js`

Add import:
```javascript
import { decodeIp, decodeAttack, decodeAttackGroup, lookupAttackColor, lookupAttackGroupColor } from './src/mappings/decoders.js';
```

The original `decodeIp`, `decodeAttack`, `decodeAttackGroup`, `lookupAttackColor`, `lookupAttackGroupColor` functions (around lines 3237-3343) reference global variables. We need to make them call the imported versions.

DELETE the function definitions but KEEP the global map variables (`ipIdToAddr`, `attackIdToName`, etc.)

CREATE wrapper functions that call the imported ones with the globals:
```javascript
// Replace the old function bodies with these wrappers:
// (Keep these INSIDE the IIFE, they close over the global maps)

const _decodeIp = (value) => decodeIp(value, ipIdToAddr);
const _decodeAttack = (value) => decodeAttack(value, attackIdToName);
const _decodeAttackGroup = (groupVal, fallbackVal) => decodeAttackGroup(groupVal, fallbackVal, attackGroupIdToName, attackIdToName);
const _lookupAttackColor = (name) => lookupAttackColor(name, rawColorByAttack, colorByAttack);
const _lookupAttackGroupColor = (name) => lookupAttackGroupColor(name, rawColorByAttackGroup, colorByAttackGroup);
```

Then find/replace throughout the file:
- `decodeIp(` → `_decodeIp(`
- `decodeAttack(` → `_decodeAttack(`  
- `decodeAttackGroup(` → `_decodeAttackGroup(`
- `lookupAttackColor(` → `_lookupAttackColor(`
- `lookupAttackGroupColor(` → `_lookupAttackGroupColor(`

### Step 3: Test
1. Refresh browser
2. Load default CSV - do IPs display correctly?
3. Check attack labels in tooltips
4. Verify arc colors match attacks

### Verification Checklist
- [ ] IPs decode to dotted quad format
- [ ] Attack names display (not IDs)
- [ ] Arc colors match attack types
- [ ] Legend shows correct colors
```

---

## Stage 4: Extract Data Aggregation (Working Version)

```
## STAGE 4: Extract Data Aggregation — Produces Working Version

### Prerequisites
- Stages 1-3 complete and working

### Step 1: Create `src/data/aggregation.js`

```javascript
// src/data/aggregation.js
// Link and relationship aggregation logic

/**
 * Build pairwise relationships with per-minute aggregation.
 * @param {Object[]} data - Processed records
 * @returns {Map}
 */
export function buildRelationships(data) {
  const pairKey = (a, b) => (a < b ? `${a}__${b}` : `${b}__${a}`);
  const rel = new Map();
  for (const row of data) {
    const key = pairKey(row.src_ip, row.dst_ip);
    let rec = rel.get(key);
    if (!rec) {
      rec = { counts: new Map(), max: 0, maxTime: null, a: row.src_ip, b: row.dst_ip };
      rel.set(key, rec);
    }
    const m = row.timestamp;
    const newVal = (rec.counts.get(m) || 0) + (row.count || 1);
    rec.counts.set(m, newVal);
    if (newVal > rec.max) { rec.max = newVal; rec.maxTime = m; }
  }
  return rel;
}

/**
 * Compute connectivity from relationships.
 */
export function computeConnectivityFromRelationships(relationships, threshold, allIps) {
  const res = new Map();
  for (const rec of relationships.values()) {
    if ((rec.max || 0) < threshold) continue;
    const { a, b, max, maxTime } = rec;
    const ra = res.get(a) || { max: -Infinity, time: null };
    const rb = res.get(b) || { max: -Infinity, time: null };
    if (max > ra.max || (max === ra.max && (maxTime ?? 0) < (ra.time ?? Infinity))) res.set(a, { max, time: maxTime });
    if (max > rb.max || (max === rb.max && (maxTime ?? 0) < (rb.time ?? Infinity))) res.set(b, { max, time: maxTime });
  }
  if (allIps) {
    for (const ip of allIps) if (!res.has(ip)) res.set(ip, { max: 0, time: null });
  }
  return res;
}

/**
 * Compute aggregated links per (src, dst, minute).
 * @param {Object[]} data - Processed records
 * @returns {Object[]}
 */
export function computeLinks(data) {
  const keyOf = (src, dst, m) => `${src}__${dst}__${m}`;
  const agg = new Map();
  for (const row of data) {
    const src = row.src_ip, dst = row.dst_ip, m = row.timestamp;
    const k = keyOf(src, dst, m);
    let rec = agg.get(k);
    if (!rec) {
      rec = { source: src, target: dst, minute: m, count: 0, attackCounts: new Map(), attackGroupCounts: new Map() };
      agg.set(k, rec);
    }
    const c = (row.count || 1);
    rec.count += c;
    const att = (row.attack || 'normal');
    rec.attackCounts.set(att, (rec.attackCounts.get(att) || 0) + c);
    const attg = (row.attack_group || 'normal');
    rec.attackGroupCounts.set(attg, (rec.attackGroupCounts.get(attg) || 0) + c);
  }
  
  const links = [];
  for (const rec of agg.values()) {
    let bestAttack = 'normal', bestCnt = -1;
    for (const [att, c] of rec.attackCounts.entries()) {
      if (c > bestCnt) { bestCnt = c; bestAttack = att; }
    }
    let bestGroup = 'normal', bestGroupCnt = -1;
    for (const [attg, c] of rec.attackGroupCounts.entries()) {
      if (c > bestGroupCnt) { bestGroupCnt = c; bestGroup = attg; }
    }
    links.push({ source: rec.source, target: rec.target, minute: rec.minute, count: rec.count, attack: bestAttack, attack_group: bestGroup });
  }
  
  links.sort((a, b) => (a.minute - b.minute) || (b.count - a.count) || a.source.localeCompare(b.source));
  return links;
}

/**
 * Find connected components.
 */
export function findConnectedComponents(nodes, links) {
  const ipToIndex = new Map();
  nodes.forEach((n, i) => ipToIndex.set(n.id, i));
  
  const adj = Array(nodes.length).fill(0).map(() => []);
  for (const link of links) {
    const srcIdx = ipToIndex.get(link.source);
    const tgtIdx = ipToIndex.get(link.target);
    if (srcIdx !== undefined && tgtIdx !== undefined) {
      adj[srcIdx].push(tgtIdx);
      adj[tgtIdx].push(srcIdx);
    }
  }
  
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
```

### Step 2: Update `attack_timearcs.js`

Add import:
```javascript
import { buildRelationships, computeConnectivityFromRelationships, computeLinks, findConnectedComponents } from './src/data/aggregation.js';
```

DELETE these functions from original:
- `function buildRelationships(data)` (around line 2900)
- `function computeConnectivityFromRelationships(...)` (around line 2968)
- `function computeLinks(data)` (around line 2986)
- `function findConnectedComponents(nodes, links)` (around line 3022)

The imported functions should work as drop-in replacements.

### Step 3: Test
1. Refresh browser
2. Load CSV - does visualization render?
3. Verify arcs connect correct IPs
4. Check that disconnected components are separated

### Verification Checklist
- [ ] Arcs render between correct IP pairs
- [ ] Link counts are correct (check tooltip)
- [ ] Multiple components separate properly
- [ ] Sort order looks correct (chronological)
```

---

## Stage 5: Extract Arc Path Generator (Working Version)

```
## STAGE 5: Extract Arc Rendering — Produces Working Version

### Prerequisites
- Stages 1-4 complete and working

### Step 1: Create `src/rendering/arcPath.js`

```javascript
// src/rendering/arcPath.js
// Arc path generation

/**
 * Generate SVG arc path for a link.
 * @param {Object} d - Link with source/target having x/y properties
 * @returns {string} - SVG path string
 */
export function linkArc(d) {
  if (!d || !d.source || !d.target) {
    console.warn('Invalid link object for arc:', d);
    return 'M0,0 L0,0';
  }
  const dx = d.target.x - d.source.x;
  const dy = d.target.y - d.source.y;
  const dr = Math.sqrt(dx * dx + dy * dy) / 2;
  if (d.source.y < d.target.y) {
    return "M" + d.source.x + "," + d.source.y + "A" + dr + "," + dr + " 0 0,1 " + d.target.x + "," + d.target.y;
  } else {
    return "M" + d.target.x + "," + d.target.y + "A" + dr + "," + dr + " 0 0,1 " + d.source.x + "," + d.source.y;
  }
}

/**
 * Generate gradient ID for a link.
 * @param {Object} d - Link object
 * @param {Function} sanitizeId - ID sanitizer function
 * @returns {string}
 */
export function gradientIdForLink(d, sanitizeId) {
  const src = d.sourceIp || (typeof d.source === 'string' ? d.source : d.source?.name);
  const tgt = d.targetIp || (typeof d.target === 'string' ? d.target : d.target?.name);
  return `grad-${sanitizeId(`${src}__${tgt}__${d.minute}`)}`;
}
```

### Step 2: Update `attack_timearcs.js`

Add import:
```javascript
import { linkArc, gradientIdForLink } from './src/rendering/arcPath.js';
```

DELETE from original:
- `function linkArc(d)` (around line 1182)

UPDATE gradient ID function:
- Find `const gradIdForLink = (d) =>` (around line 1071)
- Replace with: `const gradIdForLink = (d) => gradientIdForLink(d, sanitizeId);`

### Step 3: Test
1. Refresh browser
2. Verify arcs render as curved paths
3. Check arc direction (should curve right)
4. Verify gradients apply correctly

### Verification Checklist
- [ ] Arcs render as semicircles
- [ ] Arc curves in correct direction
- [ ] Gradients visible (grey to color)
- [ ] No visual difference from before
```

---

## Stage 6: Extract Legend Builder (Working Version)

```
## STAGE 6: Extract Legend — Produces Working Version

### Prerequisites
- Stages 1-5 complete and working

### Step 1: Create `src/ui/legend.js`

```javascript
// src/ui/legend.js
// Legend building and interaction

/**
 * Build legend UI with click handlers.
 * @param {HTMLElement} container - Legend container element
 * @param {string[]} items - Attack/group names
 * @param {Function} colorFn - Color lookup function
 * @param {Set} visibleAttacks - Set of currently visible attacks
 * @param {Object} callbacks - { onToggle, onIsolate, onUpdate }
 */
export function buildLegend(container, items, colorFn, visibleAttacks, callbacks) {
  container.innerHTML = '';
  const frag = document.createDocumentFragment();
  
  // Initialize all as visible if set is empty
  if (visibleAttacks.size === 0) {
    items.forEach(item => visibleAttacks.add(item));
  }
  
  items.forEach(p => {
    const item = document.createElement('div');
    item.className = 'legend-item';
    item.style.cursor = 'pointer';
    item.style.userSelect = 'none';
    item.setAttribute('data-attack', p);
    
    const isVisible = visibleAttacks.has(p);
    if (!isVisible) {
      item.style.opacity = '0.3';
      item.style.textDecoration = 'line-through';
    }
    
    const sw = document.createElement('div');
    sw.className = 'swatch';
    sw.style.background = colorFn(p);
    const label = document.createElement('span');
    label.textContent = p;
    item.appendChild(sw);
    item.appendChild(label);
    
    // Click timing for distinguishing click vs dblclick
    let lastClickTime = 0;
    let clickTimeout = null;
    
    item.addEventListener('click', function(e) {
      const attackName = this.getAttribute('data-attack');
      const now = Date.now();
      
      if (now - lastClickTime < 300) {
        if (clickTimeout) { clearTimeout(clickTimeout); clickTimeout = null; }
        lastClickTime = now;
        return;
      }
      
      lastClickTime = now;
      if (clickTimeout) { clearTimeout(clickTimeout); }
      
      clickTimeout = setTimeout(() => {
        clickTimeout = null;
        callbacks.onToggle(attackName);
      }, 300);
    });
    
    item.addEventListener('dblclick', function(e) {
      e.preventDefault();
      if (clickTimeout) { clearTimeout(clickTimeout); clickTimeout = null; }
      const attackName = this.getAttribute('data-attack');
      callbacks.onIsolate(attackName);
      lastClickTime = Date.now();
    });
    
    item.addEventListener('mouseenter', function() {
      if (visibleAttacks.has(this.getAttribute('data-attack'))) {
        this.style.backgroundColor = 'rgba(0, 0, 0, 0.05)';
      }
    });
    item.addEventListener('mouseleave', function() {
      this.style.backgroundColor = '';
    });
    
    frag.appendChild(item);
  });
  container.appendChild(frag);
}

/**
 * Update legend visual state.
 */
export function updateLegendVisualState(container, visibleAttacks) {
  const items = container.querySelectorAll('.legend-item');
  items.forEach(item => {
    const attackName = item.getAttribute('data-attack');
    const isVisible = visibleAttacks.has(attackName);
    item.style.opacity = isVisible ? '1' : '0.3';
    item.style.textDecoration = isVisible ? 'none' : 'line-through';
  });
}

/**
 * Isolate single attack (or show all if already isolated).
 */
export function isolateAttack(attackName, visibleAttacks, container) {
  if (visibleAttacks.size === 1 && visibleAttacks.has(attackName)) {
    // Show all
    const items = container.querySelectorAll('.legend-item');
    visibleAttacks.clear();
    items.forEach(item => visibleAttacks.add(item.getAttribute('data-attack')));
  } else {
    // Isolate
    visibleAttacks.clear();
    visibleAttacks.add(attackName);
  }
}
```

### Step 2: Update `attack_timearcs.js`

Add import:
```javascript
import { buildLegend, updateLegendVisualState, isolateAttack } from './src/ui/legend.js';
```

FIND the `buildLegend` function (around line 654) and REPLACE its body to call the imported version:

```javascript
function buildLegend(items, colorFn) {
  buildLegend(legendEl, items, colorFn, visibleAttacks, {
    onToggle: (attackName) => {
      if (visibleAttacks.has(attackName)) {
        visibleAttacks.delete(attackName);
      } else {
        visibleAttacks.add(attackName);
      }
      updateArcVisibility();
      updateLegendVisualState(legendEl, visibleAttacks);
    },
    onIsolate: (attackName) => {
      isolateAttack(attackName, visibleAttacks, legendEl);
      updateArcVisibility();
      updateLegendVisualState(legendEl, visibleAttacks);
    }
  });
}
```

Wait — there's a name collision. Rename the imported function:

```javascript
import { buildLegend as createLegend, updateLegendVisualState, isolateAttack } from './src/ui/legend.js';
```

Then update the local function:
```javascript
function buildLegend(items, colorFn) {
  createLegend(legendEl, items, colorFn, visibleAttacks, {
    onToggle: (attackName) => {
      if (visibleAttacks.has(attackName)) {
        visibleAttacks.delete(attackName);
      } else {
        visibleAttacks.add(attackName);
      }
      updateArcVisibility();
      updateLegendVisualState(legendEl, visibleAttacks);
    },
    onIsolate: (attackName) => {
      isolateAttack(attackName, visibleAttacks, legendEl);
      updateArcVisibility();
      updateLegendVisualState(legendEl, visibleAttacks);
    }
  });
}
```

DELETE the original helper functions:
- `updateLegendVisualState()` (around line 616)
- `isolateAttack()` (around line 631)

### Step 3: Test
1. Refresh browser
2. Click legend items - do arcs toggle visibility?
3. Double-click legend - does it isolate?
4. Double-click again - does it show all?

### Verification Checklist
- [ ] Legend items render with correct colors
- [ ] Single click toggles visibility
- [ ] Double click isolates attack
- [ ] Visual state (opacity/strikethrough) updates
```

---

## Stage 7: Extract CSV Parser (Working Version)

```
## STAGE 7: Extract CSV Parser — Produces Working Version

### Prerequisites
- Stages 1-6 complete and working

### Step 1: Create `src/data/csvParser.js`

```javascript
// src/data/csvParser.js
// Stream CSV parsing

/**
 * Parse a single CSV line respecting quoted fields.
 * @param {string} line - Raw line
 * @param {string} delimiter - Field delimiter
 * @returns {string[]}
 */
export function parseCSVLine(line, delimiter = ',') {
  const out = [];
  let i = 0;
  const n = line.length;
  while (i < n) {
    if (line[i] === '"') {
      i++;
      let start = i;
      let val = '';
      while (i < n) {
        const ch = line[i];
        if (ch === '"') {
          if (i + 1 < n && line[i + 1] === '"') {
            val += line.slice(start, i) + '"';
            i += 2;
            start = i;
            continue;
          }
          val += line.slice(start, i);
          i++;
          break;
        }
        i++;
      }
      if (i < n && line[i] === delimiter) i++;
      out.push(val);
    } else {
      let start = i;
      while (i < n && line[i] !== delimiter) i++;
      out.push(line.slice(start, i));
      if (i < n && line[i] === delimiter) i++;
    }
  }
  return out;
}

/**
 * Stream-parse CSV file.
 * @param {File} file - File to parse
 * @param {Function} onRow - Called with (rowObject, index)
 * @param {Object} options - { hasHeader, delimiter }
 * @returns {Promise<{fileName, totalRows, validRows}>}
 */
export async function parseCSVStream(file, onRow, options = {}) {
  const hasHeader = options.hasHeader !== false;
  const delimiter = options.delimiter || ',';
  
  let header = null;
  let totalRows = 0;
  let validRows = 0;
  let carry = '';
  
  const decoder = new TextDecoder();
  const reader = file.stream().getReader();
  
  function findNextBreak(s) {
    const n = s.indexOf('\n');
    const r = s.indexOf('\r');
    if (n === -1 && r === -1) return -1;
    if (n === -1) return r;
    if (r === -1) return n;
    return Math.min(n, r);
  }
  
  function stripBreakPrefix(s) {
    if (s.startsWith('\r\n')) return s.slice(2);
    if (s.startsWith('\n') || s.startsWith('\r')) return s.slice(1);
    return s;
  }
  
  function processLine(line) {
    const s = line.trim();
    if (!s) return;
    
    if (!header && hasHeader) {
      header = parseCSVLine(s, delimiter);
      return;
    }
    
    const cols = parseCSVLine(s, delimiter);
    if (!cols || cols.length === 0) return;
    
    totalRows++;
    const obj = header 
      ? Object.fromEntries(header.map((h, i) => [h, cols[i]]))
      : Object.fromEntries(cols.map((v, i) => [String(i), v]));
    
    const accepted = onRow(obj, totalRows - 1);
    if (accepted !== false) validRows++;
  }
  
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    
    const txt = decoder.decode(value, { stream: true });
    carry += txt;
    
    let idx;
    while ((idx = findNextBreak(carry)) >= 0) {
      const line = carry.slice(0, idx);
      processLine(line);
      carry = stripBreakPrefix(carry.slice(idx));
    }
  }
  
  // Flush remainder
  if (carry.trim()) {
    processLine(carry);
  }
  
  return { fileName: file.name, totalRows, validRows };
}
```

### Step 2: Update `attack_timearcs.js`

Add import:
```javascript
import { parseCSVStream, parseCSVLine } from './src/data/csvParser.js';
```

FIND `async function processCsvFile(file, combinedData, options = {})` (around line 182)

This function is complex and tightly coupled. Replace its line parsing with imported functions:

Inside `processCsvFile`, DELETE these local functions:
- `emitLinesFromChunk`
- `findNextBreak`
- `stripBreakPrefix`
- `parseCsvLine`

The simplest approach: Replace the entire `processCsvFile` to use `parseCSVStream`:

```javascript
async function processCsvFile(file, combinedData, options = { hasHeader: true, delimiter: ',' }) {
  const result = await parseCSVStream(file, (obj, idx) => {
    const attackName = _decodeAttack(obj.attack);
    const attackGroupName = _decodeAttackGroup(obj.attack_group, obj.attack);
    const rec = {
      idx: combinedData.length,
      timestamp: toNumber(obj.timestamp),
      length: toNumber(obj.length),
      src_ip: _decodeIp(obj.src_ip),
      dst_ip: _decodeIp(obj.dst_ip),
      protocol: (obj.protocol || '').toUpperCase() || 'OTHER',
      count: toNumber(obj.count) || 1,
      attack: attackName,
      attack_group: attackGroupName,
    };
    
    const hasValidTimestamp = isFinite(rec.timestamp);
    const hasValidSrcIp = rec.src_ip && rec.src_ip !== 'N/A' && !String(rec.src_ip).startsWith('IP_');
    const hasValidDstIp = rec.dst_ip && rec.dst_ip !== 'N/A' && !String(rec.dst_ip).startsWith('IP_');
    
    if (hasValidTimestamp && hasValidSrcIp && hasValidDstIp) {
      combinedData.push(rec);
      return true;
    }
    return false;
  }, options);
  
  return { 
    fileName: result.fileName, 
    totalRows: result.totalRows, 
    validRows: result.validRows 
  };
}
```

### Step 3: Test
1. Refresh browser
2. Upload a CSV file
3. Verify data loads and renders
4. Try uploading multiple files
5. Check status message shows correct counts

### Verification Checklist
- [ ] CSV files parse correctly
- [ ] Quoted fields with commas handled
- [ ] Row counts match expected
- [ ] Multiple file upload works
```

---

## Stage 8: Final Cleanup (Working Version)

```
## STAGE 8: Final Cleanup — Complete Modular Version

### Prerequisites
- Stages 1-7 complete and working

### Goals
1. Verify all modules are imported correctly
2. Remove any dead code from original
3. Document the module structure
4. Final testing

### Step 1: Verify Import Summary

At the top of `attack_timearcs.js`, you should have:

```javascript
import { MARGIN, DEFAULT_WIDTH, DEFAULT_HEIGHT, INNER_HEIGHT, PROTOCOL_COLORS, DEFAULT_COLOR, NEUTRAL_GREY } from './src/config/constants.js';
import { toNumber, sanitizeId, canonicalizeName, showTooltip, hideTooltip, setStatus } from './src/utils/helpers.js';
import { decodeIp, decodeAttack, decodeAttackGroup, lookupAttackColor, lookupAttackGroupColor } from './src/mappings/decoders.js';
import { buildRelationships, computeConnectivityFromRelationships, computeLinks, findConnectedComponents } from './src/data/aggregation.js';
import { linkArc, gradientIdForLink } from './src/rendering/arcPath.js';
import { buildLegend as createLegend, updateLegendVisualState, isolateAttack } from './src/ui/legend.js';
import { parseCSVStream, parseCSVLine } from './src/data/csvParser.js';
```

### Step 2: Create Module Index

Create `src/index.js` as a convenience re-export:

```javascript
// src/index.js
// Central export for all modules

export * from './config/constants.js';
export * from './utils/helpers.js';
export * from './mappings/decoders.js';
export * from './data/aggregation.js';
export * from './data/csvParser.js';
export * from './rendering/arcPath.js';
export * from './ui/legend.js';
```

### Step 3: Create README

Create `src/README.md`:

```markdown
# attack_timearcs Modules

Modular components extracted from attack_timearcs.js.

## Structure

```
src/
├── config/
│   └── constants.js      # Margins, colors, defaults
├── utils/
│   └── helpers.js        # Pure utility functions
├── mappings/
│   └── decoders.js       # IP/attack/color decoding
├── data/
│   ├── aggregation.js    # Link computation, components
│   └── csvParser.js      # Stream CSV parsing
├── rendering/
│   └── arcPath.js        # SVG arc path generation
├── ui/
│   └── legend.js         # Legend building/interaction
└── index.js              # Re-exports all modules
```

## Usage

```javascript
// Import specific functions
import { computeLinks, findConnectedComponents } from './src/data/aggregation.js';

// Or import from index
import { computeLinks, linkArc, buildLegend } from './src/index.js';
```
```

### Step 4: Final Test Checklist

Run through ALL functionality:

**Data Loading**
- [ ] Default CSV loads automatically
- [ ] Custom CSV upload works
- [ ] Multiple file upload works
- [ ] IP map upload updates display
- [ ] Event map upload updates labels

**Visualization**
- [ ] Arcs render correctly
- [ ] Arc colors match attacks
- [ ] Gradients visible (grey → color)
- [ ] IP labels positioned correctly
- [ ] Timeline axis displays

**Interactions**
- [ ] Arc hover highlights endpoints
- [ ] Arc hover shows tooltip
- [ ] IP label hover highlights arcs
- [ ] Legend click toggles visibility
- [ ] Legend double-click isolates
- [ ] Lensing toggle works (button)
- [ ] Lensing toggle works (Shift+L)
- [ ] Lens slider adjusts magnification
- [ ] Label mode radio switches

**Animation**
- [ ] Initial force layout animates
- [ ] Transition to timeline smooth
- [ ] Lens updates animate

### Step 5: Line Count Comparison

Check how much the main file has shrunk:

```bash
wc -l attack_timearcs.js
wc -l attack_timearcs.js.backup
wc -l src/**/*.js
```

Expected: Original ~3400 lines → Main file ~2500 lines + ~900 lines in modules

### Done!

You now have a working modular version where:
- Each module can be tested independently
- Changes to one module don't affect others
- Code is organized by responsibility
- Future refactoring can continue from here
```

---

## Quick Reference: What Each Stage Extracts

| Stage | Files Created | Lines Extracted | Risk |
|-------|--------------|-----------------|------|
| 1 | constants.js | ~30 | Low |
| 2 | helpers.js | ~80 | Low |
| 3 | decoders.js | ~100 | Low |
| 4 | aggregation.js | ~150 | Medium |
| 5 | arcPath.js | ~30 | Low |
| 6 | legend.js | ~120 | Medium |
| 7 | csvParser.js | ~100 | Medium |
| 8 | Cleanup | — | Low |

**Total: ~610 lines extracted into 7 modules**

---

## If Something Breaks

1. Check browser console for errors
2. Compare with backup: `diff attack_timearcs.js attack_timearcs.js.backup`
3. Revert just the imports and re-try
4. Worst case: `cp attack_timearcs.js.backup attack_timearcs.js`
