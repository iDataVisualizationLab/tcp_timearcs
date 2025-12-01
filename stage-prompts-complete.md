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
# Continuation Prompts: Stages 9-14

**Prerequisites**: Stages 1-8 complete and working.

These stages break up the massive `render()` function into focused modules.

---

## Stage 9: Extract Scale Factories (Working Version)

```
## STAGE 9: Extract Scale Factories — Produces Working Version

### Goal
Extract timestamp detection and scale creation from render() into a module.

### Step 1: Create `src/scales/scaleFactory.js`

```javascript
// src/scales/scaleFactory.js
// Timestamp detection and D3 scale creation

/**
 * Detect timestamp unit from data range.
 * @param {number} tsMin - Minimum timestamp
 * @param {number} tsMax - Maximum timestamp
 * @returns {{ unit: string, looksAbsolute: boolean, unitMs: number, unitSuffix: string, base: number }}
 */
export function detectTimestampUnit(tsMin, tsMax) {
  const looksLikeMicroseconds = tsMin > 1e15;
  const looksLikeMilliseconds = tsMin > 1e12 && tsMin <= 1e15;
  const looksLikeSeconds = tsMin > 1e9 && tsMin <= 1e12;
  const looksLikeMinutesAbs = tsMin > 1e7 && tsMin <= 1e9;
  const looksLikeHoursAbs = tsMin > 1e5 && tsMin <= 1e7;
  const looksAbsolute = looksLikeMicroseconds || looksLikeMilliseconds || looksLikeSeconds || looksLikeMinutesAbs || looksLikeHoursAbs;
  
  let unit = 'minutes';
  if (looksLikeMicroseconds) unit = 'microseconds';
  else if (looksLikeMilliseconds) unit = 'milliseconds';
  else if (looksLikeSeconds) unit = 'seconds';
  else if (looksLikeMinutesAbs) unit = 'minutes';
  else if (looksLikeHoursAbs) unit = 'hours';
  
  const base = looksAbsolute ? 0 : tsMin;
  
  const unitMs = unit === 'microseconds' ? 0.001
              : unit === 'milliseconds' ? 1
              : unit === 'seconds' ? 1000
              : unit === 'minutes' ? 60_000
              : 3_600_000;
  
  const unitSuffix = unit === 'seconds' ? 's' : unit === 'hours' ? 'h' : 'm';
  
  return { unit, looksAbsolute, unitMs, unitSuffix, base };
}

/**
 * Create timestamp to Date converter.
 * @param {Object} timeInfo - From detectTimestampUnit
 * @returns {Function} - (timestamp) => Date
 */
export function createToDateConverter(timeInfo) {
  const { unit, looksAbsolute, unitMs, base } = timeInfo;
  
  return (m) => {
    if (m === undefined || m === null || !isFinite(m)) {
      console.warn('Invalid timestamp in toDate:', m);
      return new Date(0);
    }
    
    const val = looksAbsolute ? m : (m - base);
    const ms = unit === 'microseconds' ? (val / 1000)
             : unit === 'milliseconds' ? val
             : val * unitMs;
    
    const result = new Date(ms);
    if (!isFinite(result.getTime())) {
      console.warn('Invalid date result:', { m, looksAbsolute, unit, base, ms });
      return new Date(0);
    }
    return result;
  };
}

/**
 * Create X time scale.
 * @param {Date} minDate
 * @param {Date} maxDate
 * @param {number} xStart
 * @param {number} xEnd
 * @returns {d3.ScaleTime}
 */
export function createTimeScale(d3, minDate, maxDate, xStart, xEnd) {
  return d3.scaleTime()
    .domain([minDate, maxDate])
    .range([xStart, xEnd]);
}

/**
 * Create Y point scale for IPs.
 * @param {string[]} ips
 * @param {number} rangeStart
 * @param {number} rangeEnd
 * @param {number} padding
 * @returns {d3.ScalePoint}
 */
export function createIpScale(d3, ips, rangeStart, rangeEnd, padding = 0.5) {
  return d3.scalePoint()
    .domain(ips)
    .range([rangeStart, rangeEnd])
    .padding(padding);
}

/**
 * Create log scale for arc width.
 * @param {number} minCount
 * @param {number} maxCount
 * @returns {d3.ScaleLog}
 */
export function createWidthScale(d3, minCount, maxCount) {
  const min = Math.max(1, minCount);
  const max = maxCount <= min ? min + 1 : maxCount;
  return d3.scaleLog().domain([min, max]).range([1, 4]);
}

/**
 * Calculate max arc radius for layout.
 * @param {Object[]} links
 * @param {Map} ipIndexMap - IP to index
 * @param {number} estimatedStep - Estimated Y step
 * @returns {number}
 */
export function calculateMaxArcRadius(links, ipIndexMap, estimatedStep) {
  let maxDist = 0;
  links.forEach(l => {
    const srcIdx = ipIndexMap.get(l.source);
    const tgtIdx = ipIndexMap.get(l.target);
    if (srcIdx !== undefined && tgtIdx !== undefined) {
      const dist = Math.abs(srcIdx - tgtIdx);
      if (dist > maxDist) maxDist = dist;
    }
  });
  return (maxDist * estimatedStep) / 2;
}
```

### Step 2: Update `attack_timearcs.js`

Add import:
```javascript
import { detectTimestampUnit, createToDateConverter, createTimeScale, createIpScale, createWidthScale, calculateMaxArcRadius } from './src/scales/scaleFactory.js';
```

In the `render()` function, FIND the timestamp detection block (around line 755-796).

REPLACE this entire block:
```javascript
// Old code (DELETE):
const tsMin = d3.min(data, d => d.timestamp);
const tsMax = d3.max(data, d => d.timestamp);
const looksLikeMicroseconds = tsMin > 1e15;
// ... many more lines ...
const toDate = (m) => { ... };
```

WITH:
```javascript
// New code:
const tsMin = d3.min(data, d => d.timestamp);
const tsMax = d3.max(data, d => d.timestamp);
const timeInfo = detectTimestampUnit(tsMin, tsMax);
const { unit, looksAbsolute, unitMs, unitSuffix, base } = timeInfo;
const toDate = createToDateConverter(timeInfo);
```

FIND the scale creation (around line 916):
```javascript
// Old:
const x = d3.scaleTime()
  .domain([xMinDate, xMaxDate])
  .range([xStart, xEnd]);
```

REPLACE with:
```javascript
const x = createTimeScale(d3, xMinDate, xMaxDate, xStart, xEnd);
```

FIND Y scale creation (around line 1002):
```javascript
// Old:
const y = d3.scalePoint()
  .domain(allIps)
  .range([margin.top, margin.top + innerHeight])
  .padding(0.5);
```

REPLACE with:
```javascript
const y = createIpScale(d3, allIps, MARGIN.top, MARGIN.top + INNER_HEIGHT, 0.5);
```

FIND width scale creation (around line 1027-1032):
```javascript
// Old:
let minLinkCount = d3.min(links, d => Math.max(1, d.count)) || 1;
let maxLinkCount = d3.max(links, d => Math.max(1, d.count)) || 1;
minLinkCount = Math.max(1, minLinkCount);
if (maxLinkCount <= minLinkCount) maxLinkCount = minLinkCount + 1;
const widthScale = d3.scaleLog().domain([minLinkCount, maxLinkCount]).range([1, 4]);
```

REPLACE with:
```javascript
const minLinkCount = d3.min(links, d => Math.max(1, d.count)) || 1;
const maxLinkCount = d3.max(links, d => Math.max(1, d.count)) || 1;
const widthScale = createWidthScale(d3, minLinkCount, maxLinkCount);
```

FIND arc radius calculation (around line 898-910) and use `calculateMaxArcRadius`.

### Step 3: Test
1. Refresh browser
2. Verify timeline axis shows correct dates/times
3. Check arc widths vary by count
4. Verify IPs spread across full height

### Verification Checklist
- [ ] Absolute timestamps show as dates
- [ ] Relative timestamps show as t=N
- [ ] Arc widths proportional to count
- [ ] Y positions evenly distributed
```

---

## Stage 10: Extract Force Simulation (Working Version)

```
## STAGE 10: Extract Force Simulation — Produces Working Version

### Goal
Extract force layout setup and convergence logic from render().

### Step 1: Create `src/layout/forceSimulation.js`

```javascript
// src/layout/forceSimulation.js
// D3 force simulation setup and helpers

/**
 * Create force simulation for node layout.
 * @param {Object} d3 - D3 library
 * @param {Object[]} nodes - Nodes with 'id' property
 * @param {Object[]} links - Links with source/target/value
 * @param {Object} options - Simulation parameters
 * @returns {d3.Simulation}
 */
export function createForceSimulation(d3, nodes, links, options = {}) {
  const {
    chargeStrength = -12,
    linkDistance = 0,
    linkStrength = 1.0,
    xStrength = 0.01,
    alpha = 0.05,
    alphaDecay = 0.02,
    velocityDecay = 0.1,
  } = options;
  
  const sim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(d => d.id).strength(linkStrength).distance(linkDistance))
    .force('charge', d3.forceManyBody().strength(chargeStrength))
    .force('x', d3.forceX(0).strength(xStrength))
    .alpha(alpha)
    .alphaDecay(alphaDecay)
    .velocityDecay(velocityDecay)
    .stop();
  
  // Initialize positions deterministically
  nodes.forEach((n, i) => {
    if (n.x === undefined) n.x = 0;
    if (n.y === undefined) n.y = 0;
    if (n.vx === undefined) n.vx = 0;
    if (n.vy === undefined) n.vy = 0;
  });
  
  return sim;
}

/**
 * Run simulation until energy converges.
 * @param {d3.Simulation} sim
 * @param {number} maxIterations
 * @param {number} threshold
 * @returns {number} - Iterations run
 */
export function runUntilConverged(sim, maxIterations = 300, threshold = 0.001) {
  let prevEnergy = Infinity;
  let stableCount = 0;
  
  for (let i = 0; i < maxIterations; i++) {
    sim.tick();
    
    const energy = sim.nodes().reduce((sum, n) =>
      sum + (n.vx * n.vx + n.vy * n.vy), 0);
    
    if (Math.abs(prevEnergy - energy) < threshold) {
      stableCount++;
      if (stableCount >= 5) {
        console.log(`Converged after ${i + 1} iterations`);
        return i + 1;
      }
    } else {
      stableCount = 0;
    }
    prevEnergy = energy;
  }
  
  console.log(`Max iterations (${maxIterations}) reached`);
  return maxIterations;
}

/**
 * Create component separation force.
 * @param {Map} ipToComponent
 * @param {Object[]} simNodes
 * @param {Object} params
 * @returns {Function}
 */
export function createComponentSeparationForce(ipToComponent, simNodes, params = {}) {
  const { separationStrength = 1.2, minDistance = 80 } = params;
  
  return (alpha) => {
    // Compute component centroids
    const centroids = new Map();
    const counts = new Map();
    
    simNodes.forEach(n => {
      const compIdx = ipToComponent.get(n.id) || -1;
      if (!centroids.has(compIdx)) {
        centroids.set(compIdx, { x: 0, y: 0 });
        counts.set(compIdx, 0);
      }
      const c = centroids.get(compIdx);
      c.x += n.x || 0;
      c.y += n.y || 0;
      counts.set(compIdx, counts.get(compIdx) + 1);
    });
    
    // Normalize
    centroids.forEach((c, idx) => {
      const count = counts.get(idx);
      if (count > 0) { c.x /= count; c.y /= count; }
    });
    
    // Apply separation between centroids
    const compIndices = Array.from(centroids.keys());
    for (let i = 0; i < compIndices.length; i++) {
      for (let j = i + 1; j < compIndices.length; j++) {
        const cA = centroids.get(compIndices[i]);
        const cB = centroids.get(compIndices[j]);
        
        const dx = cB.x - cA.x;
        const dy = cB.y - cA.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        
        if (dist < minDistance * 2) {
          const force = (minDistance * 2 - dist) / dist * separationStrength * alpha;
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force * 3.0;
          
          simNodes.forEach(n => {
            const comp = ipToComponent.get(n.id) || -1;
            const count = counts.get(comp) || 1;
            if (comp === compIndices[i]) {
              n.vx = (n.vx || 0) - fx / count;
              n.vy = (n.vy || 0) - fy / count;
            } else if (comp === compIndices[j]) {
              n.vx = (n.vx || 0) + fx / count;
              n.vy = (n.vy || 0) + fy / count;
            }
          });
        }
      }
    }
  };
}

/**
 * Create Y positioning force for components.
 * @param {Object} d3
 * @param {Map} ipToComponent
 * @param {Map} componentCenters
 * @param {number} defaultY
 * @returns {d3.ForceY}
 */
export function createComponentYForce(d3, ipToComponent, componentCenters, defaultY) {
  return d3.forceY()
    .y(n => {
      const compIdx = ipToComponent.get(n.id) || 0;
      return componentCenters.get(compIdx) || defaultY;
    })
    .strength(1.0);
}

/**
 * Initialize node positions by component.
 * @param {Object[]} nodes
 * @param {Map} ipToComponent
 * @param {Map} componentCenters
 * @param {number} centerX
 * @param {number} spread
 */
export function initializeNodePositions(nodes, ipToComponent, componentCenters, centerX, spread = 30) {
  // Group nodes by component
  const byComponent = new Map();
  nodes.forEach(n => {
    const comp = ipToComponent.get(n.id) || 0;
    if (!byComponent.has(comp)) byComponent.set(comp, []);
    byComponent.get(comp).push(n);
  });
  
  // Position each component's nodes
  byComponent.forEach((nodeList, compIdx) => {
    const targetY = componentCenters.get(compIdx) || 400;
    const step = nodeList.length > 1 ? spread / (nodeList.length - 1) : 0;
    
    nodeList.forEach((n, idx) => {
      n.x = centerX;
      if (nodeList.length === 1) {
        n.y = targetY;
      } else {
        const offset = (idx - (nodeList.length - 1) / 2) * step;
        n.y = targetY + offset;
      }
      n.vx = 0;
      n.vy = 0;
    });
  });
}
```

### Step 2: Update `attack_timearcs.js`

Add import:
```javascript
import { createForceSimulation, runUntilConverged, createComponentSeparationForce, createComponentYForce, initializeNodePositions } from './src/layout/forceSimulation.js';
```

In `render()`, FIND the force simulation setup (around lines 1440-1500).

The code currently creates simulation inline in `computeNodesByAttackGrouping`. 

FIRST, update `src/data/aggregation.js` to NOT create the simulation — just return the data:

In `computeNodesByAttackGrouping`, change the return to NOT include simulation setup, just return:
```javascript
return { 
  nodes, 
  simNodes,  // raw node objects for simulation
  simLinks,  // raw link objects for simulation
  yMap, 
  components, 
  ipToComponent,
  pairHasNonNormalAttack 
};
```

THEN in `render()`, create the simulation using the imported function:
```javascript
const nodeData = computeNodesByAttackGrouping(links);
const { nodes, simNodes, simLinks, yMap, components, ipToComponent } = nodeData;

// Create simulation
const simulation = createForceSimulation(d3, simNodes, simLinks);
simulation._components = components;
simulation._ipToComponent = ipToComponent;
```

FIND the component separation force (around line 1579-1673) and REPLACE with:
```javascript
const componentSeparationForce = createComponentSeparationForce(ipToComponent, simNodes);
simulation.force('componentSeparation', componentSeparationForce);
```

FIND `runUntilConverged` function definition (around line 1474) — DELETE it (now imported).

FIND node position initialization (around line 1547-1565) and use `initializeNodePositions`.

### Step 3: Test
1. Refresh browser
2. Watch initial animation — nodes should cluster by attack type
3. Components should separate vertically
4. Animation should converge smoothly

### Verification Checklist
- [ ] Force simulation runs
- [ ] Nodes cluster by attack
- [ ] Multiple components separate
- [ ] Animation completes without errors
```

---

## Stage 11: Extract Fisheye/Lens Logic (Working Version)

```
## STAGE 11: Extract Fisheye and Lens Logic — Produces Working Version

### Goal
Extract fisheye distortion and lens transformation from render().

### Step 1: Create `src/scales/distortion.js`

```javascript
// src/scales/distortion.js
// Fisheye and lens distortion functions

/**
 * Apply 1D lens transformation.
 * Expands a band around center, compresses outside.
 * @param {number} normalized - Input (0-1)
 * @param {number} lensCenterNorm - Center (0-1)
 * @param {number} bandRadiusNorm - Radius (0-1)
 * @param {number} magnification - Magnification factor
 * @returns {number}
 */
export function applyLens1D(normalized, lensCenterNorm, bandRadiusNorm, magnification) {
  const n = Math.min(1, Math.max(0, normalized));
  const c = Math.min(1, Math.max(0, lensCenterNorm));
  const r = Math.max(0, bandRadiusNorm);
  
  if (magnification <= 1 || r === 0) return n;
  
  const a = Math.max(0, c - r);
  const b = Math.min(1, c + r);
  const insideLength = Math.max(0, b - a);
  const outsideLength = a + (1 - b);
  
  if (insideLength === 0 || outsideLength < 0) return n;
  
  const scale = 1 / (outsideLength + insideLength * magnification);
  
  if (n < a) {
    return n * scale;
  } else if (n > b) {
    const base = scale * (a + insideLength * magnification);
    return base + (n - b) * scale;
  } else {
    const base = scale * a;
    return base + (n - a) * magnification * scale;
  }
}

/**
 * Create lens-aware X scale function.
 * @param {Object} params
 * @returns {Function}
 */
export function createLensXScale(params) {
  const { 
    xScale, tsMin, tsMax, xStart, xEnd, toDate,
    getIsLensing, getLensCenter, getLensingMul,
    getHorizontalFisheyeScale, getFisheyeEnabled
  } = params;
  
  return (timestamp) => {
    const minX = xStart;
    const maxX = xEnd;
    
    // Use horizontal fisheye if enabled
    if (getFisheyeEnabled() && getHorizontalFisheyeScale()) {
      const fisheyeX = getHorizontalFisheyeScale().apply(timestamp);
      return Math.max(minX, Math.min(fisheyeX, maxX));
    }
    
    if (!getIsLensing()) {
      const rawX = xScale(toDate(timestamp));
      return Math.max(minX, Math.min(rawX, maxX));
    }
    
    if (tsMax === tsMin) {
      const rawX = xScale(toDate(timestamp));
      return Math.max(minX, Math.min(rawX, maxX));
    }
    
    const normalized = (timestamp - tsMin) / (tsMax - tsMin);
    const totalWidth = xEnd - xStart;
    const lensCenterNorm = (getLensCenter() - tsMin) / (tsMax - tsMin);
    const bandRadiusNorm = 0.045;
    
    const position = applyLens1D(normalized, lensCenterNorm, bandRadiusNorm, getLensingMul());
    const rawX = minX + position * totalWidth;
    return Math.max(minX, Math.min(rawX, maxX));
  };
}

/**
 * Fisheye distortion function (monotonicity-preserving).
 * @param {number} t - Input (0-1)
 * @param {number} focus - Focus point (0-1)
 * @param {number} distortion - Distortion factor
 * @returns {number}
 */
export function fisheyeDistort(t, focus, distortion) {
  if (distortion <= 1) return t;
  
  const delta = t - focus;
  const distance = Math.abs(delta);
  const sign = delta < 0 ? -1 : 1;
  
  if (distance < 0.0001) return t;
  
  const effectRadius = 0.5;
  let scale;
  
  if (distance < effectRadius) {
    const normalized = distance / effectRadius;
    const blend = (1 - Math.cos(normalized * Math.PI)) / 2;
    scale = distortion - (distortion - 1) * blend;
  } else {
    const excessDistance = distance - effectRadius;
    const compressionFactor = 1 / distortion;
    scale = 1 - (1 - compressionFactor) * Math.min(1, excessDistance / (1 - effectRadius));
  }
  
  const distorted = focus + sign * distance * scale;
  return Math.max(0, Math.min(1, distorted));
}

/**
 * Create vertical fisheye scale.
 * @param {Object} params
 * @returns {Object}
 */
export function createFisheyeScale(params) {
  const { sortedIps, originalPositions, marginTop, innerHeight, getDistortion } = params;
  
  return {
    _focus: marginTop + innerHeight / 2,
    _sortedIps: sortedIps,
    
    focus(f) { this._focus = f; return this; },
    
    distortion(d) {
      if (arguments.length === 0) return getDistortion();
      return this;
    },
    
    apply(ip) {
      const idx = this._sortedIps.indexOf(ip);
      if (idx === -1) return originalPositions.get(ip) || marginTop;
      
      const originalY = originalPositions.get(ip);
      if (!originalY) return marginTop;
      
      const t = (originalY - marginTop) / innerHeight;
      const focusT = (this._focus - marginTop) / innerHeight;
      const distortedT = fisheyeDistort(t, focusT, getDistortion());
      
      return marginTop + distortedT * innerHeight;
    }
  };
}

/**
 * Create horizontal fisheye scale for timeline.
 * @param {Object} params
 * @returns {Object}
 */
export function createHorizontalFisheyeScale(params) {
  const { xStart, xEnd, tsMin, tsMax, getDistortion } = params;
  
  return {
    _focus: xStart + (xEnd - xStart) / 2,
    
    focus(f) { this._focus = f; return this; },
    
    distortion(d) {
      if (arguments.length === 0) return getDistortion();
      return this;
    },
    
    apply(timestamp) {
      const totalWidth = xEnd - xStart;
      if (totalWidth <= 0 || tsMax === tsMin) return xStart;
      
      const t = (timestamp - tsMin) / (tsMax - tsMin);
      const focusT = (this._focus - xStart) / totalWidth;
      const distortedT = fisheyeDistort(t, focusT, getDistortion());
      
      return xStart + distortedT * totalWidth;
    }
  };
}
```

### Step 2: Update `attack_timearcs.js`

Add import:
```javascript
import { applyLens1D, createLensXScale, createFisheyeScale, createHorizontalFisheyeScale, fisheyeDistort } from './src/scales/distortion.js';
```

FIND `function applyLens1D` inside render() (around line 932) — DELETE it.

FIND `function xScaleLens` (around line 963) — REPLACE body to use imported `createLensXScale`:
```javascript
const xScaleLens = createLensXScale({
  xScale: x,
  tsMin,
  tsMax,
  xStart,
  xEnd: actualXEnd,
  toDate,
  getIsLensing: () => isLensing,
  getLensCenter: () => lensCenter,
  getLensingMul: () => lensingMul,
  getHorizontalFisheyeScale: () => horizontalFisheyeScale,
  getFisheyeEnabled: () => fisheyeEnabled
});
```

FIND `initFisheye` function (around line 2321) and refactor to use imported creators:
```javascript
function initFisheye() {
  originalRowPositions.clear();
  const ipsToUse = sortedIps && sortedIps.length > 0 ? sortedIps : allIps;
  ipsToUse.forEach(ip => {
    const node = ipToNode.get(ip);
    const currentY = node && node.y !== undefined ? node.y : y(ip);
    originalRowPositions.set(ip, currentY);
  });
  
  fisheyeScale = createFisheyeScale({
    sortedIps: ipsToUse,
    originalPositions: originalRowPositions,
    marginTop: MARGIN.top,
    innerHeight: INNER_HEIGHT,
    getDistortion: () => fisheyeDistortion
  });
  
  horizontalFisheyeScale = createHorizontalFisheyeScale({
    xStart,
    xEnd: actualXEnd,
    tsMin,
    tsMax,
    getDistortion: () => fisheyeDistortion
  });
}
```

DELETE the large inline fisheye scale definitions (around lines 2336-2575).

### Step 3: Test
1. Refresh browser
2. Enable lensing (Shift+L or button)
3. Move mouse — timeline should distort
4. Adjust slider — magnification should change
5. Disable lensing — should reset

### Verification Checklist
- [ ] Lensing toggle works
- [ ] Mouse movement distorts timeline
- [ ] Fisheye distorts vertically
- [ ] Slider changes magnification
- [ ] Reset restores original positions
```

---

## Stage 12: Extract Row Rendering (Working Version)

```
## STAGE 12: Extract Row Rendering — Produces Working Version

### Goal
Extract IP row lines and labels rendering from render().

### Step 1: Create `src/rendering/rows.js`

```javascript
// src/rendering/rows.js
// IP row lines and labels

/**
 * Compute IP activity spans.
 * @param {Object[]} links
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

/**
 * Create span data array for rendering.
 * @param {string[]} ips
 * @param {Map} ipSpans
 * @returns {Array<{ip: string, span: {min, max}|undefined}>}
 */
export function createSpanData(ips, ipSpans) {
  return ips.map(ip => ({ ip, span: ipSpans.get(ip) }));
}

/**
 * Render row lines.
 * @param {d3.Selection} container
 * @param {Array} spanData
 * @param {number} marginLeft
 * @returns {d3.Selection}
 */
export function renderRowLines(container, spanData, marginLeft) {
  return container.selectAll('line')
    .data(spanData)
    .join('line')
    .attr('class', 'row-line')
    .attr('x1', marginLeft)
    .attr('x2', marginLeft)
    .attr('y1', d => 0) // Will be set during animation
    .attr('y2', d => 0)
    .style('opacity', 0);
}

/**
 * Render IP labels.
 * @param {d3.Selection} container
 * @param {string[]} ips
 * @param {Map} ipToNode
 * @param {number} marginLeft
 * @returns {d3.Selection}
 */
export function renderIpLabels(container, ips, ipToNode, marginLeft) {
  return container.selectAll('text')
    .data(ips)
    .join('text')
    .attr('class', 'ip-label')
    .attr('data-ip', d => d)
    .attr('x', d => {
      const node = ipToNode.get(d);
      return node && node.xConnected !== undefined ? node.xConnected : marginLeft;
    })
    .attr('y', d => {
      const node = ipToNode.get(d);
      return node && node.y !== undefined ? node.y : 0;
    })
    .attr('text-anchor', 'end')
    .attr('dominant-baseline', 'middle')
    .style('cursor', 'pointer')
    .text(d => d);
}

/**
 * Attach hover handlers to labels.
 * @param {d3.Selection} labels
 * @param {Object} callbacks
 */
export function attachLabelHoverHandlers(labels, callbacks) {
  const { onHover, onMove, onLeave } = callbacks;
  
  labels
    .on('mouseover', function(event, ip) {
      onHover(event, ip, this);
    })
    .on('mousemove', function(event) {
      onMove(event);
    })
    .on('mouseout', function() {
      onLeave();
    });
}

/**
 * Update row lines for animation.
 * @param {d3.Selection} lines
 * @param {Function} xScale
 * @param {Function} yScale
 * @param {number} duration
 */
export function animateRowLines(lines, xScale, yScale, duration) {
  return lines
    .transition()
    .duration(duration)
    .attr('x1', d => d.span ? xScale(d.span.min) : 0)
    .attr('x2', d => d.span ? xScale(d.span.max) : 0)
    .attr('y1', d => yScale(d.ip))
    .attr('y2', d => yScale(d.ip))
    .style('opacity', 1);
}

/**
 * Update labels for animation.
 * @param {d3.Selection} labels
 * @param {Function} yScale
 * @param {Map} ipToNode
 * @param {number} duration
 */
export function animateLabels(labels, yScale, ipToNode, duration) {
  return labels
    .transition()
    .duration(duration)
    .attr('y', d => yScale(d))
    .attr('x', d => {
      const node = ipToNode.get(d);
      return node && node.xConnected !== undefined ? node.xConnected : 0;
    });
}
```

### Step 2: Update `attack_timearcs.js`

Add import:
```javascript
import { computeIpSpans, createSpanData, renderRowLines, renderIpLabels, attachLabelHoverHandlers, animateRowLines, animateLabels } from './src/rendering/rows.js';
```

FIND IP spans calculation (around line 1081-1088):
```javascript
// Old:
const ipSpans = new Map();
for (const l of links) {
  for (const ip of [l.source, l.target]) { ... }
}
```
REPLACE with:
```javascript
const ipSpans = computeIpSpans(links);
```

FIND span data creation (around line 1091):
```javascript
// Old:
const spanData = allIps.map(ip => ({ ip, span: ipSpans.get(ip) }));
```
REPLACE with:
```javascript
const spanData = createSpanData(allIps, ipSpans);
```

FIND row lines rendering (around line 1093-1101) and use `renderRowLines`.

FIND labels rendering (around line 1159-1178) and use `renderIpLabels`.

FIND label hover handlers (around line 1367-1438) — extract the handler logic and use `attachLabelHoverHandlers`.

### Step 3: Test
1. Refresh browser
2. Verify IP labels display on left
3. Hover IP label — connected arcs highlight
4. Row lines visible from first to last activity

### Verification Checklist
- [ ] Labels positioned correctly
- [ ] Row lines span activity range
- [ ] Label hover highlights arcs
- [ ] Tooltip shows on label hover
```

---

## Stage 13: Extract Arc Event Handlers (Working Version)

```
## STAGE 13: Extract Arc Event Handlers — Produces Working Version

### Goal
Extract arc mouseover/mouseout handlers from render().

### Step 1: Create `src/rendering/arcInteractions.js`

```javascript
// src/rendering/arcInteractions.js
// Arc hover and interaction logic

/**
 * Create arc hover handler.
 * @param {Object} config
 * @returns {Function}
 */
export function createArcHoverHandler(config) {
  const { 
    arcPaths, svg, ipToNode, widthScale, 
    xScaleLens, yScaleLens, colorForAttack,
    showTooltip, labelMode, toDate, timeFormatter,
    looksAbsolute, unitSuffix, base
  } = config;
  
  return function(event, d) {
    const xp = xScaleLens(d.minute);
    const y1 = yScaleLens(d.sourceNode.name);
    const y2 = yScaleLens(d.targetNode.name);
    
    if (!isFinite(xp) || !isFinite(y1) || !isFinite(y2)) return;
    
    // Highlight this arc
    arcPaths.style('stroke-opacity', p => (p === d ? 1 : 0.3));
    const baseW = widthScale(Math.max(1, d.count));
    d3.select(this)
      .attr('stroke-width', Math.max(3, baseW < 2 ? baseW * 3 : baseW * 1.5))
      .raise();
    
    // Highlight connected elements
    const active = new Set([d.sourceNode.name, d.targetNode.name]);
    
    svg.selectAll('.row-line')
      .attr('stroke-opacity', s => s && s.ip && active.has(s.ip) ? 0.8 : 0.1)
      .attr('stroke-width', s => s && s.ip && active.has(s.ip) ? 1 : 0.4);
    
    const attackCol = colorForAttack(
      (labelMode === 'attack_group' ? d.attack_group : d.attack) || 'normal'
    );
    
    svg.selectAll('.ip-label')
      .attr('font-weight', s => active.has(s) ? 'bold' : null)
      .style('font-size', s => active.has(s) ? '14px' : null)
      .style('fill', s => active.has(s) ? attackCol : '#343a40')
      .filter(s => active.has(s))
      .transition()
      .duration(200)
      .attr('x', xp)
      .attr('y', s => {
        const node = ipToNode.get(s);
        return node && node.y !== undefined ? node.y : 0;
      });
    
    // Show tooltip
    const dt = toDate(d.minute);
    const timeStr = looksAbsolute ? timeFormatter(dt) : `t=${d.minute - base} ${unitSuffix}`;
    const content = `${d.sourceNode.name} → ${d.targetNode.name}<br>` +
      (labelMode === 'attack_group' 
        ? `Attack Group: ${d.attack_group || 'normal'}<br>` 
        : `Attack: ${d.attack || 'normal'}<br>`) +
      `${timeStr}<br>count=${d.count}`;
    
    showTooltip(event, content);
  };
}

/**
 * Create arc mouseout handler.
 * @param {Object} config
 * @returns {Function}
 */
export function createArcLeaveHandler(config) {
  const { arcPaths, svg, ipToNode, widthScale, hideTooltip } = config;
  
  return function() {
    hideTooltip();
    
    arcPaths
      .style('stroke-opacity', 0.6)
      .attr('stroke-width', d => widthScale(Math.max(1, d.count)));
    
    svg.selectAll('.row-line')
      .attr('stroke-opacity', 1)
      .attr('stroke-width', 0.4);
    
    svg.selectAll('.ip-label')
      .attr('font-weight', null)
      .style('font-size', null)
      .style('fill', '#343a40')
      .transition()
      .duration(200)
      .attr('x', s => {
        const node = ipToNode.get(s);
        return node && node.xConnected !== undefined ? node.xConnected : 0;
      })
      .attr('y', s => {
        const node = ipToNode.get(s);
        return node && node.y !== undefined ? node.y : 0;
      });
  };
}

/**
 * Attach handlers to arc paths.
 * @param {d3.Selection} arcPaths
 * @param {Function} hoverHandler
 * @param {Function} moveHandler
 * @param {Function} leaveHandler
 */
export function attachArcHandlers(arcPaths, hoverHandler, moveHandler, leaveHandler) {
  arcPaths
    .on('mouseover', hoverHandler)
    .on('mousemove', moveHandler)
    .on('mouseout', leaveHandler);
}
```

### Step 2: Update `attack_timearcs.js`

Add import:
```javascript
import { createArcHoverHandler, createArcLeaveHandler, attachArcHandlers } from './src/rendering/arcInteractions.js';
```

FIND arc event handlers (around line 1259-1359).

REPLACE inline handlers with:
```javascript
const arcHoverHandler = createArcHoverHandler({
  arcPaths,
  svg,
  ipToNode,
  widthScale,
  xScaleLens,
  yScaleLens: (ip) => yScaleLens(ip),
  colorForAttack,
  showTooltip: (evt, html) => showTooltip(tooltip, evt, html),
  labelMode,
  toDate,
  timeFormatter: utcTick,
  looksAbsolute,
  unitSuffix,
  base
});

const arcMoveHandler = (event) => {
  if (tooltip && tooltip.style.display !== 'none') {
    const pad = 10;
    tooltip.style.left = (event.clientX + pad) + 'px';
    tooltip.style.top = (event.clientY + pad) + 'px';
  }
};

const arcLeaveHandler = createArcLeaveHandler({
  arcPaths,
  svg,
  ipToNode,
  widthScale,
  hideTooltip: () => hideTooltip(tooltip)
});

attachArcHandlers(arcPaths, arcHoverHandler, arcMoveHandler, arcLeaveHandler);
```

DELETE the inline `.on('mouseover', ...)` handler code.

### Step 3: Test
1. Refresh browser
2. Hover an arc — endpoints should highlight
3. Labels should move to arc position
4. Tooltip should follow mouse
5. Mouseout should restore everything

### Verification Checklist
- [ ] Arc highlight works
- [ ] Connected labels highlight
- [ ] Labels animate to arc position
- [ ] Tooltip displays correctly
- [ ] Mouseout restores state
```

---

## Stage 14: Extract Map Loaders (Working Version)

```
## STAGE 14: Extract Map Loaders — Final Stage

### Goal
Extract JSON map loading functions from outside render().

### Step 1: Create `src/mappings/loaders.js`

```javascript
// src/mappings/loaders.js
// Async map loading functions

/**
 * Load JSON file with cache disabled.
 * @param {string} path
 * @returns {Promise<Object>}
 */
async function loadJson(path) {
  const res = await fetch(path, { cache: 'no-store' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

/**
 * Load IP mapping (id ↔ address).
 * @param {string} path
 * @returns {Promise<Map<number, string>>}
 */
export async function loadIpMap(path = './full_ip_map.json') {
  try {
    const obj = await loadJson(path);
    const rev = new Map();
    for (const [ip, id] of Object.entries(obj)) {
      const num = Number(id);
      if (Number.isFinite(num)) {
        rev.set(num, ip);
      }
    }
    console.log(`IP map loaded: ${rev.size} entries`);
    return rev;
  } catch (err) {
    console.warn('Failed to load IP map:', err);
    return null;
  }
}

/**
 * Load event type mapping.
 * @param {string} path
 * @returns {Promise<Map<number, string>>}
 */
export async function loadEventTypeMap(path = './event_type_mapping.json') {
  try {
    const obj = await loadJson(path);
    const rev = new Map();
    for (const [name, id] of Object.entries(obj)) {
      const num = Number(id);
      if (Number.isFinite(num)) rev.set(num, name);
    }
    return rev;
  } catch (err) {
    console.warn('Failed to load event type map:', err);
    return null;
  }
}

/**
 * Load color mapping.
 * @param {string} path
 * @param {Function} canonicalize
 * @returns {Promise<{raw: Map, canonical: Map}>}
 */
export async function loadColorMapping(path, canonicalize) {
  try {
    const obj = await loadJson(path);
    const raw = new Map(Object.entries(obj));
    const canonical = new Map();
    for (const [name, col] of Object.entries(obj)) {
      canonical.set(canonicalize(name), col);
    }
    return { raw, canonical };
  } catch (err) {
    console.warn('Failed to load color mapping:', path, err);
    return { raw: null, canonical: null };
  }
}

/**
 * Load attack group mapping.
 * @param {string} path
 * @returns {Promise<Map<number, string>>}
 */
export async function loadAttackGroupMap(path = './attack_group_mapping.json') {
  try {
    const obj = await loadJson(path);
    const entries = Object.entries(obj);
    const rev = new Map();
    
    if (entries.length) {
      let nameToId = 0, idToName = 0;
      for (const [k, v] of entries.slice(0, 10)) {
        if (typeof v === 'number') nameToId++;
        if (!isNaN(+k) && typeof v === 'string') idToName++;
      }
      
      if (nameToId >= idToName) {
        for (const [name, id] of entries) {
          const num = Number(id);
          if (Number.isFinite(num)) rev.set(num, name);
        }
      } else {
        for (const [idStr, name] of entries) {
          const num = Number(idStr);
          if (Number.isFinite(num) && typeof name === 'string') rev.set(num, name);
        }
      }
    }
    return rev;
  } catch (err) {
    console.warn('Failed to load attack group map:', err);
    return null;
  }
}

/**
 * Load all mappings concurrently.
 * @param {Function} canonicalize
 * @returns {Promise<Object>}
 */
export async function loadAllMappings(canonicalize) {
  const [ipMap, eventMap, colorMap, groupMap, groupColorMap] = await Promise.all([
    loadIpMap(),
    loadEventTypeMap(),
    loadColorMapping('./color_mapping.json', canonicalize),
    loadAttackGroupMap(),
    loadColorMapping('./attack_group_color_mapping.json', canonicalize),
  ]);
  
  return {
    ipIdToAddr: ipMap,
    attackIdToName: eventMap,
    colorByAttack: colorMap.canonical,
    rawColorByAttack: colorMap.raw,
    attackGroupIdToName: groupMap,
    colorByAttackGroup: groupColorMap.canonical,
    rawColorByAttackGroup: groupColorMap.raw,
  };
}
```

### Step 2: Update `attack_timearcs.js`

Add import:
```javascript
import { loadIpMap, loadEventTypeMap, loadColorMapping, loadAttackGroupMap, loadAllMappings } from './src/mappings/loaders.js';
```

FIND the async loading functions (around lines 3254-3423):
- `async function loadIpMap()`
- `async function loadEventTypeMap()`
- `async function loadColorMapping()`
- `async function loadAttackGroupMap()`
- `async function loadAttackGroupColorMapping()`

DELETE all of them.

FIND the init function (around line 166):
```javascript
(async function init() {
  try {
    await Promise.all([
      loadIpMap(),
      loadEventTypeMap(),
      ...
    ]);
  } catch (_) {}
  tryLoadDefaultCsv();
})();
```

REPLACE with:
```javascript
(async function init() {
  try {
    const mappings = await loadAllMappings(canonicalizeName);
    ipIdToAddr = mappings.ipIdToAddr;
    ipMapLoaded = ipIdToAddr !== null && ipIdToAddr.size > 0;
    attackIdToName = mappings.attackIdToName;
    colorByAttack = mappings.colorByAttack;
    rawColorByAttack = mappings.rawColorByAttack;
    attackGroupIdToName = mappings.attackGroupIdToName;
    colorByAttackGroup = mappings.colorByAttackGroup;
    rawColorByAttackGroup = mappings.rawColorByAttackGroup;
    
    if (ipMapLoaded) {
      setStatus(statusEl, `IP map loaded (${ipIdToAddr.size} entries). Upload CSV to render.`);
    }
  } catch (err) {
    console.warn('Mapping load failed:', err);
  }
  tryLoadDefaultCsv();
})();
```

### Step 3: Final Test — Full Checklist

Run through EVERYTHING:

**Loading**
- [ ] Page loads without errors
- [ ] IP map loads automatically
- [ ] Event type map loads
- [ ] Color mappings load
- [ ] Default CSV loads (if present)

**CSV Upload**
- [ ] Single file upload works
- [ ] Multiple file upload works
- [ ] Status shows correct counts
- [ ] Custom IP map upload works
- [ ] Custom event map upload works

**Visualization**  
- [ ] Arcs render correctly
- [ ] Arc colors match attacks
- [ ] Gradients visible
- [ ] IP labels positioned
- [ ] Timeline axis correct

**Interactions**
- [ ] Arc hover highlights
- [ ] Arc hover tooltip
- [ ] Label hover highlights
- [ ] Legend click toggles
- [ ] Legend double-click isolates
- [ ] Lensing works
- [ ] Fisheye works
- [ ] Slider adjusts magnification

**Animation**
- [ ] Initial layout animates
- [ ] Timeline transition smooth
- [ ] Lens updates animate

### You're Done! 🎉

Final structure:
```
src/
├── config/
│   └── constants.js
├── data/
│   ├── aggregation.js
│   └── csvParser.js
├── layout/
│   └── forceSimulation.js
├── mappings/
│   ├── decoders.js
│   └── loaders.js
├── rendering/
│   ├── arcInteractions.js
│   ├── arcPath.js
│   └── rows.js
├── scales/
│   ├── distortion.js
│   └── scaleFactory.js
├── ui/
│   └── legend.js
└── utils/
    └── helpers.js
```

Main file: ~800-1000 lines (orchestration + render flow)
Modules: ~1,400 lines across 12 files
```

---

## Summary: All 14 Stages

| Stage | Module | Lines | Risk |
|-------|--------|-------|------|
| 1 | constants.js | ~30 | Low |
| 2 | helpers.js | ~80 | Low |
| 3 | decoders.js | ~100 | Low |
| 4 | aggregation.js | ~150 | Medium |
| 5 | arcPath.js | ~30 | Low |
| 6 | legend.js | ~120 | Medium |
| 7 | csvParser.js | ~100 | Medium |
| 8 | Cleanup | — | Low |
| 9 | scaleFactory.js | ~120 | Medium |
| 10 | forceSimulation.js | ~180 | High |
| 11 | distortion.js | ~200 | High |
| 12 | rows.js | ~120 | Medium |
| 13 | arcInteractions.js | ~150 | Medium |
| 14 | loaders.js | ~120 | Low |

**Total extracted: ~1,500 lines into 12 modules**
**Remaining main file: ~800-1000 lines**
