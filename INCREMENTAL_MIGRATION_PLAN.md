# Incremental Migration: DuckDB + Parquet + deck.gl

## Guiding Principle

**Every step produces a working system.** The old and new code paths coexist, controlled by feature flags. You can ship at any checkpoint.

---

## Architecture Layers

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LAYER INDEPENDENCE                                   │
│                                                                              │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐                   │
│   │    DATA     │     │   QUERY     │     │   RENDER    │                   │
│   │   FORMAT    │     │   ENGINE    │     │   ENGINE    │                   │
│   └─────────────┘     └─────────────┘     └─────────────┘                   │
│         │                   │                   │                            │
│   CSV ──┼── Parquet   JS ───┼── DuckDB    D3 ──┼── deck.gl                  │
│         │                   │                   │                            │
│         ▼                   ▼                   ▼                            │
│   (migrate first)    (migrate second)   (migrate third)                     │
│                                                                              │
│   Each layer can be migrated independently.                                 │
│   Mix and match: Parquet + JS queries + D3 rendering works fine.            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Data Format (Parquet alongside CSV)

**Goal**: Generate Parquet files without changing any browser code.

**Risk**: Zero. Existing code ignores new files.

### Step 1.1: Add Parquet Export to Python Loader

```python
# tcp_data_loader_chunked.py - ADD to existing code, don't modify

import duckdb  # pip install duckdb

def export_parquet(csv_path, output_dir):
    """Export CSV to Parquet format alongside existing outputs."""
    parquet_path = os.path.join(output_dir, 'packets.parquet')

    con = duckdb.connect()
    con.execute(f"""
        COPY (
            SELECT * FROM read_csv('{csv_path}', header=true)
            ORDER BY timestamp
        ) TO '{parquet_path}' (FORMAT PARQUET, COMPRESSION ZSTD)
    """)
    con.close()

    print(f"Exported Parquet: {parquet_path}")
    return parquet_path

# Call at end of existing main():
if __name__ == '__main__':
    # ... existing code ...

    # NEW: Also export Parquet (optional, behind flag)
    if args.export_parquet:
        export_parquet(args.data, args.output_dir)
```

### Step 1.2: Update Manifest

```json
{
  "format": "chunked",
  "version": "2.1",

  "parquet": {
    "available": true,
    "file": "packets.parquet",
    "sizeBytes": 52000000
  }
}
```

### Checkpoint 1

```
output_folder/
├── manifest.json           # Updated with parquet info
├── packets.csv             # Existing (unchanged)
├── packets.parquet         # NEW (ignored by current code)
├── flows/                  # Existing (unchanged)
└── ...
```

**Verification**: Existing visualization works exactly as before.

---

## Phase 2: Add DuckDB Query Engine (Behind Feature Flag)

**Goal**: Load Parquet in browser, query with DuckDB, but still render with D3.

**Risk**: Low. New code path is opt-in via URL parameter.

### Step 2.1: Create DuckDB Wrapper Module

```javascript
// src/data/duckdb-loader.js - NEW FILE

import * as duckdb from 'https://cdn.jsdelivr.net/npm/@duckdb/duckdb-wasm@1.28.0/+esm';

let db = null;
let conn = null;

export async function initDuckDB() {
    if (db) return { db, conn };

    const JSDELIVR_BUNDLES = duckdb.getJsDelivrBundles();
    const bundle = await duckdb.selectBundle(JSDELIVR_BUNDLES);

    const worker = new Worker(bundle.mainWorker);
    const logger = new duckdb.ConsoleLogger(duckdb.LogLevel.WARNING);

    db = new duckdb.AsyncDuckDB(logger, worker);
    await db.instantiate(bundle.mainModule, bundle.pthreadWorker);

    conn = await db.connect();

    return { db, conn };
}

export async function loadParquetFile(folderHandle) {
    const { db, conn } = await initDuckDB();

    // Get parquet file from folder
    const fileHandle = await folderHandle.getFileHandle('packets.parquet');
    const file = await fileHandle.getFile();
    const buffer = await file.arrayBuffer();

    // Register with DuckDB
    await db.registerFileBuffer('packets.parquet', new Uint8Array(buffer));

    // Create view
    await conn.query(`CREATE VIEW packets AS SELECT * FROM 'packets.parquet'`);

    // Get metadata
    const extent = await conn.query(`
        SELECT MIN(timestamp) as min_t, MAX(timestamp) as max_t, COUNT(*) as count
        FROM packets
    `);

    return {
        timeExtent: [extent.get(0).min_t, extent.get(0).max_t],
        packetCount: extent.get(0).count,
        conn
    };
}

export async function queryAggregated(conn, timeRange, binCount = 300) {
    const [start, end] = timeRange;
    const binSize = Math.max(1, Math.floor((end - start) / binCount));

    const result = await conn.query(`
        SELECT
            (timestamp / ${binSize}) * ${binSize} AS bin_start,
            src_ip,
            dst_ip,
            flags,
            COUNT(*) AS packet_count,
            SUM(length) AS total_bytes
        FROM packets
        WHERE timestamp BETWEEN ${start} AND ${end}
        GROUP BY bin_start, src_ip, dst_ip, flags
        ORDER BY bin_start
    `);

    return result.toArray().map(row => ({
        timestamp: Number(row.bin_start),
        src_ip: row.src_ip,
        dst_ip: row.dst_ip,
        flags: row.flags,
        count: Number(row.packet_count),
        totalBytes: Number(row.total_bytes),
        binned: true
    }));
}

export async function queryDetail(conn, timeRange, limit = 50000) {
    const [start, end] = timeRange;

    const result = await conn.query(`
        SELECT *
        FROM packets
        WHERE timestamp BETWEEN ${start} AND ${end}
        ORDER BY timestamp
        LIMIT ${limit}
    `);

    return result.toArray().map(row => ({
        timestamp: Number(row.timestamp),
        src_ip: row.src_ip,
        dst_ip: row.dst_ip,
        src_port: row.src_port,
        dst_port: row.dst_port,
        flags: row.flags,
        length: row.length,
        protocol: row.protocol
    }));
}
```

### Step 2.2: Create Unified Data Source Interface

```javascript
// src/data/data-source.js - NEW FILE

import { FolderLoader } from '../../folder_loader.js';
import * as DuckDBLoader from './duckdb-loader.js';

export class DataSource {
    constructor() {
        this.mode = 'legacy';  // 'legacy' or 'duckdb'
        this.folderLoader = new FolderLoader();
        this.duckdbConn = null;
        this.timeExtent = null;
    }

    async init(folderHandle, options = {}) {
        // Check URL param or option for mode
        const useDuckDB = options.useDuckDB ??
            new URLSearchParams(location.search).has('duckdb');

        if (useDuckDB) {
            try {
                console.log('Initializing DuckDB mode...');
                const result = await DuckDBLoader.loadParquetFile(folderHandle);
                this.duckdbConn = result.conn;
                this.timeExtent = result.timeExtent;
                this.mode = 'duckdb';
                console.log(`DuckDB mode active: ${result.packetCount} packets`);
            } catch (err) {
                console.warn('DuckDB init failed, falling back to legacy:', err);
                this.mode = 'legacy';
            }
        }

        if (this.mode === 'legacy') {
            this.folderLoader.folderHandle = folderHandle;
            await this.folderLoader.loadManifest();
            await this.folderLoader.loadPackets();
            this.timeExtent = this._computeTimeExtent(this.folderLoader.packets);
        }

        return { mode: this.mode, timeExtent: this.timeExtent };
    }

    async getAggregatedData(timeRange, binCount = 300) {
        if (this.mode === 'duckdb') {
            return DuckDBLoader.queryAggregated(this.duckdbConn, timeRange, binCount);
        } else {
            // Use existing binning logic
            return this._legacyBinPackets(timeRange, binCount);
        }
    }

    async getDetailData(timeRange, limit = 50000) {
        if (this.mode === 'duckdb') {
            return DuckDBLoader.queryDetail(this.duckdbConn, timeRange, limit);
        } else {
            return this._legacyFilterPackets(timeRange, limit);
        }
    }

    // Wrap existing logic
    _legacyBinPackets(timeRange, binCount) {
        const packets = this.folderLoader.packets.filter(
            p => p.timestamp >= timeRange[0] && p.timestamp <= timeRange[1]
        );
        // Call existing binPackets from src/data/binning.js
        return binPackets(packets, { /* existing options */ });
    }

    _legacyFilterPackets(timeRange, limit) {
        return this.folderLoader.packets
            .filter(p => p.timestamp >= timeRange[0] && p.timestamp <= timeRange[1])
            .slice(0, limit);
    }

    _computeTimeExtent(packets) {
        if (!packets.length) return [0, 0];
        let min = Infinity, max = -Infinity;
        for (const p of packets) {
            if (p.timestamp < min) min = p.timestamp;
            if (p.timestamp > max) max = p.timestamp;
        }
        return [min, max];
    }
}

export const dataSource = new DataSource();
```

### Step 2.3: Integrate into Existing Visualization

```javascript
// ip_bar_diagram.js - MINIMAL CHANGES

import { dataSource } from './src/data/data-source.js';

// In initialization, replace direct folder loader usage:
async function initVisualization(folderHandle) {
    // OLD: await folderLoader.loadPackets();
    // NEW:
    const { mode, timeExtent } = await dataSource.init(folderHandle);
    console.log(`Data source: ${mode}`);

    // Rest of initialization unchanged...
}

// In zoom handler, use unified interface:
async function onZoomEnd(domain) {
    // OLD: const binned = binPackets(filteredData, options);
    // NEW:
    const binned = await dataSource.getAggregatedData(domain, GLOBAL_BIN_COUNT);

    // Rendering code unchanged - still uses D3
    renderCirclesWithOptions(layer, binned, rScale);
}
```

### Checkpoint 2

**Testing**:
```bash
# Legacy mode (default)
open index.html

# DuckDB mode
open index.html?duckdb
```

Both modes produce identical visualizations. DuckDB mode is faster for large datasets.

---

## Phase 3: Add deck.gl Rendering Layer (Behind Feature Flag)

**Goal**: Use WebGL for data points while keeping D3 for axes and UI.

**Risk**: Low. New rendering is opt-in, D3 code unchanged.

### Step 3.1: Create deck.gl Overlay Module

```javascript
// src/rendering/deckgl-overlay.js - NEW FILE

import { Deck } from 'https://cdn.jsdelivr.net/npm/deck.gl@9.0.0/+esm';
import { ScatterplotLayer } from 'https://cdn.jsdelivr.net/npm/@deck.gl/layers@9.0.0/+esm';

export class DeckGLOverlay {
    constructor(container, options = {}) {
        this.container = container;
        this.xScale = options.xScale;
        this.yScale = options.yScale;
        this.flagColors = options.flagColors || {};

        this.deck = null;
        this.enabled = false;
    }

    init() {
        // Create overlay container
        this.overlayDiv = document.createElement('div');
        this.overlayDiv.style.cssText = `
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
        `;
        this.container.appendChild(this.overlayDiv);

        // Initialize deck.gl with orthographic view
        this.deck = new Deck({
            parent: this.overlayDiv,
            views: new OrthographicView({ id: 'ortho' }),
            controller: false,  // D3 handles zoom
            style: { background: 'transparent' }
        });

        this.enabled = true;
    }

    updateData(binned, domain) {
        if (!this.enabled || !this.deck) return;

        const xScale = this.xScale;
        const yPositions = this.yScale;
        const flagColors = this.flagColors;

        // Transform data to deck.gl format
        const data = binned.map(d => ({
            position: [xScale(d.timestamp), yPositions.get(d.yPos) || 0],
            radius: Math.sqrt(d.count) * 3,
            color: this._flagToColor(d.flagType)
        }));

        this.deck.setProps({
            layers: [
                new ScatterplotLayer({
                    id: 'packets',
                    data,
                    getPosition: d => d.position,
                    getRadius: d => d.radius,
                    getFillColor: d => d.color,
                    radiusUnits: 'pixels',
                    transitions: {
                        getPosition: 200,
                        getRadius: 200
                    }
                })
            ]
        });
    }

    syncWithD3Zoom(transform) {
        if (!this.enabled || !this.deck) return;

        // Update deck.gl viewport to match D3 zoom
        this.deck.setProps({
            viewState: {
                target: [transform.x, transform.y],
                zoom: Math.log2(transform.k)
            }
        });
    }

    destroy() {
        if (this.deck) {
            this.deck.finalize();
            this.deck = null;
        }
        if (this.overlayDiv) {
            this.overlayDiv.remove();
        }
        this.enabled = false;
    }

    _flagToColor(flagType) {
        const hex = this.flagColors[flagType] || '#888888';
        // Convert hex to RGBA array for deck.gl
        const r = parseInt(hex.slice(1, 3), 16);
        const g = parseInt(hex.slice(3, 5), 16);
        const b = parseInt(hex.slice(5, 7), 16);
        return [r, g, b, 200];
    }
}
```

### Step 3.2: Integrate with Existing Rendering

```javascript
// ip_bar_diagram.js - ADD to existing code

import { DeckGLOverlay } from './src/rendering/deckgl-overlay.js';

let deckOverlay = null;
const useWebGL = new URLSearchParams(location.search).has('webgl');

function initVisualization(container) {
    // Existing D3 setup...
    svg = d3.select(container).append('svg');
    // ...

    // NEW: Initialize deck.gl overlay if enabled
    if (useWebGL) {
        deckOverlay = new DeckGLOverlay(container, {
            xScale,
            yScale: ipPositions,
            flagColors
        });
        deckOverlay.init();
    }
}

function renderData(binned) {
    if (useWebGL && deckOverlay) {
        // Use deck.gl for data points
        deckOverlay.updateData(binned, xScale.domain());

        // D3 still renders axes, legends, arcs
        renderAxes();
        renderLegends();
        renderArcs();  // Could also migrate to deck.gl later
    } else {
        // Legacy D3 rendering (unchanged)
        renderCirclesWithOptions(layer, binned, rScale);
    }
}

// In zoom handler
function onZoom(event) {
    // Existing D3 zoom handling...

    // NEW: Sync deck.gl if active
    if (useWebGL && deckOverlay) {
        deckOverlay.syncWithD3Zoom(event.transform);
    }
}
```

### Checkpoint 3

**Testing**:
```bash
# Legacy rendering
open index.html

# DuckDB + D3 rendering
open index.html?duckdb

# DuckDB + WebGL rendering
open index.html?duckdb&webgl

# Legacy data + WebGL rendering (also works!)
open index.html?webgl
```

All four combinations work correctly.

---

## Phase 4: Performance Optimization

**Goal**: Enable WebGL by default for large datasets, keep D3 for small ones.

### Step 4.1: Auto-Detection Logic

```javascript
// src/config/feature-flags.js - NEW FILE

export function detectOptimalMode(packetCount) {
    // URL params override auto-detection
    const params = new URLSearchParams(location.search);
    if (params.has('legacy')) return { useDuckDB: false, useWebGL: false };
    if (params.has('duckdb')) return { useDuckDB: true, useWebGL: params.has('webgl') };

    // Auto-detect based on dataset size
    if (packetCount > 100000) {
        return { useDuckDB: true, useWebGL: true };
    } else if (packetCount > 10000) {
        return { useDuckDB: true, useWebGL: false };
    } else {
        return { useDuckDB: false, useWebGL: false };
    }
}

export function showModeIndicator(mode) {
    const indicator = document.createElement('div');
    indicator.className = 'mode-indicator';
    indicator.textContent = mode.useDuckDB
        ? (mode.useWebGL ? '⚡ DuckDB + WebGL' : '⚡ DuckDB')
        : '📊 Legacy';
    indicator.style.cssText = `
        position: fixed;
        bottom: 10px;
        right: 10px;
        padding: 4px 8px;
        background: rgba(0,0,0,0.7);
        color: white;
        border-radius: 4px;
        font-size: 12px;
    `;
    document.body.appendChild(indicator);
}
```

### Step 4.2: Graceful Degradation

```javascript
// src/data/data-source.js - ENHANCE

export class DataSource {
    async init(folderHandle, options = {}) {
        // Check if Parquet file exists
        let hasParquet = false;
        try {
            await folderHandle.getFileHandle('packets.parquet');
            hasParquet = true;
        } catch {
            console.log('No Parquet file, using legacy mode');
        }

        // Check WebGL support
        const hasWebGL = !!document.createElement('canvas').getContext('webgl2');

        // Determine mode
        const mode = detectOptimalMode(options.estimatedPackets || 0);

        if (mode.useDuckDB && !hasParquet) {
            console.warn('DuckDB requested but no Parquet file, falling back');
            mode.useDuckDB = false;
        }

        if (mode.useWebGL && !hasWebGL) {
            console.warn('WebGL requested but not supported, falling back');
            mode.useWebGL = false;
        }

        // Initialize based on mode
        // ... rest of init
    }
}
```

### Checkpoint 4

System automatically selects optimal mode based on:
1. Dataset size
2. Browser capabilities
3. Available file formats

Users can override via URL params for testing.

---

## Phase 5: Cleanup (Optional)

**Goal**: Remove legacy code paths after confidence is established.

**Timeline**: Only after production validation (weeks/months).

### Step 5.1: Mark Legacy as Deprecated

```javascript
// folder_loader.js - ADD deprecation notices

/**
 * @deprecated Use DataSource with DuckDB mode instead.
 * This class is maintained for backward compatibility only.
 */
export class FolderLoader {
    constructor() {
        console.warn('FolderLoader is deprecated. Use DataSource with ?duckdb param.');
        // ...
    }
}
```

### Step 5.2: Remove Legacy (When Ready)

```bash
# Only after:
# 1. All users have Parquet files generated
# 2. No bug reports from DuckDB mode
# 3. Performance metrics confirm improvement

git rm folder_loader.js
git rm src/data/binning.js  # Replaced by SQL aggregation
git rm -r chunks/           # No longer needed
```

---

## Summary: What Changes at Each Phase

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MIGRATION SUMMARY                                    │
│                                                                              │
│   Phase   New Files              Modified Files       Breaking Changes       │
│   ─────   ─────────              ──────────────       ────────────────       │
│   1       tcp_loader (adds       manifest.json        None                   │
│           Parquet export)        (optional field)                            │
│                                                                              │
│   2       src/data/duckdb-       ip_bar_diagram.js    None                   │
│           loader.js              (2-3 lines)                                 │
│           src/data/data-                                                     │
│           source.js                                                          │
│                                                                              │
│   3       src/rendering/         ip_bar_diagram.js    None                   │
│           deckgl-overlay.js      (5-10 lines)                                │
│                                                                              │
│   4       src/config/            data-source.js       None                   │
│           feature-flags.js       (enhancement)                               │
│                                                                              │
│   5       (deletions only)       -                    Removes legacy         │
│                                                       (optional)             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Testing Strategy

Each phase has parallel paths that can be A/B tested:

```javascript
// In browser console or test scripts:

// Compare data output
const legacyData = await dataSource.getAggregatedData(range);  // mode: legacy
const duckdbData = await dataSource.getAggregatedData(range);  // mode: duckdb
assert(deepEqual(legacyData, duckdbData), 'Data mismatch!');

// Compare performance
console.time('legacy');
await legacyRender(data);
console.timeEnd('legacy');

console.time('webgl');
await webglRender(data);
console.timeEnd('webgl');
```

---

## Rollback Plan

At any phase, rolling back is trivial:

```javascript
// Option 1: URL param
window.location.search = '?legacy';

// Option 2: Feature flag in config
localStorage.setItem('forceLeaacyMode', 'true');

// Option 3: Remove new files, git revert the 2-3 changed lines
git checkout HEAD~1 -- ip_bar_diagram.js
```

The legacy code is never deleted until you're confident (Phase 5).
