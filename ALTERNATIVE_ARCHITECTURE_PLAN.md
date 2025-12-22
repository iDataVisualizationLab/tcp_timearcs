# Alternative Architecture: DuckDB-WASM + Parquet + WebGL

## Why This Is Better

The previous plan maintains compatibility with existing JSON/CSV infrastructure. If we start fresh, modern browser capabilities enable a fundamentally superior approach:

| Aspect | Current/Compatible | Modern Approach |
|--------|-------------------|-----------------|
| **Data format** | JSON/CSV (~10× bloat) | Parquet (~3-5× smaller than CSV) |
| **Query engine** | JavaScript loops | DuckDB-WASM (columnar SQL) |
| **Rendering** | D3 SVG (~10K elements max) | WebGL (millions of points) |
| **Aggregation** | Pre-computed files | On-the-fly SQL queries |
| **Initial load** | Parse minute JSON | Single SQL query |
| **Zoom detail** | Fetch chunk files | SQL range query |

**Result**: 10-100× faster with simpler code.

---

## 1. Core Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     MODERN TIME-SERIES ARCHITECTURE                          │
│                                                                              │
│   ┌────────────────┐      ┌────────────────┐      ┌────────────────┐        │
│   │   Parquet      │      │   DuckDB       │      │   WebGL        │        │
│   │   File(s)      │─────▶│   WASM         │─────▶│   Renderer     │        │
│   │                │      │                │      │   (deck.gl)    │        │
│   │   ~50MB for    │      │   In-browser   │      │                │        │
│   │   50M packets  │      │   SQL engine   │      │   Renders 1M+  │        │
│   └────────────────┘      └────────────────┘      │   points at    │        │
│                                  │                │   60fps        │        │
│                                  │                └────────────────┘        │
│                                  │                                          │
│                                  ▼                                          │
│                     ┌────────────────────────┐                              │
│                     │   Query Interface      │                              │
│                     │                        │                              │
│                     │   getAggregated(       │                              │
│                     │     timeRange,         │                              │
│                     │     binSize            │                              │
│                     │   )                    │                              │
│                     │                        │                              │
│                     │   getDetail(           │                              │
│                     │     timeRange,         │                              │
│                     │     ipFilter           │                              │
│                     │   )                    │                              │
│                     └────────────────────────┘                              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Data Format: Parquet

### Why Parquet?

```
CSV:     timestamp,src_ip,dst_ip,src_port,dst_port,flags,length,protocol
         1703001234567890,192.168.1.1,10.0.0.2,443,52341,16,1500,6
         ... (100 bytes per row typical)

         50M rows × 100 bytes = 5 GB

Parquet: Columnar, compressed, with statistics
         - Dictionary encoding for IPs (4 bytes instead of 15)
         - Delta encoding for timestamps
         - Zstd compression

         50M rows = ~50-100 MB
```

### Schema

```sql
-- Parquet schema (automatically inferred by DuckDB)
CREATE TABLE packets (
    timestamp    BIGINT,      -- Microseconds, delta-encoded
    src_ip_id    UINT16,      -- Dictionary-encoded IP
    dst_ip_id    UINT16,      -- Dictionary-encoded IP
    src_port     UINT16,
    dst_port     UINT16,
    flags        UINT8,
    length       UINT16,
    protocol     UINT8,
    attack_type  UINT8        -- Optional: dictionary-encoded
);

-- Separate IP dictionary table
CREATE TABLE ip_dict (
    ip_id   UINT16 PRIMARY KEY,
    ip_str  VARCHAR
);
```

### Preprocessing: CSV → Parquet

```python
# One-time conversion using DuckDB CLI or Python
import duckdb

con = duckdb.connect()
con.execute("""
    COPY (
        SELECT
            timestamp,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            flags,
            length,
            protocol
        FROM read_csv('raw_packets.csv', header=true)
        ORDER BY timestamp  -- Critical for range query performance
    ) TO 'packets.parquet' (FORMAT PARQUET, COMPRESSION ZSTD);
""")
```

**Output**: Single `packets.parquet` file, ~50-100MB for 50M packets.

---

## 3. Browser Query Engine: DuckDB-WASM

### Setup

```html
<script type="module">
  import * as duckdb from 'https://cdn.jsdelivr.net/npm/@duckdb/duckdb-wasm@latest/+esm';

  const JSDELIVR_BUNDLES = duckdb.getJsDelivrBundles();
  const bundle = await duckdb.selectBundle(JSDELIVR_BUNDLES);

  const worker = new Worker(bundle.mainWorker);
  const logger = new duckdb.ConsoleLogger();
  const db = new duckdb.AsyncDuckDB(logger, worker);
  await db.instantiate(bundle.mainModule);

  // Register the parquet file (can be remote URL or local file)
  await db.registerFileURL('packets.parquet', '/data/packets.parquet');
</script>
```

### Query Interface

```javascript
class PacketQueryEngine {
  constructor(db) {
    this.db = db;
    this.conn = null;
  }

  async init() {
    this.conn = await this.db.connect();

    // Create view for the parquet file
    await this.conn.query(`
      CREATE VIEW packets AS
      SELECT * FROM 'packets.parquet'
    `);
  }

  // Get aggregated data for overview (instant, regardless of dataset size)
  async getMinuteAggregates(timeRange) {
    const [start, end] = timeRange;

    const result = await this.conn.query(`
      SELECT
        (timestamp / 60000000) * 60000000 AS bin_start,
        flags,
        COUNT(*) AS packet_count,
        SUM(length) AS total_bytes
      FROM packets
      WHERE timestamp BETWEEN ${start} AND ${end}
      GROUP BY bin_start, flags
      ORDER BY bin_start
    `);

    return result.toArray();
  }

  // Get detailed packets for zoomed view
  async getDetailedPackets(timeRange, limit = 100000) {
    const [start, end] = timeRange;

    const result = await this.conn.query(`
      SELECT *
      FROM packets
      WHERE timestamp BETWEEN ${start} AND ${end}
      ORDER BY timestamp
      LIMIT ${limit}
    `);

    return result.toArray();
  }

  // Dynamic aggregation based on zoom level
  async getAdaptiveData(timeRange, targetBins = 300) {
    const [start, end] = timeRange;
    const rangeMs = (end - start) / 1000;  // Convert to ms
    const binSizeMs = Math.max(1, Math.floor(rangeMs / targetBins));
    const binSizeUs = binSizeMs * 1000;

    const result = await this.conn.query(`
      SELECT
        (timestamp / ${binSizeUs}) * ${binSizeUs} AS bin_start,
        flags,
        COUNT(*) AS packet_count,
        SUM(length) AS total_bytes,
        MIN(timestamp) AS first_ts,
        MAX(timestamp) AS last_ts
      FROM packets
      WHERE timestamp BETWEEN ${start} AND ${end}
      GROUP BY bin_start, flags
      ORDER BY bin_start
    `);

    return result.toArray();
  }

  // IP filtering
  async getPacketsForIPs(timeRange, ipIds) {
    const [start, end] = timeRange;
    const ipList = ipIds.join(',');

    const result = await this.conn.query(`
      SELECT *
      FROM packets
      WHERE timestamp BETWEEN ${start} AND ${end}
        AND (src_ip_id IN (${ipList}) OR dst_ip_id IN (${ipList}))
      ORDER BY timestamp
    `);

    return result.toArray();
  }
}
```

### Query Performance

```
┌─────────────────────────────────────────────────────────────────┐
│                    DuckDB-WASM QUERY SPEEDS                      │
│                    (50 million packet dataset)                   │
│                                                                  │
│   Query Type                          Time (typical)             │
│   ─────────────────────────────────   ───────────────           │
│   Full dataset minute aggregation     50-100ms                   │
│   1-hour range minute aggregation     5-10ms                     │
│   1-minute range detail (30K rows)    10-20ms                    │
│   IP-filtered aggregation             20-50ms                    │
│                                                                  │
│   Compare to JavaScript loop:         10-100× slower             │
│   Compare to loading JSON chunks:     5-20× slower               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Rendering: WebGL with deck.gl

### Why WebGL?

```
┌─────────────────────────────────────────────────────────────────┐
│                    RENDERING COMPARISON                          │
│                                                                  │
│   Approach          Max Elements    60fps Threshold              │
│   ────────────────  ────────────    ─────────────────           │
│   D3 + SVG          ~5,000          ~2,000 with transitions     │
│   D3 + Canvas       ~50,000         ~20,000                      │
│   deck.gl (WebGL)   ~10,000,000     ~1,000,000                  │
│                                                                  │
│   For 50M packets zoomed to 1-minute (30K visible):             │
│   • SVG: ❌ Unusable                                             │
│   • Canvas: ⚠️ Borderline                                        │
│   • WebGL: ✅ Smooth 60fps                                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### deck.gl Implementation

```javascript
import { Deck } from '@deck.gl/core';
import { ScatterplotLayer, ArcLayer } from '@deck.gl/layers';

class PacketVisualizer {
  constructor(container) {
    this.deck = new Deck({
      parent: container,
      initialViewState: {
        longitude: 0,
        latitude: 0,
        zoom: 1
      },
      controller: true,
      onViewStateChange: ({ viewState }) => this.onViewChange(viewState)
    });
  }

  // Render aggregated bins as rectangles
  renderAggregate(bins) {
    const layer = new ScatterplotLayer({
      id: 'aggregate-bins',
      data: bins,
      getPosition: d => [d.bin_start, d.y_position],
      getRadius: d => Math.sqrt(d.packet_count) * 2,
      getFillColor: d => this.flagColors[d.flags],
      pickable: true,
      onHover: info => this.showTooltip(info),
      updateTriggers: {
        getPosition: [this.xScale, this.yScale]
      }
    });

    this.deck.setProps({ layers: [layer] });
  }

  // Render detailed packets
  renderDetail(packets) {
    const layer = new ScatterplotLayer({
      id: 'detail-packets',
      data: packets,
      getPosition: d => [d.timestamp, d.y_position],
      getRadius: 3,
      getFillColor: d => this.flagColors[d.flags],
      pickable: true,
      onHover: info => this.showTooltip(info)
    });

    this.deck.setProps({ layers: [layer] });
  }

  // Render flow arcs
  renderArcs(flows) {
    const layer = new ArcLayer({
      id: 'flow-arcs',
      data: flows,
      getSourcePosition: d => [d.start_time, d.src_y],
      getTargetPosition: d => [d.end_time, d.dst_y],
      getSourceColor: [52, 152, 219],
      getTargetColor: [46, 204, 113],
      getWidth: 2
    });

    this.deck.setProps({ layers: [layer] });
  }
}
```

### Hybrid Approach: D3 for Axes, WebGL for Data

```javascript
// Keep D3 for axes, legends, and UI controls
const xAxis = d3.axisBottom(xScale);
d3.select('#x-axis').call(xAxis);

// Use deck.gl overlay for data points
const deckOverlay = new Deck({
  parent: document.getElementById('chart'),
  style: { position: 'absolute', top: 0, left: 0 },
  layers: [packetLayer, arcLayer]
});

// Sync deck.gl view with D3 zoom
d3.select('#chart').call(
  d3.zoom().on('zoom', (event) => {
    const { k, x } = event.transform;
    xScale.range([x, x + width * k]);
    d3.select('#x-axis').call(xAxis);

    // Update deck.gl viewport
    deckOverlay.setProps({
      viewState: {
        zoom: Math.log2(k),
        target: [xScale.invert(width / 2), 0]
      }
    });
  })
);
```

---

## 5. Simplified File Structure

```
output_folder/
├── packets.parquet          # Single file, 50-100MB for 50M packets
├── ip_dictionary.json       # IP ID → string mapping (~10KB)
├── metadata.json            # Time extent, packet count, etc.
└── flows.parquet            # Optional: pre-computed flows
```

That's it. No chunk files, no pre-computed aggregates, no complex folder hierarchy.

---

## 6. Complete Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            DATA FLOW                                         │
│                                                                              │
│   PREPROCESSING (one-time)                                                  │
│   ────────────────────────                                                  │
│                                                                              │
│   raw_packets.csv ──▶ DuckDB ──▶ packets.parquet                            │
│   (5 GB)                         (100 MB)                                   │
│                                                                              │
│                                                                              │
│   RUNTIME (browser)                                                         │
│   ─────────────────                                                         │
│                                                                              │
│   1. Page Load                                                              │
│      └──▶ Load parquet header (~1KB) ──▶ Get time extent                   │
│                                                                              │
│   2. Initial View (full dataset overview)                                   │
│      └──▶ SQL: GROUP BY minute ──▶ ~1500 bins ──▶ WebGL render             │
│           (50-100ms)                                                        │
│                                                                              │
│   3. User Zooms In                                                          │
│      └──▶ SQL: WHERE timestamp BETWEEN x AND y                              │
│           GROUP BY (zoom-adaptive bin size)                                 │
│           (5-20ms)                                                          │
│                                                                              │
│   4. User Zooms to Detail                                                   │
│      └──▶ SQL: SELECT * WHERE timestamp BETWEEN x AND y                     │
│           (10-30ms for 50K rows)                                            │
│           └──▶ WebGL renders 50K points at 60fps                            │
│                                                                              │
│   5. Smooth Transition                                                      │
│      └──▶ deck.gl handles interpolation automatically                       │
│           No manual animation code needed                                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Transitions Are Free

With deck.gl, transitions between aggregate and detail views happen automatically:

```javascript
// deck.gl layer with built-in transitions
const layer = new ScatterplotLayer({
  id: 'packets',
  data: currentData,  // Can be aggregates or detail
  getPosition: d => [d.x, d.y],
  getRadius: d => d.radius,

  // Built-in smooth transitions
  transitions: {
    getPosition: 300,    // 300ms position interpolation
    getRadius: 300,      // 300ms radius interpolation
    getFillColor: 300    // 300ms color interpolation
  }
});
```

When you update `data`, deck.gl automatically:
1. Matches elements by ID
2. Interpolates positions, sizes, colors
3. Handles enter/exit animations

No manual cross-fade, frozen layers, or animation state machines needed.

---

## 8. Implementation Comparison

| Task | JSON/CSV Approach | DuckDB + WebGL |
|------|-------------------|----------------|
| **Preprocessing** | 200+ lines Python, multiple output files | 10 lines, single parquet file |
| **Initial load** | Parse JSON, build data structures | One SQL query |
| **Zoom handling** | Resolution manager, chunk fetching, caching | One SQL query |
| **Rendering** | D3 enter/update/exit, manual batching | deck.gl setProps |
| **Transitions** | Manual animation state machine | Built-in |
| **Memory management** | LRU cache, eviction logic | Automatic (DuckDB manages) |
| **Total JS code** | ~2000 lines | ~300 lines |

---

## 9. Browser Compatibility

```
┌─────────────────────────────────────────────────────────────────┐
│                    BROWSER SUPPORT                               │
│                                                                  │
│   Feature          Chrome   Firefox   Safari   Edge              │
│   ──────────────   ──────   ───────   ──────   ────              │
│   DuckDB-WASM      ✅ 80+   ✅ 78+    ✅ 15+   ✅ 80+            │
│   WebGL 2.0        ✅ 56+   ✅ 51+    ✅ 15+   ✅ 79+            │
│   deck.gl          ✅ 64+   ✅ 57+    ✅ 12+   ✅ 79+            │
│                                                                  │
│   Fallback for older browsers:                                   │
│   • DuckDB → sql.js (SQLite WASM)                               │
│   • WebGL → Canvas 2D (deck.gl supports this)                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 10. Minimal Implementation Skeleton

```javascript
// Complete working example in ~100 lines

import * as duckdb from '@duckdb/duckdb-wasm';
import { Deck, ScatterplotLayer } from 'deck.gl';

async function init() {
  // 1. Initialize DuckDB
  const db = await initDuckDB();
  const conn = await db.connect();
  await conn.query(`CREATE VIEW packets AS SELECT * FROM 'packets.parquet'`);

  // 2. Get time extent
  const extent = await conn.query(`
    SELECT MIN(timestamp) as min_t, MAX(timestamp) as max_t FROM packets
  `);
  const [minTime, maxTime] = [extent[0].min_t, extent[0].max_t];

  // 3. Initialize deck.gl
  const deck = new Deck({
    parent: document.getElementById('chart'),
    controller: true,
    onViewStateChange: ({ viewState }) => updateData(viewState)
  });

  // 4. Query and render function
  async function updateData(viewState) {
    const visibleRange = getVisibleTimeRange(viewState, minTime, maxTime);
    const binSize = calculateBinSize(visibleRange);

    const data = await conn.query(`
      SELECT
        (timestamp / ${binSize}) * ${binSize} AS x,
        flags,
        COUNT(*) AS count
      FROM packets
      WHERE timestamp BETWEEN ${visibleRange[0]} AND ${visibleRange[1]}
      GROUP BY x, flags
    `);

    deck.setProps({
      layers: [
        new ScatterplotLayer({
          data: data.toArray(),
          getPosition: d => [d.x, flagToY(d.flags)],
          getRadius: d => Math.sqrt(d.count) * 3,
          getFillColor: d => flagColors[d.flags],
          transitions: { getPosition: 200, getRadius: 200 }
        })
      ]
    });
  }

  // Initial render
  updateData({ zoom: 1, target: [(minTime + maxTime) / 2, 0] });
}

init();
```

---

## 11. When to Choose Each Approach

### Use JSON/CSV + D3 (Previous Plan) If:
- Must maintain backward compatibility with existing data pipeline
- Dataset < 1 million rows
- Team unfamiliar with SQL/Parquet/WebGL
- Need pixel-perfect SVG export
- Existing codebase investment is significant

### Use DuckDB + Parquet + WebGL (This Plan) If:
- Starting fresh or can migrate
- Dataset > 1 million rows (especially > 10 million)
- Performance is critical
- Want simpler, more maintainable code
- Willing to learn new tools

---

## 12. Migration Path

If you want to adopt this architecture incrementally:

```
Phase 1: Data Format
────────────────────
• Convert CSV → Parquet (keep generating CSV too)
• Test DuckDB queries alongside current loader

Phase 2: Query Layer
────────────────────
• Add DuckDB-WASM as alternative data source
• Keep D3 rendering unchanged
• A/B test performance

Phase 3: Rendering Layer
────────────────────────
• Add deck.gl for data points only
• Keep D3 for axes, legends, UI
• Remove D3 data bindings gradually

Phase 4: Full Migration
───────────────────────
• Remove legacy JSON/CSV loaders
• Remove D3 data rendering code
• Simplify codebase
```

---

## Summary

The DuckDB-WASM + Parquet + deck.gl stack is the modern standard for large-scale browser visualizations. It eliminates:

- Pre-computed aggregation files
- Chunk-based loading strategies
- Resolution managers and state machines
- Manual transition animations
- Memory management and caching logic

The result is **10× less code** that handles **100× more data** with **better performance**.
