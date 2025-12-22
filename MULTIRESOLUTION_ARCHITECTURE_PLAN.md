# Multi-Resolution Time-Series Visualization Architecture

## Executive Summary

This document describes a scalable data and visualization architecture for the TCP TimeArcs IP bar diagram that enables:
- **Instant initial load** via pre-aggregated minute-level data
- **On-demand microsecond detail** loaded only when users zoom/brush
- **Perceptually seamless transitions** between resolution levels
- **Tens of millions of rows** handled efficiently

The design extends the existing tile-based worker architecture (`src/ingest/`) and folder-based loading (`folder_loader.js`) already present in the codebase.

---

## 1. Data Preprocessing Strategy

### 1.1 Resolution Pyramid Concept

Build a hierarchical data structure during preprocessing that stores aggregations at multiple temporal resolutions:

```
Level 0: Raw microsecond data (full fidelity)
Level 1: Aggregated by second (~1,000x reduction)
Level 2: Aggregated by minute (~60,000x reduction) ← Initial load
Level 3: Aggregated by hour (~3,600,000x reduction, optional)
```

Each level stores:
- **Bin timestamp** (start of bin)
- **Packet count** per flag type
- **Total bytes** per flag type
- **Min/max timestamps** within bin (for drill-down bounds)
- **Representative sample packet** (for tooltip context)

### 1.2 Preprocessing Script: `tcp_data_loader_multiresolution.py`

Extend the existing `tcp_data_loader_chunked.py` to generate the pyramid:

```
Input: raw_packets.csv (microseconds)
       ↓
┌──────────────────────────────────────────────────────────────┐
│                   PREPROCESSING PIPELINE                      │
│                                                               │
│  1. Stream-parse CSV (handle 10M+ rows)                      │
│  2. Build per-minute aggregates on first pass                │
│  3. Write minute-level JSON/CSV (small, loads instantly)     │
│  4. Partition raw data into 1-minute chunk files             │
│  5. Generate spatial index for range queries                 │
└──────────────────────────────────────────────────────────────┘
       ↓
Output folder structure (see Section 2)
```

### 1.3 Aggregation Schema

Each aggregate bin stores:

```typescript
interface AggregateBin {
  // Temporal bounds
  binStart: number;      // Start timestamp (microseconds)
  binEnd: number;        // End timestamp (microseconds)

  // Aggregate metrics (per flag type)
  flagCounts: {
    [flagType: string]: number;  // e.g., { "SYN": 45, "ACK": 1203, ... }
  };
  flagBytes: {
    [flagType: string]: number;  // Total bytes per flag type
  };

  // For radius scaling
  totalPackets: number;
  totalBytes: number;

  // IP pair info (for arc grouping)
  srcIp: string;
  dstIp: string;

  // Sample packet for tooltip preview
  samplePacket?: {
    timestamp: number;
    flags: number;
    length: number;
    src_port: number;
    dst_port: number;
  };

  // Reference to detail chunk
  detailChunk: string;  // e.g., "minute_chunks/1703001200.csv"
}
```

---

## 2. File Organization

### 2.1 Output Directory Structure

```
output_folder/
├── manifest.json                    # Dataset metadata + resolution info
│
├── aggregates/
│   ├── minute_level.json           # Pre-computed minute bins (~10KB-1MB)
│   ├── minute_level_by_ip/         # Optional: per-IP-pair minute data
│   │   ├── 192.168.1.1_10.0.0.2.json
│   │   └── ...
│   └── hour_level.json             # Optional: even coarser for huge datasets
│
├── minute_chunks/                   # Raw data partitioned by minute
│   ├── 1703001200.csv              # All packets in minute 1703001200
│   ├── 1703001260.csv              # Next minute
│   ├── ...
│   └── index.json                  # Maps minute → chunk filename + packet count
│
├── indices/
│   ├── time_index.json             # Time range → chunk mapping
│   ├── ip_index.json               # IP → which chunks contain it
│   └── bins.json                   # Existing bin structure
│
├── flows/                          # Existing flow structure (unchanged)
│   ├── flows_index.json
│   └── chunk_*.json
│
└── packets.csv                     # Optional: minimal packets for arc rendering
```

### 2.2 Manifest Schema Extension

```json
{
  "format": "multiresolution",
  "version": "3.0",
  "generated": "2024-01-15T10:30:00Z",

  "timeExtent": [1703001200000000, 1703087600000000],
  "totalPackets": 45000000,

  "resolutions": {
    "minute": {
      "file": "aggregates/minute_level.json",
      "binCount": 1440,
      "avgPacketsPerBin": 31250
    },
    "second": {
      "strategy": "on-demand",
      "chunkDir": "minute_chunks/"
    },
    "microsecond": {
      "strategy": "on-demand",
      "source": "minute_chunks/"
    }
  },

  "chunkIndex": "minute_chunks/index.json",
  "ipIndex": "indices/ip_index.json"
}
```

### 2.3 Minute Chunk Index

```json
{
  "chunkSize": 60000000,  // 1 minute in microseconds
  "chunks": [
    {
      "id": 1703001200,
      "file": "1703001200.csv",
      "packetCount": 28450,
      "byteSize": 1245000,
      "timeRange": [1703001200000000, 1703001259999999]
    },
    // ... more chunks
  ]
}
```

---

## 3. Client-Side Loading Architecture

### 3.1 Resolution Manager

A new module that orchestrates multi-resolution data:

```
┌─────────────────────────────────────────────────────────────────┐
│                     ResolutionManager                            │
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ MinuteCache │  │ DetailCache │  │ PrefetchQ   │             │
│  │ (always     │  │ (LRU, ~50   │  │ (speculative│             │
│  │  in memory) │  │  chunks)    │  │  loading)   │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│         │                │                │                      │
│         └────────────────┴────────────────┘                      │
│                          │                                       │
│              ┌───────────▼───────────┐                          │
│              │  Current Resolution   │                          │
│              │  State Machine        │                          │
│              └───────────────────────┘                          │
│                          │                                       │
│         ┌────────────────┼────────────────┐                     │
│         ▼                ▼                ▼                      │
│   [Aggregated]     [Transitioning]    [Detailed]                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Loading State Machine

```
┌──────────────────┐         zoom in              ┌──────────────────┐
│                  │ ─────────────────────────────▶│                  │
│   AGGREGATED     │                               │   TRANSITIONING  │
│   (minute-level) │                               │   (loading detail)│
│                  │◀───────────────────────────── │                  │
└──────────────────┘      detail loaded            └──────────────────┘
        │                                                  │
        │ zoom out                                         │ detail ready
        │                                                  ▼
        │                                          ┌──────────────────┐
        │                                          │                  │
        └──────────────────────────────────────────│    DETAILED      │
                                                   │  (microsecond)   │
                                                   │                  │
                                                   └──────────────────┘
```

### 3.3 Extended FolderLoader API

```javascript
// Extend existing folder_loader.js

class MultiResolutionLoader extends FolderLoader {
  constructor() {
    super();
    this.minuteData = null;        // Always in memory after init
    this.detailCache = new LRUCache(50);  // Cache ~50 minute-chunks
    this.loadingChunks = new Set();       // Prevent duplicate fetches
    this.prefetchQueue = [];              // Speculative loading
  }

  // NEW: Load aggregated data for instant initial render
  async loadMinuteAggregates() {
    const file = await this.getFile('aggregates/minute_level.json');
    this.minuteData = await this.parseJSON(file);
    return this.minuteData;
  }

  // NEW: Load detail for specific time range (on zoom/brush)
  async loadDetailForRange(startTime, endTime) {
    const chunkIds = this.getChunksInRange(startTime, endTime);
    const missing = chunkIds.filter(id => !this.detailCache.has(id));

    if (missing.length === 0) {
      return this.assembleFromCache(chunkIds);
    }

    // Load missing chunks in parallel
    const loads = missing.map(id => this.loadChunk(id));
    await Promise.all(loads);

    return this.assembleFromCache(chunkIds);
  }

  // NEW: Speculative prefetch for adjacent chunks
  prefetchAdjacent(currentChunkIds) {
    const adjacent = this.getAdjacentChunks(currentChunkIds, 2);
    adjacent.forEach(id => {
      if (!this.detailCache.has(id) && !this.loadingChunks.has(id)) {
        this.prefetchQueue.push(id);
      }
    });
    this.processPrefetchQueue();
  }
}
```

---

## 4. Zoom/Brush-Triggered Data Fetching

### 4.1 Zoom Level Thresholds

Define thresholds that determine which resolution to display:

```javascript
// In src/data/binning.js or new resolution-manager.js

const RESOLUTION_THRESHOLDS = {
  // If visible range > 30 minutes, use minute aggregates
  MINUTE_LEVEL: 30 * 60 * 1000000,  // 30 min in microseconds

  // If visible range 1-30 minutes, use second-level (from minute chunks)
  SECOND_LEVEL: 1 * 60 * 1000000,   // 1 min in microseconds

  // If visible range < 1 minute, show full microsecond detail
  MICROSECOND_LEVEL: 0
};

function getRequiredResolution(visibleRange) {
  if (visibleRange > RESOLUTION_THRESHOLDS.MINUTE_LEVEL) {
    return 'minute';
  } else if (visibleRange > RESOLUTION_THRESHOLDS.SECOND_LEVEL) {
    return 'second';
  } else {
    return 'microsecond';
  }
}
```

### 4.2 Integration with Existing Zoom Behavior

Modify `src/interaction/zoom.js`:

```javascript
// Existing zoom handler in zoom.js
function onZoomEnd(event) {
  const transform = event.transform;
  const newDomain = transform.rescaleX(baseXScale).domain();
  const visibleRange = newDomain[1] - newDomain[0];

  // NEW: Determine required resolution
  const requiredRes = getRequiredResolution(visibleRange);
  const currentRes = resolutionManager.getCurrentResolution();

  if (requiredRes !== currentRes) {
    // Trigger resolution transition
    resolutionManager.transitionTo(requiredRes, newDomain)
      .then(() => {
        // Redraw with new data
        renderCurrentData();
      });
  } else {
    // Same resolution, just re-render visible portion
    renderCurrentData();
  }
}
```

### 4.3 Brush Integration

Modify `overview_chart.js` brush handler:

```javascript
function brushed(event) {
  if (!event.selection) return;

  const [x0, x1] = event.selection;
  const newDomain = [overviewXScale.invert(x0), overviewXScale.invert(x1)];
  const visibleRange = newDomain[1] - newDomain[0];

  // Check if we need higher-resolution data
  const requiredRes = getRequiredResolution(visibleRange);

  if (requiredRes !== 'minute') {
    // Show loading indicator immediately
    showLoadingOverlay();

    // Fetch detail data
    multiResLoader.loadDetailForRange(newDomain[0], newDomain[1])
      .then(detailData => {
        hideLoadingOverlay();
        transitionToDetail(detailData, newDomain);
      });
  } else {
    // Minute data already loaded, instant transition
    applyZoomDomain(newDomain, 'brush');
  }
}
```

### 4.4 Debouncing and Cancellation

```javascript
class ZoomDebouncer {
  constructor(delay = 150) {
    this.delay = delay;
    this.pending = null;
    this.abortController = null;
  }

  schedule(domain, callback) {
    // Cancel any pending request
    if (this.abortController) {
      this.abortController.abort();
    }

    clearTimeout(this.pending);
    this.abortController = new AbortController();

    this.pending = setTimeout(() => {
      callback(domain, this.abortController.signal);
    }, this.delay);
  }
}

// Usage
const zoomDebouncer = new ZoomDebouncer(100);

function onZoom(event) {
  const domain = getNewDomain(event);

  // Immediate: update x-axis, clip existing data
  updateAxisImmediate(domain);
  clipExistingData(domain);

  // Debounced: fetch new data if needed
  zoomDebouncer.schedule(domain, async (d, signal) => {
    if (signal.aborted) return;
    const data = await loadDataForDomain(d);
    if (signal.aborted) return;
    renderNewData(data);
  });
}
```

---

## 5. Transition and Animation Strategy

### 5.1 Visual Continuity Principles

The key to seamless transitions:

1. **Never blank the canvas** - Keep existing visualization visible while loading
2. **Morph, don't replace** - Animate from aggregate to detail positions
3. **Progressive reveal** - Fade in detail as it loads
4. **Skeleton previews** - Show approximate positions from aggregates

### 5.2 Transition State Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                      │
│  [USER ZOOMS IN]                                                    │
│        │                                                             │
│        ▼                                                             │
│  ┌─────────────┐                                                    │
│  │ 1. FREEZE   │  Keep current minute bars visible                  │
│  │    CURRENT  │  Apply new x-domain to frozen bars                 │
│  └─────────────┘  (they stretch/compress with zoom)                 │
│        │                                                             │
│        ▼                                                             │
│  ┌─────────────┐                                                    │
│  │ 2. SHOW     │  Subtle pulsing glow on stretched bars             │
│  │    LOADING  │  OR thin progress line at top of chart             │
│  └─────────────┘                                                     │
│        │                                                             │
│        ▼  (detail data arrives)                                      │
│  ┌─────────────┐                                                    │
│  │ 3. SPAWN    │  Render detail dots/bars at α=0, behind frozen     │
│  │    DETAIL   │  Position detail elements at correct x-positions   │
│  └─────────────┘                                                     │
│        │                                                             │
│        ▼                                                             │
│  ┌─────────────┐                                                    │
│  │ 4. CROSS-   │  Fade out frozen aggregates (α: 1 → 0, 200ms)      │
│  │    FADE     │  Fade in detail elements (α: 0 → 1, 200ms)         │
│  └─────────────┘                                                     │
│        │                                                             │
│        ▼                                                             │
│  ┌─────────────┐                                                    │
│  │ 5. CLEANUP  │  Remove frozen aggregate layer                     │
│  │             │  Detail layer becomes primary                      │
│  └─────────────┘                                                     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.3 D3 Implementation Pattern

```javascript
function transitionToDetail(aggregateBins, detailPackets, xScale) {
  const container = d3.select('#main-chart');

  // 1. Freeze current aggregates in a separate layer
  const frozenLayer = container.append('g')
    .attr('class', 'frozen-aggregate-layer')
    .attr('opacity', 1);

  // Clone current aggregate bars to frozen layer
  container.selectAll('.aggregate-bar').each(function(d) {
    frozenLayer.append('rect')
      .attr('class', 'frozen-bar')
      .attr('x', d3.select(this).attr('x'))
      .attr('y', d3.select(this).attr('y'))
      .attr('width', d3.select(this).attr('width'))
      .attr('height', d3.select(this).attr('height'))
      .attr('fill', d3.select(this).attr('fill'));
  });

  // Remove original aggregates immediately
  container.selectAll('.aggregate-bar').remove();

  // 2. Create detail layer behind frozen
  const detailLayer = container.insert('g', '.frozen-aggregate-layer')
    .attr('class', 'detail-layer')
    .attr('opacity', 0);

  // 3. Render detail packets
  detailLayer.selectAll('.detail-dot')
    .data(detailPackets)
    .enter()
    .append('circle')
    .attr('class', 'detail-dot')
    .attr('cx', d => xScale(d.timestamp))
    .attr('cy', d => getYPosition(d))
    .attr('r', 3)
    .attr('fill', d => getFlagColor(d.flags));

  // 4. Cross-fade
  frozenLayer.transition()
    .duration(200)
    .attr('opacity', 0)
    .remove();

  detailLayer.transition()
    .duration(200)
    .attr('opacity', 1);
}
```

### 5.4 Zoom-Out Transition (Detail → Aggregate)

```javascript
function transitionToAggregate(detailPackets, aggregateBins, xScale) {
  const container = d3.select('#main-chart');

  // Identify which aggregate bin each detail dot belongs to
  const binAssignments = assignDetailToBins(detailPackets, aggregateBins);

  // 1. Group detail dots by their target bin
  const detailLayer = container.select('.detail-layer');

  // 2. Animate dots moving toward bin centers (collapse effect)
  detailLayer.selectAll('.detail-dot')
    .transition()
    .duration(300)
    .attr('cx', d => {
      const bin = binAssignments.get(d);
      return xScale(bin.binCenter);
    })
    .attr('r', 1)  // Shrink as they merge
    .attr('opacity', 0.3);

  // 3. Simultaneously fade in aggregate bars
  const aggLayer = container.insert('g', '.detail-layer')
    .attr('class', 'aggregate-layer')
    .attr('opacity', 0);

  renderAggregateBars(aggLayer, aggregateBins, xScale);

  aggLayer.transition()
    .delay(150)  // Slight delay for overlap
    .duration(200)
    .attr('opacity', 1);

  // 4. Remove detail layer after transition
  detailLayer.transition()
    .delay(300)
    .remove();
}
```

### 5.5 Loading Indicator Patterns

```javascript
// Subtle top-edge progress line
function showLoadingIndicator() {
  const width = getChartWidth();

  d3.select('#chart-container')
    .append('div')
    .attr('class', 'loading-line')
    .style('position', 'absolute')
    .style('top', '0')
    .style('left', '0')
    .style('width', '0%')
    .style('height', '2px')
    .style('background', 'linear-gradient(90deg, #3498db, #2ecc71)')
    .transition()
    .duration(2000)
    .ease(d3.easeLinear)
    .style('width', '80%');
}

// Pulsing glow on stretched bars
function pulseLoadingBars() {
  d3.selectAll('.frozen-bar')
    .style('filter', 'drop-shadow(0 0 3px rgba(52, 152, 219, 0.5))')
    .transition()
    .duration(500)
    .style('filter', 'drop-shadow(0 0 6px rgba(52, 152, 219, 0.8))')
    .transition()
    .duration(500)
    .style('filter', 'drop-shadow(0 0 3px rgba(52, 152, 219, 0.5))')
    .on('end', function() {
      if (isStillLoading) pulseLoadingBars();
    });
}
```

---

## 6. Performance Considerations

### 6.1 Memory Management

```
┌─────────────────────────────────────────────────────────────────┐
│                    MEMORY BUDGET (~200MB target)                │
│                                                                  │
│  ┌──────────────────────────────────┐                           │
│  │ Minute Aggregates (always)       │  ~2-5 MB                  │
│  │ - 1440 bins × ~500 bytes         │                           │
│  └──────────────────────────────────┘                           │
│                                                                  │
│  ┌──────────────────────────────────┐                           │
│  │ Detail Cache (LRU, 30 chunks)    │  ~30-90 MB               │
│  │ - 30 chunks × ~30K packets       │                           │
│  │ - ~100 bytes per packet          │                           │
│  └──────────────────────────────────┘                           │
│                                                                  │
│  ┌──────────────────────────────────┐                           │
│  │ DOM Elements (visible only)      │  ~20-50 MB               │
│  │ - Max ~10K circles/bars          │                           │
│  │ - Use virtual scrolling if >10K  │                           │
│  └──────────────────────────────────┘                           │
│                                                                  │
│  ┌──────────────────────────────────┐                           │
│  │ Flow Cache (unchanged)           │  ~50 MB                   │
│  └──────────────────────────────────┘                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 LRU Cache Implementation

```javascript
class LRUCache {
  constructor(maxSize = 30) {
    this.maxSize = maxSize;
    this.cache = new Map();  // Maintains insertion order
  }

  get(key) {
    if (!this.cache.has(key)) return undefined;

    // Move to end (most recently used)
    const value = this.cache.get(key);
    this.cache.delete(key);
    this.cache.set(key, value);
    return value;
  }

  set(key, value) {
    if (this.cache.has(key)) {
      this.cache.delete(key);
    } else if (this.cache.size >= this.maxSize) {
      // Evict oldest (first) entry
      const oldest = this.cache.keys().next().value;
      this.cache.delete(oldest);
    }
    this.cache.set(key, value);
  }

  has(key) {
    return this.cache.has(key);
  }
}
```

### 6.3 Web Worker Integration

Extend existing worker architecture for parsing detail chunks:

```
┌─────────────────────────────────────────────────────────────────┐
│                       WORKER ARCHITECTURE                        │
│                                                                  │
│   Main Thread              Worker Pool (existing)                │
│   ───────────              ───────────────────────               │
│                                                                  │
│   loadDetailForRange()                                           │
│        │                                                         │
│        ├──────────────────▶ [Parse Worker 1] ─┐                  │
│        │                                       │                  │
│        ├──────────────────▶ [Parse Worker 2] ─┼──▶ Parsed chunks │
│        │                                       │                  │
│        └──────────────────▶ [Parse Worker N] ─┘                  │
│                                    │                             │
│                                    ▼                             │
│                            [Aggregator Worker]                   │
│                                    │                             │
│                                    ▼                             │
│   onDetailReady(data) ◀────────────┘                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 6.4 Render Batching

When zoomed to detail level with thousands of packets:

```javascript
function renderDetailBatched(packets, batchSize = 500) {
  let index = 0;

  function renderBatch() {
    const batch = packets.slice(index, index + batchSize);

    if (batch.length === 0) return;

    detailLayer.selectAll('.detail-dot-batch-' + index)
      .data(batch)
      .enter()
      .append('circle')
      .attr('class', 'detail-dot')
      .attr('cx', d => xScale(d.timestamp))
      .attr('cy', d => yScale(d.ip))
      .attr('r', 2)
      .attr('fill', d => flagColors[d.flagType]);

    index += batchSize;

    if (index < packets.length) {
      requestAnimationFrame(renderBatch);
    }
  }

  requestAnimationFrame(renderBatch);
}
```

### 6.5 Culling and Viewport Optimization

```javascript
function getVisiblePackets(packets, domain, margin = 0.1) {
  const domainWidth = domain[1] - domain[0];
  const expandedMin = domain[0] - domainWidth * margin;
  const expandedMax = domain[1] + domainWidth * margin;

  // Binary search for start index (packets are sorted by timestamp)
  const startIdx = binarySearchLeft(packets, expandedMin, p => p.timestamp);
  const endIdx = binarySearchRight(packets, expandedMax, p => p.timestamp);

  return packets.slice(startIdx, endIdx);
}
```

---

## 7. Tradeoffs and Design Decisions

### 7.1 Why Minute-Level as Initial Resolution?

| Approach | Pros | Cons |
|----------|------|------|
| **Minute-level** | Matches existing binning (300 bins over ~5 hours); instant load (~1MB); familiar visual | May need intermediate second-level for medium zooms |
| Second-level | More detail in overview | 60× larger initial payload; slower first paint |
| Hour-level | Extremely fast initial load | Too coarse for useful overview |

**Decision**: Minute-level balances initial load time with meaningful overview granularity.

### 7.2 Chunk Size Selection

| Chunk Size | Typical File Size | Load Time | Cache Efficiency |
|------------|-------------------|-----------|------------------|
| 10 seconds | ~50KB | <50ms | Poor (many fetches) |
| **1 minute** | ~300KB | <100ms | Good balance |
| 5 minutes | ~1.5MB | ~300ms | Good for linear scan |
| 1 hour | ~18MB | 1-3s | Poor (large waste) |

**Decision**: 1-minute chunks balance granularity with fetch overhead.

### 7.3 Cache vs. Re-fetch

| Strategy | Pros | Cons |
|----------|------|------|
| **LRU cache (30 chunks)** | Fast revisits; bounded memory | May evict recently-used data |
| Persist to IndexedDB | Survives page reload | Slower than memory; adds complexity |
| No cache | Simplest; lowest memory | Slow repeated zooms |

**Decision**: In-memory LRU with optional IndexedDB persistence for very large sessions.

### 7.4 Transition Duration

| Duration | Perception | Risk |
|----------|------------|------|
| 0ms (instant) | Jarring; disorienting | Data appears to "pop" |
| 100-150ms | Snappy; perceptible movement | May feel rushed |
| **200-250ms** | Smooth; natural motion | Good balance |
| 400ms+ | Deliberate; "luxurious" | Feels slow on repeated use |

**Decision**: 200ms cross-fade with 50ms stagger for natural feel.

---

## 8. Implementation Phases

### Phase 1: Preprocessing (Estimated: 2-3 days of work)
- [ ] Create `tcp_data_loader_multiresolution.py`
- [ ] Generate minute-level aggregates with flag breakdowns
- [ ] Partition raw data into minute chunks
- [ ] Generate chunk index and manifest

### Phase 2: Loading Infrastructure (Estimated: 3-4 days of work)
- [ ] Extend `FolderLoader` with multi-resolution methods
- [ ] Implement LRU cache for detail chunks
- [ ] Add prefetching for adjacent chunks
- [ ] Integrate with existing worker pool

### Phase 3: Resolution Transitions (Estimated: 3-4 days of work)
- [ ] Create `ResolutionManager` state machine
- [ ] Implement zoom threshold detection
- [ ] Modify `applyZoomDomain` for resolution awareness
- [ ] Add debouncing and cancellation

### Phase 4: Visual Transitions (Estimated: 2-3 days of work)
- [ ] Implement freeze/clone of current state
- [ ] Create cross-fade animation
- [ ] Add loading indicators
- [ ] Handle zoom-out aggregation animation

### Phase 5: Polish and Optimization (Estimated: 2-3 days of work)
- [ ] Profile memory usage
- [ ] Tune cache sizes
- [ ] Add render batching
- [ ] Test with 10M+ packet datasets

---

## 9. Appendix: ASCII Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MULTI-RESOLUTION ARCHITECTURE                        │
│                                                                              │
│  ┌──────────────────┐                                                       │
│  │   User Action    │                                                       │
│  │  (zoom/brush)    │                                                       │
│  └────────┬─────────┘                                                       │
│           │                                                                  │
│           ▼                                                                  │
│  ┌──────────────────┐     ┌─────────────────┐     ┌──────────────────┐     │
│  │ ResolutionManager│────▶│  DataLoader     │────▶│  RenderPipeline  │     │
│  │                  │     │                 │     │                  │     │
│  │ • Threshold calc │     │ • Minute cache  │     │ • Layer manage   │     │
│  │ • State machine  │     │ • Detail cache  │     │ • Transition     │     │
│  │ • Debouncing     │     │ • Web Workers   │     │ • Animation      │     │
│  └──────────────────┘     └─────────────────┘     └──────────────────┘     │
│           │                       │                       │                 │
│           │                       │                       │                 │
│           ▼                       ▼                       ▼                 │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                           DATA LAYERS                                │   │
│  │                                                                      │   │
│  │   [Minute Aggregates]    [Second Bins]    [Microsecond Packets]     │   │
│  │         ▲                      ▲                   ▲                 │   │
│  │         │                      │                   │                 │   │
│  │   Always loaded          On-demand            On-demand              │   │
│  │   (~1MB, instant)        (~300KB/chunk)       (from chunks)          │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                          FILE SYSTEM                                 │   │
│  │                                                                      │   │
│  │   output_folder/                                                     │   │
│  │   ├── manifest.json          ← Loaded first (metadata)              │   │
│  │   ├── aggregates/                                                    │   │
│  │   │   └── minute_level.json  ← Loaded second (initial view)         │   │
│  │   ├── minute_chunks/                                                 │   │
│  │   │   ├── index.json         ← Loaded with aggregates               │   │
│  │   │   ├── 1703001200.csv     ← Loaded on zoom (detail)              │   │
│  │   │   └── ...                                                        │   │
│  │   └── flows/                 ← Unchanged from current system         │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 10. Summary

This architecture enables:

1. **< 500ms initial render** by loading only minute-level aggregates
2. **< 200ms detail transitions** via prefetching and caching
3. **Seamless visual continuity** through cross-fade animations
4. **Bounded memory** (~200MB) with LRU eviction
5. **Scales to 10M+ packets** by never loading all data at once

The design builds upon the existing tile-store and worker-pool infrastructure, extending it with resolution-aware loading and D3 transition patterns that maintain perceptual continuity during zoom operations.
