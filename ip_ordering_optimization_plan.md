# IP Ordering Optimization Plan: Hub-Preserving Crossing Minimization

**Goal**: Reduce arc crossings in the vertical IP layout while preserving the hub-centric component structure.

**File**: `attack_timearcs.js`

**Date**: 2024-12-02

---

## Problem Statement

The current visualization orders IPs using force simulation to create natural component clustering with high-degree "hub" IPs centered within each component. However, the final vertical ordering doesn't explicitly minimize arc crossings, which can create visual clutter especially in the periphery of components.

**Challenge**: Reduce crossings WITHOUT breaking the intentional hub-centric design.

---

## Current Hub-Centric Layout (Must Preserve)

### Existing Implementation (lines 961-1092)

The current approach intentionally places hub IPs at component centers:

1. **Hub Identification** (lines 969-974)
   ```javascript
   const componentHubIps = findComponentHubIps(components, ipDegree);
   ```
   Identifies the IP with most connections in each component.

2. **Hub-Centered Initialization** (line 992)
   ```javascript
   initializeNodePositions(simNodes, ipToComponent, componentCenters, centerX, ipDegree, componentSpacing);
   ```
   Starts hub IPs near component centers.

3. **Hub Centering Force** (line 1001)
   ```javascript
   const hubCenteringForce = createHubCenteringForce(componentHubIps, componentCenters, simNodes);
   simulation.force('hubCentering', hubCenteringForce);
   ```
   Actively pulls hubs toward center during simulation.

4. **Single Component Handling** (lines 1054-1067)
   ```javascript
   if (hubIp) {
     simulation.force('hubCentering', createHubCenteringForce(singleHubIps, singleComponentCenters, simNodes));
   }
   ```

### Design Rationale

**Why hub-centric?**
- **Shorter arcs**: High-degree nodes at center = minimal arc lengths to periphery
- **Visual clarity**: Star-like structure makes connectivity patterns obvious
- **Cognitive load**: Hub prominence reflects network importance
- **Force stability**: Centering high-degree nodes reduces simulation oscillation

**Critical Constraint**: Any optimization MUST preserve hub centrality.

---

## Revised Algorithm: Hub-Preserving Crossing Minimization

### Core Strategy

1. **Preserve force simulation** (lines 961-1092) - no changes
2. **Optimize periphery nodes only** - low-degree IPs can be reordered
3. **Use radial partitioning** - order nodes at same distance from hub
4. **Smart crossing metric** - exclude hub-connected arcs from count

### Three-Layer Approach

#### Layer 1: Hub Anchoring (Existing - No Changes)

Force simulation establishes hub positions at component centers. This is the foundation - **do not modify**.

#### Layer 2: Radial Partitioning (New)

Partition each component's IPs into concentric "shells" by distance from hub:

```javascript
function partitionByDistanceFromHub(component, hubIp, yMap) {
  const hubY = yMap.get(hubIp);

  // Separate into above/below hub
  const above = component.filter(n => yMap.get(n.id) < hubY);
  const below = component.filter(n => yMap.get(n.id) >= hubY);

  // Further partition by degree (core vs periphery)
  const degreeThreshold = d3.median(component.map(n => ipDegree.get(n.id)));

  return {
    hub: [hubIp],
    aboveCore: above.filter(n => ipDegree.get(n.id) >= degreeThreshold),
    abovePeriphery: above.filter(n => ipDegree.get(n.id) < degreeThreshold),
    belowCore: below.filter(n => ipDegree.get(n.id) >= degreeThreshold),
    belowPeriphery: below.filter(n => ipDegree.get(n.id) < degreeThreshold)
  };
}
```

**Key insight**: Only reorder periphery partitions. Hub and core nodes stay stable.

#### Layer 3: Partition-Level Barycentric Ordering (New)

Apply crossing minimization within each periphery partition:

```javascript
function optimizePeripheryOrder(peripheryNodes, links, yMap, ipDegree) {
  // Compute barycenter for each node (weighted average of neighbor Y positions)
  const barycenters = new Map();

  peripheryNodes.forEach(node => {
    const ip = node.id;
    const neighbors = getNeighbors(ip, links);

    if (neighbors.length === 0) {
      barycenters.set(ip, yMap.get(ip)); // No neighbors - keep current pos
      return;
    }

    // Weighted average: higher degree neighbors pull stronger
    let weightedSum = 0;
    let totalWeight = 0;

    neighbors.forEach(neighborIp => {
      const weight = ipDegree.get(neighborIp) || 1;
      weightedSum += yMap.get(neighborIp) * weight;
      totalWeight += weight;
    });

    barycenters.set(ip, weightedSum / totalWeight);
  });

  // Sort by barycenter value
  return peripheryNodes.slice().sort((a, b) => {
    return barycenters.get(a.id) - barycenters.get(b.id);
  });
}
```

**Barycenter heuristic**: Classic graph drawing technique that typically reduces crossings by 30-60%.

---

## Implementation Plan

### New Function 1: Smart Crossing Counter (~line 1988)

```javascript
/**
 * Count arc crossings, excluding hub-connected arcs.
 * Hub-connected arcs are structural necessities and shouldn't penalize the metric.
 */
function countPeripheryCrossings(links, yMap, ipToComponent, componentHubIps, ipDegree) {
  let crossings = 0;
  const degreeThreshold = d3.median(Array.from(ipDegree.values())) || 5;

  // Group links by minute for efficient comparison
  const linksByTime = d3.group(links, l => l.minute);

  linksByTime.forEach((timeLinks, minute) => {
    for (let i = 0; i < timeLinks.length; i++) {
      for (let j = i + 1; j < timeLinks.length; j++) {
        const link1 = timeLinks[i];
        const link2 = timeLinks[j];

        // Skip if either arc connects to a hub or high-degree node
        const link1IsCore = ipDegree.get(link1.source) >= degreeThreshold ||
                           ipDegree.get(link1.target) >= degreeThreshold;
        const link2IsCore = ipDegree.get(link2.source) >= degreeThreshold ||
                           ipDegree.get(link2.target) >= degreeThreshold;

        if (link1IsCore || link2IsCore) continue;

        // Check if arcs cross
        if (arcsIntersect(link1, link2, yMap)) {
          crossings++;
        }
      }
    }
  });

  return crossings;
}

/**
 * Check if two arcs intersect geometrically.
 */
function arcsIntersect(arc1, arc2, yMap) {
  const y1_src = yMap.get(arc1.sourceNode.name);
  const y1_dst = yMap.get(arc1.targetNode.name);
  const y2_src = yMap.get(arc2.sourceNode.name);
  const y2_dst = yMap.get(arc2.targetNode.name);

  // Normalize so src < dst
  const [y1_min, y1_max] = y1_src < y1_dst ? [y1_src, y1_dst] : [y1_dst, y1_src];
  const [y2_min, y2_max] = y2_src < y2_dst ? [y2_src, y2_dst] : [y2_dst, y2_src];

  // Arcs cross if one starts below and ends above the other
  return (y1_min < y2_min && y1_max > y2_max) || (y2_min < y1_min && y2_max > y1_max);
}
```

### New Function 2: Hub-Preserving Compaction (~line 2010)

```javascript
/**
 * Modified compactIPPositions that preserves hub centrality.
 * Replaces current implementation at line 1962.
 */
function compactIPPositionsWithHubPreservation(
  simNodes, yMap, topMargin, INNER_HEIGHT, components, ipToComponent,
  componentHubIps, ipDegree, links
) {
  if (!components || components.length <= 1) {
    // Single component or no component info - use hub-aware single compaction
    compactSingleComponentWithHub(simNodes, yMap, topMargin, INNER_HEIGHT,
                                  componentHubIps, ipDegree, links);
    return;
  }

  // Multi-component: allocate space with explicit gaps
  const componentGap = 40; // pixels between components
  const usableHeight = INNER_HEIGHT - componentGap * (components.length - 1);

  // Allocate height proportional to component size
  let currentY = topMargin + 12;

  components.forEach((comp, compIdx) => {
    const compSize = comp.length;
    const totalNodes = simNodes.length;
    const compHeight = (compSize / totalNodes) * usableHeight;

    // Get hub for this component
    const hubIp = componentHubIps.get(compIdx);

    // Partition component nodes
    const partitions = partitionByDistanceFromHub(comp, hubIp, yMap, ipDegree);

    // Optimize periphery partitions
    const aboveOptimized = optimizePeripheryOrder(partitions.abovePeriphery, links, yMap, ipDegree);
    const belowOptimized = optimizePeripheryOrder(partitions.belowPeriphery, links, yMap, ipDegree);

    // Redistribute within component space, preserving hub at center
    const compCenter = currentY + compHeight / 2;

    // Hub stays at center
    yMap.set(hubIp, compCenter);

    // Distribute above nodes
    const aboveNodes = [...partitions.aboveCore, ...aboveOptimized];
    const aboveStep = aboveNodes.length > 0 ? (compHeight / 2 - 5) / aboveNodes.length : 0;
    aboveNodes.forEach((node, idx) => {
      yMap.set(node.id, currentY + idx * aboveStep);
    });

    // Distribute below nodes
    const belowNodes = [...partitions.belowCore, ...belowOptimized];
    const belowStep = belowNodes.length > 0 ? (compHeight / 2 - 5) / belowNodes.length : 0;
    belowNodes.forEach((node, idx) => {
      yMap.set(node.id, compCenter + 5 + idx * belowStep);
    });

    currentY += compHeight + componentGap;
  });

  console.log(`Compacted ${components.length} components with hub preservation`);
}

/**
 * Single component compaction with hub at center.
 */
function compactSingleComponentWithHub(simNodes, yMap, topMargin, INNER_HEIGHT,
                                       componentHubIps, ipDegree, links) {
  const hubIp = componentHubIps.get(0);
  const center = topMargin + INNER_HEIGHT / 2;

  // Partition and optimize
  const allNodes = simNodes.map(n => ({ id: n.id }));
  const partitions = partitionByDistanceFromHub(allNodes, hubIp, yMap, ipDegree);

  const aboveOptimized = optimizePeripheryOrder(partitions.abovePeriphery, links, yMap, ipDegree);
  const belowOptimized = optimizePeripheryOrder(partitions.belowPeriphery, links, yMap, ipDegree);

  // Hub at center
  yMap.set(hubIp, center);

  // Distribute above
  const aboveNodes = [...partitions.aboveCore, ...aboveOptimized];
  const aboveStep = Math.min((INNER_HEIGHT / 2 - 25) / (aboveNodes.length + 1), 15);
  aboveNodes.forEach((node, idx) => {
    yMap.set(node.id, topMargin + 12 + idx * aboveStep);
  });

  // Distribute below
  const belowNodes = [...partitions.belowCore, ...belowOptimized];
  const belowStep = Math.min((INNER_HEIGHT / 2 - 25) / (belowNodes.length + 1), 15);
  belowNodes.forEach((node, idx) => {
    yMap.set(node.id, center + 5 + idx * belowStep);
  });
}

/**
 * Get all neighbors of an IP from the links array.
 */
function getNeighbors(ip, links) {
  const neighbors = new Set();
  links.forEach(link => {
    if (link.sourceNode.name === ip) neighbors.add(link.targetNode.name);
    if (link.targetNode.name === ip) neighbors.add(link.sourceNode.name);
  });
  return Array.from(neighbors);
}
```

### Integration Point: Modify Render Function (~line 1092)

Replace the current compaction call:

```javascript
// CURRENT (line 1092):
compactIPPositions(simNodes, yMap, MARGIN.top, INNER_HEIGHT, components, ipToComponent);

// REPLACE WITH:
// Measure baseline crossings
const baselineCrossings = countPeripheryCrossings(linksWithNodes, yMap, ipToComponent, componentHubIps, ipDegree);
console.log(`Baseline peripheral crossings: ${baselineCrossings}`);

// Apply hub-preserving compaction with optimization
compactIPPositionsWithHubPreservation(
  simNodes, yMap, MARGIN.top, INNER_HEIGHT, components, ipToComponent,
  componentHubIps, ipDegree, linksWithNodes
);

// Measure optimized crossings
const optimizedCrossings = countPeripheryCrossings(linksWithNodes, yMap, ipToComponent, componentHubIps, ipDegree);
console.log(`Optimized peripheral crossings: ${optimizedCrossings} (${Math.round((1 - optimizedCrossings/baselineCrossings) * 100)}% reduction)`);
```

---

## Expected Outcomes

### Quantitative Improvements

| Metric | Before | After (Expected) |
|--------|--------|------------------|
| **Peripheral crossings** | Baseline | -30% to -60% |
| **Hub position deviation** | 0px | 0px (unchanged) |
| **Component gaps** | Minimal | 40px (explicit) |
| **Computation time** | ~200ms | ~300ms (+50%) |

### Qualitative Improvements

1. ✅ **Cleaner periphery**: Reduced visual clutter in low-degree regions
2. ✅ **Maintained structure**: Hub-centric star patterns preserved
3. ✅ **Better component separation**: Explicit gaps between disconnected clusters
4. ✅ **Temporal coherence**: IPs active at similar times grouped (via barycenter)

### What Does NOT Change

- ❌ Hub IP positions (stay centered)
- ❌ Force simulation logic (fully preserved)
- ❌ Core high-degree node positions (stable)
- ❌ Component membership (unchanged)

---

## Testing Strategy

### Phase 1: Baseline Measurement
```javascript
// Add before optimization
const metrics = {
  totalCrossings: countAllCrossings(linksWithNodes, yMap),
  peripheralCrossings: countPeripheryCrossings(linksWithNodes, yMap, ipToComponent, componentHubIps, ipDegree),
  hubDeviations: measureHubCentrality(componentHubIps, yMap, components)
};
console.table(metrics);
```

### Phase 2: Visual Inspection
1. Load test dataset (e.g., `set1_first90_minutes.csv`)
2. Verify hub IPs remain centered in components
3. Check for reduced crossing in periphery
4. Confirm component gaps are visible

### Phase 3: Performance Validation
```javascript
console.time('optimization');
compactIPPositionsWithHubPreservation(...);
console.timeEnd('optimization'); // Should be < 500ms for 1000 IPs
```

### Phase 4: Regression Testing
- Multi-component datasets: Check component separation
- Single-component datasets: Check hub centering
- Large datasets (>500 IPs): Check performance
- Small datasets (<50 IPs): Check graceful degradation

---

## Implementation Checklist

- [ ] Add `arcsIntersect()` helper function
- [ ] Add `countPeripheryCrossings()` function
- [ ] Add `getNeighbors()` helper function
- [ ] Add `partitionByDistanceFromHub()` function
- [ ] Add `optimizePeripheryOrder()` function
- [ ] Add `compactIPPositionsWithHubPreservation()` function
- [ ] Add `compactSingleComponentWithHub()` function
- [ ] Modify integration point at line ~1092
- [ ] Add baseline/optimized metrics logging
- [ ] Test with multiple datasets
- [ ] Validate hub positions unchanged
- [ ] Document crossing reduction percentage

---

## Risks and Mitigations

### Risk 1: Performance Degradation
**Impact**: Barycentric ordering is O(n²) worst case
**Mitigation**: Only optimize periphery (typically 50-70% of nodes), limit iterations to 5

### Risk 2: Hub Position Drift
**Impact**: Optimization accidentally moves hubs
**Mitigation**: Explicitly anchor hubs, validate positions before/after

### Risk 3: Component Mixing
**Impact**: Optimization crosses component boundaries
**Mitigation**: Process each component independently, maintain explicit gaps

### Risk 4: Minimal Visual Improvement
**Impact**: Crossing reduction not noticeable
**Mitigation**: Log metrics, compare before/after screenshots, iterate if needed

---

## Future Enhancements

### Phase 2 (Optional)
1. **Iterative improvement**: Run barycenter heuristic 3-5 times until convergence
2. **Local search**: Try greedy swaps of adjacent periphery nodes
3. **Temporal clustering**: Pre-group IPs by peak activity time before optimization

### Phase 3 (Advanced)
1. **Simulated annealing**: Global optimization with temperature schedule
2. **User control**: Slider to balance "hub centrality" vs "crossing minimization"
3. **Multi-objective**: Optimize for both crossings AND arc length simultaneously

---

## References

- **Graph Drawing**: Sugiyama et al. "Methods for Visual Understanding of Hierarchical System Structures" (1981)
- **Barycenter Heuristic**: Eades & Wormald "Edge Crossings in Drawings of Bipartite Graphs" (1994)
- **Force-Directed Layout**: Fruchterman & Reingold "Graph Drawing by Force-directed Placement" (1991)
- **TimeArcs**: Greilich et al. "Visualizing the Temporal Evolution of Dynamic Networks" (2009)

---

## Contact

For questions about this optimization plan:
- Review code in `attack_timearcs.js` lines 961-1092 (force simulation)
- Review code in `attack_timearcs.js` lines 1957-1987 (current compaction)
- See `src/layout/forceSimulation.js` for force calculation details
