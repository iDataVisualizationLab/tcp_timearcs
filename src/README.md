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

## Module Descriptions

### config/constants.js
- **Purpose**: Global configuration constants
- **Exports**: `MARGIN`, `DEFAULT_WIDTH`, `DEFAULT_HEIGHT`, `INNER_HEIGHT`, `PROTOCOL_COLORS`, `DEFAULT_COLOR`, `NEUTRAL_GREY`, `LENS_DEFAULTS`, `FISHEYE_DEFAULTS`
- **Dependencies**: None (pure constants)

### utils/helpers.js
- **Purpose**: Pure utility functions with no side effects
- **Exports**:
  - `toNumber(v)` - Safe number conversion
  - `sanitizeId(s)` - SVG ID sanitization
  - `canonicalizeName(s)` - Attack name normalization
  - `showTooltip(tooltip, evt, html)` - Display tooltip
  - `hideTooltip(tooltip)` - Hide tooltip
  - `setStatus(statusEl, msg)` - Update status message
- **Dependencies**: None (pure functions)

### mappings/decoders.js
- **Purpose**: IP address and attack type decoding/mapping
- **Exports**:
  - `decodeIp(value, idToAddr)` - Decode IP ID to dotted quad
  - `decodeAttack(value, idToName)` - Decode attack ID to name
  - `decodeAttackGroup(groupVal, fallbackVal, groupIdToName, attackIdToName)` - Decode attack group
  - `lookupAttackColor(name, rawColorMap, canonicalColorMap)` - Get color for attack
  - `lookupAttackGroupColor(name, rawColorMap, canonicalColorMap)` - Get color for attack group
- **Dependencies**: `canonicalizeName` from utils/helpers.js

### data/aggregation.js
- **Purpose**: Data aggregation and network graph computation
- **Exports**:
  - `buildRelationships(data)` - Build pairwise IP relationships
  - `computeConnectivityFromRelationships(relationships, threshold, allIps)` - Compute connectivity metrics
  - `computeLinks(data)` - Aggregate links per (src, dst, minute)
  - `findConnectedComponents(nodes, links)` - Find network components using DFS
- **Dependencies**: None (pure data processing)

### data/csvParser.js
- **Purpose**: Stream-based CSV file parsing
- **Exports**:
  - `parseCSVLine(line, delimiter)` - Parse single CSV line with quote handling
  - `parseCSVStream(file, onRow, options)` - Stream-parse entire CSV file
- **Dependencies**: None (pure parsing)
- **Features**:
  - Memory-efficient streaming
  - Handles CR/LF/CRLF line endings
  - Respects quoted fields with embedded commas
  - Handles escaped quotes

### rendering/arcPath.js
- **Purpose**: SVG path generation for network arcs
- **Exports**:
  - `linkArc(d)` - Generate curved arc path between nodes
  - `gradientIdForLink(d, sanitizeId)` - Generate unique gradient ID for link
- **Dependencies**: None (pure rendering functions)

### ui/legend.js
- **Purpose**: Interactive legend UI component
- **Exports**:
  - `buildLegend(container, items, colorFn, visibleAttacks, callbacks)` - Build legend with interactions
  - `updateLegendVisualState(container, visibleAttacks)` - Update legend visual state
  - `isolateAttack(attackName, visibleAttacks, container)` - Isolate/show-all attack toggle
- **Dependencies**: None (pure UI functions)
- **Features**:
  - Click to toggle visibility
  - Double-click to isolate
  - Hover effects
  - Visual state management

## Usage

### Import Specific Functions
```javascript
import { computeLinks, findConnectedComponents } from './src/data/aggregation.js';
import { linkArc } from './src/rendering/arcPath.js';
import { buildLegend } from './src/ui/legend.js';
```

### Import from Central Index
```javascript
import {
  computeLinks,
  linkArc,
  buildLegend,
  parseCSVStream,
  decodeIp
} from './src/index.js';
```

## Design Principles

1. **Separation of Concerns**: Each module has a single, well-defined responsibility
2. **Pure Functions**: Most functions are pure (no side effects) for easier testing
3. **Minimal Dependencies**: Modules have minimal cross-dependencies
4. **Reusability**: Functions designed to be reusable in other contexts
5. **Type Safety**: JSDoc comments provide type information

## Testing Strategy

Each module can be tested independently:

```javascript
// Example: Test CSV parser
import { parseCSVLine } from './src/data/csvParser.js';

const line = 'name,value,"quoted,field"';
const fields = parseCSVLine(line);
console.assert(fields.length === 3);
console.assert(fields[2] === 'quoted,field');
```

## Migration Path

The refactoring maintains backward compatibility:
- Original `attack_timearcs.js` imports from modules
- All functionality preserved
- No API changes for end users
- Future modules can be added incrementally

## Future Enhancements

Possible next steps:
1. Add TypeScript definitions (.d.ts files)
2. Create unit tests for each module
3. Bundle modules for production (Webpack/Rollup)
4. Extract more visualization logic (force layout, timeline)
5. Create shared types module
