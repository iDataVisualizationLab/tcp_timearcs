# Lensing/Magnification Feature Implementation

## Overview
Successfully implemented a time-based magnification ("lensing") feature for the attack_timearcs.js visualization, similar to the magnification effect in Text/myscripts/main.js.

## Features Implemented

### 1. Core Lensing Engine
- **Location**: Lines 60-64, 871-927 in [attack_timearcs.js](attack_timearcs.js)
- **State Variables**:
  - `isLensing`: Boolean toggle for enabling/disabling lensing
  - `lensingMul`: Magnification multiplier (default: 5x)
  - `focusTime`: Current timestamp being magnified
  - `lensingRange`: Number of time units to magnify on each side

### 2. Lensing-Aware Scale Function
- **Location**: Lines 871-927
- **Function**: `xScaleWithLensing(timestamp)`
- **Logic**:
  - Returns normal scale when lensing is disabled
  - When enabled, divides timeline into 3 regions:
    1. **Before focus**: Compressed region
    2. **Focus area**: Magnified by `lensingMul` (5x)
    3. **After focus**: Compressed region
  - Maintains continuity between regions
  - Preserves total timeline width

### 3. UI Controls
- **Button Toggle** (line 81-83 in attack_timearcs.html):
  - Located in header controls section
  - Visual feedback when active (blue background)
  - Icon: 🔍 Lensing

- **Mouse Tracking Overlay** (lines 1317-1382):
  - Transparent overlay on chart area
  - Tracks mouse position to update focus point
  - Throttled to 60fps for performance
  - Crosshair cursor when lensing is active

### 4. Smooth Transitions
- **Function**: `updateLensingPositions()` (lines 120-157)
- **Duration**: 250ms
- **Updates**:
  - Arc paths
  - Gradient positions
  - Row lines
  - All smoothly animated with D3 transitions

### 5. Integration Points
All x-position calculations updated to use `xScaleWithLensing()`:
- Arc path generation (line 1104)
- Gradient positioning (lines 1077-1078)
- Row line spans (lines 1404-1405)
- Direction dots (line 1153)
- Arc animations (lines 1508, 1525, 1531)
- Max arc extent calculations (line 914)

## How to Use

### Basic Usage
1. Load a CSV file with network data
2. Click the "🔍 Lensing" button in the header to enable
3. Move your mouse over the chart area
4. The timeline magnifies around your mouse position
5. Click the button again to disable

### Advanced Tips
- **Adjust magnification**: Change `lensingMul` variable (line 62) to increase/decrease zoom level
- **Change focus range**: Modify `lensingRange` variable (line 64) to adjust width of magnified region
- **Auto-disable on mouseleave**: Uncomment lines 1373-1378 to disable lensing when mouse leaves chart

## Technical Details

### Timestamp Conversion
The implementation handles multiple timestamp formats:
- Absolute timestamps (microseconds, milliseconds, seconds, minutes, hours)
- Relative timestamps (normalized to start at 0)
- Proper conversion back and forth between display positions and data values

### Performance Optimizations
- **Throttling**: Mouse updates limited to 60fps (16ms interval)
- **Selective updates**: Only updates visible elements
- **Hardware acceleration**: Uses D3 transitions which leverage CSS transforms
- **Event delegation**: Single overlay for mouse tracking vs. per-element handlers

### Interaction Preservation
- Arc hover effects still work
- Tooltips remain functional
- Legend filtering unaffected
- Attack visibility toggles work normally
- The overlay uses `.lower()` to stay below interactive elements

## Architecture Decisions

### Why xScaleWithLensing() Wrapper?
- Clean separation of concerns
- Minimal changes to existing code
- Easy to enable/disable
- No performance impact when disabled (simple if check)

### Why Store Current* Variables?
- Button toggle can update from anywhere
- Mouse handler can access render-time data
- Supports re-rendering with new data
- Enables future features (keyboard shortcuts, etc.)

### Why Not Update Axis?
- Axis would become confusing when distorted
- Maintains time reference for users
- Simpler implementation
- Can be added later if desired

## Future Enhancements

### Potential Additions
1. **Adjustable magnification slider**: Let users control zoom level
2. **Keyboard shortcuts**: Press 'L' to toggle, +/- to adjust zoom
3. **Lensed axis**: Show distorted time labels in focus region
4. **Visual indicator**: Highlight the magnified region with subtle overlay
5. **Multiple focus points**: Magnify several regions simultaneously
6. **Persistent state**: Remember lensing preference in localStorage
7. **Touch support**: Enable on mobile devices with touch events

### Code Locations for Extensions
- Add slider UI: After line 83 in attack_timearcs.html
- Keyboard handlers: After line 100 in attack_timearcs.js
- Visual indicators: In updateLensingPositions() function
- URL persistence: In init() function

## Testing Checklist

- [x] Button toggle works (visual feedback)
- [x] Mouse tracking updates focus position
- [x] Arcs magnify around focus point
- [x] Gradients follow arc positions
- [x] Row lines update correctly
- [ ] Test with different timestamp formats (seconds, minutes, hours)
- [ ] Test with very large datasets (>10k arcs)
- [ ] Test with very small datasets (<10 arcs)
- [ ] Verify no performance degradation
- [ ] Check browser compatibility (Chrome, Firefox, Safari)
- [ ] Verify mobile/touch devices (if applicable)

## Known Limitations

1. **Axis not updated**: Time labels remain in original positions (intentional)
2. **Scrolling**: Lensing doesn't account for horizontal scroll position yet
3. **Edge cases**: Focus near timeline edges may need clamping improvements
4. **Very large magnifications**: Values >10x may cause visual artifacts

## Troubleshooting

### Lensing not working?
- Check console for errors
- Ensure data is loaded (button only works after render)
- Verify browser supports ES6+ features
- Try disabling browser extensions

### Performance issues?
- Reduce `lensingMul` to lower value (e.g., 3)
- Increase throttle delay from 16ms to 33ms
- Filter dataset to fewer records
- Disable other features while lensing

### Arcs disappearing?
- May be out of visible range when magnified
- Try scrolling horizontally
- Reduce magnification multiplier
- Check focusTime is within valid range

## Credits

Implementation inspired by the magnification technique in:
- [Text/myscripts/main.js](Text/myscripts/main.js:95-123) - Original lensing function
- [Text/myscripts/util.js](Text/myscripts/util.js:255-320) - UI controls reference

---

**Implementation Date**: 2025-11-10
**Version**: 1.0
**Status**: Complete and ready for testing
