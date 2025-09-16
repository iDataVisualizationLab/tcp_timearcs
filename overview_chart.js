// Overview chart module: manages stacked invalid flows overview, brush, and legends
// Internal state
let overviewSvg, overviewXScale, overviewBrush, overviewWidth = 0, overviewHeight = 100;
let isUpdatingFromBrush = false; // prevent circular updates
let isUpdatingFromZoom = false;  // prevent circular updates

// External references provided via init
let d3Ref = null;
let applyZoomDomainRef = null;
let getWidthRef = null;
let getTimeExtentRef = null;
let getChartMarginsRef = null;
let getCurrentFlowsRef = null;
let getSelectedFlowIdsRef = null;
let updateTcpFlowPacketsGlobalRef = null;
let sbRenderInvalidLegendRef = null;
let sbRenderClosingLegendRef = null;
let makeConnectionKeyRef = null;
let hiddenInvalidReasonsRef = null;
let hiddenCloseTypesRef = null;

// Config shared with main
let GLOBAL_BIN_COUNT = 600;
let flagColors = {};

export function initOverview(options) {
    d3Ref = options.d3;
    applyZoomDomainRef = options.applyZoomDomain;
    getWidthRef = options.getWidth;
    getChartMarginsRef = options.getChartMargins || (() => ({ left: 150, right: 120, top: 80, bottom: 50 }));
    getTimeExtentRef = options.getTimeExtent;
    getCurrentFlowsRef = options.getCurrentFlows;
    getSelectedFlowIdsRef = options.getSelectedFlowIds;
    updateTcpFlowPacketsGlobalRef = options.updateTcpFlowPacketsGlobal;
    sbRenderInvalidLegendRef = options.sbRenderInvalidLegend;
    sbRenderClosingLegendRef = options.sbRenderClosingLegend;
    makeConnectionKeyRef = options.makeConnectionKey;
    hiddenInvalidReasonsRef = options.hiddenInvalidReasons;
    hiddenCloseTypesRef = options.hiddenCloseTypes;
    GLOBAL_BIN_COUNT = options.GLOBAL_BIN_COUNT ?? GLOBAL_BIN_COUNT;
    flagColors = options.flagColors || {};
}

export function createOverviewChart(packets, { timeExtent, width, margins }) {
    const d3 = d3Ref;
    d3.select('#overview-chart').html('');
    const container = document.getElementById('overview-container');
    if (container) container.style.display = 'block';

    // Align overview with main chart: use identical inner width and left/right margins
    const chartMargins = margins || (getChartMarginsRef ? getChartMarginsRef() : { left: 150, right: 120, top: 80, bottom: 50 });
    const overviewMargin = { top: 10, right: chartMargins.right, bottom: 30, left: chartMargins.left };
    overviewWidth = Math.max(100, width);
    overviewHeight = 100;

    const overviewSvgContainer = d3.select('#overview-chart').append('svg')
        .attr('width', overviewWidth + overviewMargin.left + overviewMargin.right)
        .attr('height', overviewHeight + overviewMargin.top + overviewMargin.bottom);

    overviewSvg = overviewSvgContainer.append('g')
        .attr('transform', `translate(${overviewMargin.left},${overviewMargin.top})`);

    overviewXScale = d3.scaleLinear().domain(timeExtent).range([0, overviewWidth]);

    const binCount = GLOBAL_BIN_COUNT;
    const totalRange = Math.max(1, (timeExtent[1] - timeExtent[0]));
    const timeBinSize = totalRange / binCount;

    const allFlows = Array.isArray(getCurrentFlowsRef()) ? getCurrentFlowsRef() : [];
    // Separate invalid-like flows for the bottom histogram
    const invalidFlows = allFlows.filter(f => f && (f.closeType === 'invalid' || f.state === 'invalid' || f.invalidReason));
    // Separate closing types for the top histogram
    const closingTypes = ['graceful', 'abortive'];
    const closingFlows = allFlows.filter(f => f && closingTypes.includes(f.closeType));

    const invalidLabels = {
        'invalid_ack': 'Invalid ACK',
        'rst_during_handshake': 'RST during handshake',
        'incomplete_no_synack': 'Incomplete (no SYN+ACK)',
        'incomplete_no_ack': 'Incomplete (no ACK)',
        'invalid_synack': 'Invalid SYN+ACK',
        'unknown_invalid': 'Invalid (unspecified)'
    };
    const invalidDescriptions = {
        'invalid_ack': 'SYN and SYN+ACK observed but the final ACK from the client was missing, malformed, or out of order. The 3-way handshake did not complete cleanly.',
        'rst_during_handshake': 'A connection reset (RST) occurred during the TCP 3-way handshake before the session was established.',
        'incomplete_no_synack': 'A SYN was sent but no SYN+ACK response was observed. The server did not reply or the packet was not captured.',
        'incomplete_no_ack': 'SYN and SYN+ACK were seen, but the final ACK from the client was not observed to complete the handshake.',
        'invalid_synack': 'The SYN+ACK response was invalid (e.g., unexpected seq/ack numbers or incorrect flag combination).',
        'unknown_invalid': 'The flow was marked invalid, but no specific root cause was classified.'
    };
    const invalidFlowColors = {
        'invalid_ack': d3.color(flagColors['ACK'] || '#27ae60').darker(0.5).formatHex(),
        'invalid_synack': d3.color(flagColors['SYN+ACK'] || '#f39c12').darker(0.5).formatHex(),
        'rst_during_handshake': d3.color(flagColors['RST'] || '#34495e').darker(0.5).formatHex(),
        'incomplete_no_synack': d3.color(flagColors['SYN+ACK'] || '#f39c12').brighter(0.5).formatHex(),
        'incomplete_no_ack': d3.color(flagColors['ACK'] || '#27ae60').brighter(0.5).formatHex(),
        'unknown_invalid': d3.color(flagColors['OTHER'] || '#bdc3c7').darker(0.5).formatHex()
    };
    const invalidOrder = [
        'invalid_ack',
        'rst_during_handshake',
        'incomplete_no_synack',
        'incomplete_no_ack',
        'invalid_synack',
        'unknown_invalid'
    ];
    const getInvalidReason = (f) => {
        if (!f) return null;
        const r = f.invalidReason;
        if (r && invalidOrder.includes(r)) return r;
        if (f.closeType === 'invalid' || f.state === 'invalid') return 'unknown_invalid';
        return null;
    };

    const axisY = overviewHeight - 30;

    const presentReasonsSet = new Set();
    for (const f of invalidFlows) {
        if (f && (typeof f.startTime === 'number')) {
            const r = getInvalidReason(f);
            if (r) presentReasonsSet.add(r);
        }
    }
    const presentReasons = invalidOrder.filter(r => presentReasonsSet.has(r));
    const reasons = presentReasons.length ? presentReasons : ['unknown_invalid'];

    const rows = Math.max(1, reasons.length);
    const rowsHeight = Math.max(20, axisY - 6);
    const rowHeight = rowsHeight / rows;
    const reasonY = new Map(reasons.map((r, i) => [r, (i + 0.5) * rowHeight]));

    // Build binned maps for invalid reasons (bottom) and closing types (top)
    const binReasonMap = new Map();
    for (const f of invalidFlows) {
        if (!f || typeof f.startTime !== 'number') continue;
        const reason = getInvalidReason(f);
        if (!reason) continue;
        const idx = Math.min(
            binCount - 1,
            Math.max(0, Math.floor((f.startTime - timeExtent[0]) / timeBinSize))
        );
        let m = binReasonMap.get(idx);
        if (!m) { m = new Map(); binReasonMap.set(idx, m); }
        const arr = m.get(reason) || [];
        arr.push(f);
        m.set(reason, arr);
    }
    // Build bins for closing types (top histogram)
    const binCloseMap = new Map();
    for (const f of closingFlows) {
        if (!f || typeof f.startTime !== 'number') continue;
        const t = f.closeType;
        if (!closingTypes.includes(t)) continue;
        const idx = Math.min(
            binCount - 1,
            Math.max(0, Math.floor((f.startTime - timeExtent[0]) / timeBinSize))
        );
        let m = binCloseMap.get(idx);
        if (!m) { m = new Map(); binCloseMap.set(idx, m); }
        const arr = m.get(t) || [];
        arr.push(f);
        m.set(t, arr);
    }

    // Compute per-bin totals and global max per direction
    let maxBinTotalInvalid = 0;
    const binTotalsInvalid = new Map();
    for (let i = 0; i < binCount; i++) {
        const m = binReasonMap.get(i);
        let total = 0;
        if (m) for (const arr of m.values()) total += arr.length;
        binTotalsInvalid.set(i, total);
        if (total > maxBinTotalInvalid) maxBinTotalInvalid = total;
    }
    maxBinTotalInvalid = Math.max(1, maxBinTotalInvalid);

    let maxBinTotalClosing = 0;
    const binTotalsClosing = new Map();
    for (let i = 0; i < binCount; i++) {
        const m = binCloseMap.get(i);
        let total = 0;
        if (m) for (const arr of m.values()) total += arr.length;
        binTotalsClosing.set(i, total);
        if (total > maxBinTotalClosing) maxBinTotalClosing = total;
    }
    maxBinTotalClosing = Math.max(1, maxBinTotalClosing);

    // Layout heights
    const chartHeightUp = Math.max(10, axisY - 6);
    const brushTopY = overviewHeight - 4; // top of brush selection area
    const chartHeightDown = Math.max(6, brushTopY - axisY - 4); // keep a tiny gap from brush

    // Colors for closing types (top)
    const closeColors = {
        graceful: '#8e44ad',
        abortive: '#c0392b'
    };

    // Prepare render data for both directions
    const segments = [];
    for (let i = 0; i < binCount; i++) {
        const binStartTime = timeExtent[0] + i * timeBinSize;
        const binEndTime = binStartTime + timeBinSize;
        const x0 = overviewXScale(binStartTime);
        const x1 = overviewXScale(binEndTime);
        const widthPx = Math.max(1, x1 - x0);
        const baseX = x0;

        // Upward stacking: closing types
        let yTop = axisY;
        const mTop = binCloseMap.get(i) || new Map();
        const totalTop = binTotalsClosing.get(i) || 0;
        if (totalTop > 0) {
            for (const t of closingTypes) {
                const arr = mTop.get(t) || [];
                const count = arr.length;
                if (count === 0) continue;
                const h = (count / maxBinTotalClosing) * chartHeightUp;
                yTop -= h;
                segments.push({
                    kind: 'closing', closeType: t, reason: null,
                    x: baseX, y: yTop, width: widthPx, height: h,
                    count, flows: arr, binIndex: i
                });
            }
        }

        // Downward stacking: invalid reasons
        let yBottom = axisY;
        const mBot = binReasonMap.get(i) || new Map();
        const totalBot = binTotalsInvalid.get(i) || 0;
        if (totalBot > 0) {
            for (const reason of reasons) {
                const arr = mBot.get(reason) || [];
                const count = arr.length;
                if (count === 0) continue;
                const h = (count / maxBinTotalInvalid) * chartHeightDown;
                const y = yBottom; // start at baseline and grow downward
                yBottom += h;
                segments.push({
                    kind: 'invalid', reason, closeType: null,
                    x: baseX, y, width: widthPx, height: h,
                    count, flows: arr, binIndex: i
                });
            }
        }
    }

    // Render combined segments
    overviewSvg.selectAll('.overview-stack-segment')
        .data(segments)
        .enter().append('rect')
        .attr('class', 'overview-stack-segment')
        .attr('x', d => d.x)
        .attr('y', d => d.y)
        .attr('width', d => d.width)
        .attr('height', d => Math.max(1, d.height))
        .attr('fill', d => d.kind === 'invalid' ? (invalidFlowColors[d.reason] || '#6c757d') : (closeColors[d.closeType] || '#6c757d'))
        .attr('stroke', '#ffffff')
        .attr('stroke-width', 0.5)
        .attr('vector-effect', 'non-scaling-stroke')
        .style('cursor', 'pointer')
        .on('mouseover', (event, d) => {
            const sx = 5.0; // horizontal magnification on hover
            const targetSy = 3.0; // vertical magnification target on hover
            const upTotal = (binTotalsClosing && binTotalsClosing.get) ? (binTotalsClosing.get(d.binIndex) || 0) : 0;
            const downTotal = (binTotalsInvalid && binTotalsInvalid.get) ? (binTotalsInvalid.get(d.binIndex) || 0) : 0;
            const upHeight = (upTotal / Math.max(1, maxBinTotalClosing)) * chartHeightUp;
            const downHeight = (downTotal / Math.max(1, maxBinTotalInvalid)) * chartHeightDown;
            let sy = targetSy;
            if (upHeight > 0) sy = Math.min(sy, chartHeightUp / upHeight);
            if (downHeight > 0) sy = Math.min(sy, chartHeightDown / downHeight);
                sy = Math.max(1.2, sy);
                overviewSvg.selectAll('.overview-stack-segment')
                    .filter(s => s.binIndex === d.binIndex)
                    .transition().duration(200)
                    .attr('transform', s => {
                        const cx = s.x + s.width / 2;
                        const axisY = overviewHeight - 30;
                        return `translate(${cx},${axisY}) scale(${sx},${sy}) translate(${-cx},${-axisY})`;
                    })
                    .attr('stroke-width', 3.0);
        })
        .on('mouseout', (event, d) => {
            overviewSvg.selectAll('.overview-stack-segment')
                .filter(s => s.binIndex === d.binIndex)
                .transition().duration(180)
                .attr('transform', null)
                .attr('stroke-width', 0.5);
        })
        .on('click', (event, d) => {
            const timeExtent = getTimeExtentRef();
            if (!timeExtent) return;
            const width = getWidthRef();
            const binCount = GLOBAL_BIN_COUNT;
            const totalRange = Math.max(1, timeExtent[1] - timeExtent[0]);
            const timeBinSize = totalRange / binCount;

            const binStartTime = timeExtent[0] + (d.binIndex * timeBinSize);
            const binEndTime = binStartTime + timeBinSize;
            const timePerPixel = totalRange / Math.max(1, width);
            const minPaddingUs = 20000;
            const paddingFromPixels = Math.ceil(1 * timePerPixel);
            const padding = Math.max(minPaddingUs, paddingFromPixels);

            let a = Math.max(timeExtent[0], Math.floor(binStartTime - padding));
            let b = Math.min(timeExtent[1], Math.ceil(binEndTime + padding));
            if (b <= a) b = Math.min(timeExtent[1], a + 1);
            applyZoomDomainRef([a, b], 'flow');
            try { updateBrushFromZoom(); } catch {}

            const bucket = (d.kind === 'invalid') ? (binReasonMap.get(d.binIndex) || new Map())
                                                 : (binCloseMap.get(d.binIndex) || new Map());
            const binFlows = Array.from(bucket.values()).flat();
            if (!binFlows.length) return;
            try {
                const idsToSelect = new Set(binFlows.map(f => String(f.id)));
                const selectedFlowIds = getSelectedFlowIdsRef();
                selectedFlowIds.clear();
                idsToSelect.forEach(id => selectedFlowIds.add(id));
                const list = document.getElementById('flowList');
                if (list) {
                    list.querySelectorAll('.flow-item').forEach(item => {
                        const fid = item.getAttribute('data-flow-id');
                        const checked = idsToSelect.has(String(fid));
                        const checkbox = item.querySelector('.flow-checkbox');
                        if (checkbox) checkbox.checked = checked;
                        if (checked) item.classList.add('selected'); else item.classList.remove('selected');
                    });
                }
                updateTcpFlowPacketsGlobalRef();
            } catch (e) {
                console.warn('Failed to select flows from overview bin click:', e);
            }
        })
        .append('title')
        .text(d => `${d.count} ${d.kind === 'invalid' ? 'invalid' : d.closeType} flow(s)`);

    // Legends
    try {
        const panel = document.getElementById('invalidLegendPanel');
        if (panel) {
            const legendReasons = [
                'invalid_ack',
                'rst_during_handshake',
                'incomplete_no_synack',
                'incomplete_no_ack',
                'invalid_synack',
                'unknown_invalid'
            ];
            const totalsByReason = new Map(legendReasons.map(r => [r, 0]));
            for (const f of invalidFlows) {
                let r = getInvalidReason(f);
                if (!r) r = 'unknown_invalid';
                if (totalsByReason.has(r)) totalsByReason.set(r, totalsByReason.get(r) + 1);
            }
            const totalAll = Array.from(totalsByReason.values()).reduce((a, b) => a + b, 0);
            const itemsHtml = legendReasons.map(r => {
                const color = (invalidFlowColors[r] || '#6c757d');
                const label = (invalidLabels[r] || 'Invalid');
                const count = (totalsByReason.get(r) || 0);
                return `<div class="invalid-legend-item" data-reason="${r}" style="display:flex; align-items:center; gap:8px; margin:4px 0; cursor:default;">
                            <span style="display:inline-block; width:10px; height:10px; border-radius:50%; background:${color}; border:1px solid #fff; box-shadow: 0 0 0 1px rgba(0,0,0,0.1);"></span>
                            <span style="flex:1; color:#333;">${label}</span>
                            <span style="color:#555;">${count}</span>
                        </div>`;
            }).join('');
            sbRenderInvalidLegendRef(panel, itemsHtml || '<div style="color:#666;">No invalid flows</div>', `Invalid flows: ${totalAll}`);
            try {
                const tooltipSel = d3.select('#tooltip');
                panel.querySelectorAll('.invalid-legend-item').forEach((el) => {
                    const reason = el.getAttribute('data-reason');
                    el.style.cursor = 'pointer';
                    el.addEventListener('click', () => {
                        if (!reason) return;
                        const setRef = hiddenInvalidReasonsRef;
                        if (setRef.has(reason)) setRef.delete(reason); else setRef.add(reason);
                        try { updateOverviewInvalidVisibility(); } catch {}
                    });
                    el.addEventListener('mouseover', (event) => {
                        tooltipSel.style('display', 'block').html(`<b>${invalidLabels[reason] || 'Invalid'}</b>`);
                    });
                    el.addEventListener('mousemove', (event) => {
                        tooltipSel.style('left', `${event.pageX + 12}px`).style('top', `${event.pageY - 8}px`);
                    });
                    el.addEventListener('mouseout', () => {
                        tooltipSel.style('display', 'none');
                    });
                });
            } catch {}
        }
    } catch (e) {}

    try {
        const cpanel = document.getElementById('closingLegendPanel');
        if (cpanel) {
            const flowsAll = Array.isArray(getCurrentFlowsRef()) ? getCurrentFlowsRef() : [];
            const graceful = flowsAll.filter(f => f && f.closeType === 'graceful').length;
            const abortive = flowsAll.filter(f => f && f.closeType === 'abortive').length;
            const unknown = flowsAll.filter(f => f && (!f.closeType || (f.closeType !== 'graceful' && f.closeType !== 'abortive'))).length;
            const entries = [
                { type: 'graceful', label: 'Graceful closes', color: '#8e44ad', count: graceful },
                { type: 'abortive', label: 'Abortive (RST)', color: '#c0392b', count: abortive },
                { type: 'unknown', label: 'Unknown', color: '#6c757d', count: unknown }
            ];
            const total = graceful + abortive + unknown;
            const itemsHtml = entries.map(e => `
                <div class="closing-legend-item" data-type="${e.type}" style="display:flex; align-items:center; gap:8px; margin:4px 0; cursor:pointer;">
                    <span style="display:inline-block; width:10px; height:10px; border-radius:2px; background:${e.color}; border:1px solid #fff; box-shadow: 0 0 0 1px rgba(0,0,0,0.1);"></span>
                    <span style="flex:1; color:#333;">${e.label}</span>
                    <span style="color:#555;">${e.count}</span>
                </div>
            `).join('');
            sbRenderClosingLegendRef(cpanel, itemsHtml || '<div style="color:#666;">No closing data</div>', `Closing types (flows: ${total})`);
            cpanel.querySelectorAll('.closing-legend-item').forEach((el) => {
                el.addEventListener('click', () => {
                    const t = el.getAttribute('data-type');
                    if (!t) return;
                    const setRef = hiddenCloseTypesRef;
                    if (setRef.has(t)) setRef.delete(t); else setRef.add(t);
                    try { updateOverviewInvalidVisibility(); } catch {}
                });
            });
        }
    } catch {}

    const overviewXAxis = d3.axisBottom(overviewXScale)
        .ticks(6)
        .tickFormat(d => {
            const date = new Date(Math.floor(d) / 1000);
            return date.toISOString().split('T')[1].substring(0, 5);
        });

    overviewSvg.append('g')
        .attr('class', 'overview-axis')
        .attr('transform', `translate(0,${overviewHeight - 30})`)
        .call(overviewXAxis);

    const bandTop = overviewHeight - 4;
    const bandBottom = overviewHeight;
    overviewBrush = d3.brushX()
        .extent([[0, bandTop], [overviewWidth, bandBottom]])
        .on('brush end', brushed);

    overviewSvg.append('g').attr('class', 'brush').call(overviewBrush);
    // Initialize brush selection to match the provided timeExtent domain
    try {
        const x0 = Math.max(0, Math.min(overviewWidth, overviewXScale(timeExtent[0])));
        const x1 = Math.max(0, Math.min(overviewWidth, overviewXScale(timeExtent[1])));
        const brushSel = overviewSvg.select('.brush');
        if (brushSel && !brushSel.empty()) {
            overviewSvg.select('.brush').call(overviewBrush.move, [x0, x1]);
        }
    } catch (e) {
        // Fallback to full selection if computation fails
        try { overviewSvg.select('.brush').call(overviewBrush.move, [0, overviewWidth]); } catch(_) {}
    }

    const lineY = overviewHeight - 1;
    if (!overviewSvg.select('.overview-custom').node()) {
        const custom = overviewSvg.append('g').attr('class', 'overview-custom');
        custom.append('line').attr('class', 'overview-window-line').attr('x1', 0).attr('x2', Math.max(0, overviewWidth)).attr('y1', lineY).attr('y2', lineY);
        custom.append('circle').attr('class', 'overview-handle left').attr('r', 6).attr('cx', 0).attr('cy', lineY);
        custom.append('circle').attr('class', 'overview-handle right').attr('r', 6).attr('cx', Math.max(0, overviewWidth)).attr('cy', lineY);
        custom.append('rect').attr('class', 'overview-window-grab').attr('x', 0).attr('y', lineY - 8).attr('width', overviewWidth).attr('height', 16);

        const getSel = () => d3.brushSelection(overviewSvg.select('.brush').node()) || [0, overviewWidth];
        const moveBrushTo = (x0, x1) => {
            x0 = Math.max(0, Math.min(overviewWidth, x0));
            x1 = Math.max(0, Math.min(overviewWidth, x1));
            if (x1 <= x0) x1 = Math.min(overviewWidth, x0 + 1);
            overviewSvg.select('.brush').call(overviewBrush.move, [x0, x1]);
        };
        const updateCustomFromSel = () => {
            const [x0, x1] = getSel();
            const lineY = overviewHeight - 1;
            custom.select('.overview-window-line').attr('x1', x0).attr('x2', x1).attr('y1', lineY).attr('y2', lineY);
            custom.select('.overview-handle.left').attr('cx', x0).attr('cy', lineY);
            custom.select('.overview-handle.right').attr('cx', x1).attr('cy', lineY);
            custom.select('.overview-window-grab').attr('x', x0).attr('y', lineY - 8).attr('width', Math.max(1, x1 - x0)).attr('height', 16);
        };
        updateCustomFromSel();
        custom.select('.overview-handle.left').call(d3.drag().on('drag', (event) => { const x0 = event.x; const [, x1] = getSel(); moveBrushTo(x0, x1); updateCustomFromSel(); }));
        custom.select('.overview-handle.right').call(d3.drag().on('drag', (event) => { const x1 = event.x; const [x0] = getSel(); moveBrushTo(x0, x1); updateCustomFromSel(); }));
        custom.select('.overview-window-grab').call(d3.drag().on('drag', (event) => { const [x0, x1] = getSel(); moveBrushTo(x0 + event.dx, x1 + event.dx); updateCustomFromSel(); }));
    }

    try { updateOverviewInvalidVisibility(); } catch {}

    // Ensure brush visuals reflect current zoom domain after creating overview
    try { updateBrushFromZoom(); } catch (_) {}
}

export function updateBrushFromZoom() {
    if (isUpdatingFromBrush || !overviewBrush || !overviewXScale || !overviewSvg) return;
    isUpdatingFromZoom = true;
    const currentDomain = getCurrentDomain();
    const x0 = Math.max(0, Math.min(overviewWidth, overviewXScale(currentDomain[0])));
    const x1 = Math.max(0, Math.min(overviewWidth, overviewXScale(currentDomain[1])));
    if (x1 > x0) {
        overviewSvg.select('.brush').call(overviewBrush.move, [x0, x1]);
        try { updateCustomFromZoom(x0, x1); } catch {}
    }
    isUpdatingFromZoom = false;
}

export function setBrushUpdating(flag) {
    isUpdatingFromBrush = !!flag;
}

function updateCustomFromZoom(x0, x1) {
    const custom = overviewSvg.select('.overview-custom');
    if (custom && !custom.empty()) {
        const lineY = overviewHeight - 1;
        custom.select('.overview-window-line').attr('x1', x0).attr('x2', x1).attr('y1', lineY).attr('y2', lineY);
        custom.select('.overview-handle.left').attr('cx', x0).attr('cy', lineY);
        custom.select('.overview-handle.right').attr('cx', x1).attr('cy', lineY);
        custom.select('.overview-window-grab').attr('x', x0).attr('y', lineY - 8).attr('width', Math.max(1, x1 - x0)).attr('height', 16);
    }
}

function getCurrentDomain() {
    const timeExtent = getTimeExtentRef();
    // main file will update xScale domain; we just ask it to map current domain
    // Expose via getWidthRef / applyZoomDomainRef; for brush sync we rely on caller providing domain
    // Here we assume caller updated xScale so timeExtent bounds are still valid
    // The main passes current domain via a getter when calling updateBrushFromZoom indirectly
    // To avoid tight coupling, we compute domain from window: callers should pass it in options if needed
    // For now, piggyback by reading from a global xScale on window if present
    if (window && window.__arc_x_domain__) return window.__arc_x_domain__;
    // Fallback to full
    return timeExtent;
}

function brushed(event) {
    if (isUpdatingFromZoom) return; // Prevent circular updates
    if (!overviewXScale) return;
    const sel = event.selection;
    if (!sel) return;
    const [x0, x1] = sel;
    const newDomain = [overviewXScale.invert(x0), overviewXScale.invert(x1)];
    const d3 = d3Ref;
    const custom = overviewSvg && overviewSvg.select('.overview-custom');
    if (custom && !custom.empty()) {
        const lineY = overviewHeight - 1;
        custom.select('.overview-window-line').attr('x1', x0).attr('x2', x1).attr('y1', lineY).attr('y2', lineY);
        custom.select('.overview-handle.left').attr('cx', x0).attr('cy', lineY);
        custom.select('.overview-handle.right').attr('cx', x1).attr('cy', lineY);
        custom.select('.overview-window-grab').attr('x', x0).attr('y', lineY - 8).attr('width', Math.max(1, x1 - x0)).attr('height', 16);
    }
    applyZoomDomainRef(newDomain, 'brush');
}

export function updateOverviewInvalidVisibility() {
    if (!overviewSvg) return;
    const hiddenReasons = hiddenInvalidReasonsRef;
    const hiddenCloses = hiddenCloseTypesRef;
    const noReasonHidden = !hiddenReasons || hiddenReasons.size === 0;
    const noCloseHidden = !hiddenCloses || hiddenCloses.size === 0;
    overviewSvg.selectAll('.overview-stack-segment')
        .style('display', d => {
            if (!d) return null;
            if (d.kind === 'invalid') {
                return (noReasonHidden || !d.reason || !hiddenReasons.has(d.reason)) ? null : 'none';
            }
            if (d.kind === 'closing') {
                return (noCloseHidden || !d.closeType || !hiddenCloses.has(d.closeType)) ? null : 'none';
            }
            return null;
        })
        .style('opacity', d => {
            if (!d) return null;
            if (d.kind === 'invalid') {
                return (noReasonHidden || !d.reason || !hiddenReasons.has(d.reason)) ? null : 0;
            }
            if (d.kind === 'closing') {
                return (noCloseHidden || !d.closeType || !hiddenCloses.has(d.closeType)) ? null : 0;
            }
            return null;
        });
}
