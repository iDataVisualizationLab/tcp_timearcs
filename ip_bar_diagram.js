// Extracted from ip_arc_diagram_3.html inline script
// This file contains all logic for the IP Connection Analysis visualization
import { initSidebar, createIPCheckboxes as sbCreateIPCheckboxes, filterIPList as sbFilterIPList, filterFlowList as sbFilterFlowList, updateFlagStats as sbUpdateFlagStats, updateIPStats as sbUpdateIPStats, createFlowListCapped as sbCreateFlowListCapped, updateTcpFlowStats as sbUpdateTcpFlowStats, updateGroundTruthStatsUI as sbUpdateGroundTruthStatsUI, wireSidebarControls as sbWireSidebarControls, showFlowProgress as sbShowFlowProgress, updateFlowProgress as sbUpdateFlowProgress, hideFlowProgress as sbHideFlowProgress, wireFlowListModalControls as sbWireFlowListModalControls, showCsvProgress as sbShowCsvProgress, updateCsvProgress as sbUpdateCsvProgress, hideCsvProgress as sbHideCsvProgress } from './sidebar.js';
import { renderInvalidLegend as sbRenderInvalidLegend, renderClosingLegend as sbRenderClosingLegend, drawFlagLegend as drawFlagLegendFromModule } from './legends.js';
import { initOverview, createOverviewChart, updateBrushFromZoom, updateOverviewInvalidVisibility, setBrushUpdating } from './overview_chart.js';
import { GLOBAL_BIN_COUNT, FLOW_RECONSTRUCT_BATCH } from './config.js';
import {
    DEBUG, RADIUS_MIN, RADIUS_MAX, ROW_GAP, TOP_PAD,
    TCP_STATES, HANDSHAKE_TIMEOUT_MS, REORDER_WINDOW_PKTS, REORDER_WINDOW_MS,
    DEFAULT_FLAG_COLORS, FLAG_CURVATURE, PROTOCOL_MAP,
    DEFAULT_FLOW_COLORS, DEFAULT_EVENT_COLORS
} from './src/config/constants.js';
import {
    LOG, formatBytes, formatTimestamp, formatDuration,
    utcToEpochMicroseconds, epochMicrosecondsToUTC,
    makeConnectionKey, clamp, normalizeProtocolValue
} from './src/utils/formatters.js';
import {
    classifyFlags, flagPhase, isFlagVisibleByPhase,
    has, isSYN, isSYNACK, isACKonly,
    getColoredFlagBadges, getTopFlags
} from './src/tcp/flags.js';
import {
    calculateZoomLevel, getBinSize, getVisiblePackets,
    binPackets, computeBarWidthPx, getEffectiveBinCount
} from './src/data/binning.js';
import {
    reconstructFlowsFromCSVAsync,
    reconstructFlowsFromCSV,
    buildSelectedFlowKeySet as buildSelectedFlowKeySetFromModule,
    verifyFlowPacketConnection,
    exportFlowToCSV as exportFlowToCSVFromModule
} from './src/data/flowReconstruction.js';
import { renderCircles } from './src/rendering/circles.js';
import { renderBars, renderMarksForLayer } from './src/rendering/bars.js';
import { createTooltipHTML } from './src/rendering/tooltip.js';
import { arcPathGenerator } from './src/rendering/arcPath.js';
import {
    buildForceLayoutData,
    computeForceLayoutPositions as computeForceLayoutPositionsBase,
    applyForceLayoutPositions as applyForceLayoutPositionsBase
} from './src/layout/barForceLayout.js';
import { createZoomBehavior, applyZoomDomain as applyZoomDomainFromModule } from './src/interaction/zoom.js';
import { createDragReorderBehavior } from './src/interaction/dragReorder.js';
import { setupWindowResizeHandler as setupWindowResizeHandlerFromModule } from './src/interaction/resize.js';
import {
    loadGroundTruthData,
    filterGroundTruthByIPs,
    prepareGroundTruthBoxData,
    calculateGroundTruthStats
} from './src/groundTruth/groundTruth.js';
import {
    createPacketWorkerManager,
    applyVisibilityToDots
} from './src/workers/packetWorkerManager.js';

// --- Web Worker for packet filtering ---
let workerManager = null;

function initializeWorkerManager() {
    workerManager = createPacketWorkerManager({
        onVisibilityApplied: (mask) => {
            if (!mainGroup) {
                console.warn('Worker visibility applied but mainGroup not available');
                return;
            }
            const dots = mainGroup.selectAll('.direction-dot').nodes();
            if (DEBUG && dots.length !== mask.length) {
                console.warn(`Worker mask/dots mismatch: mask=${mask.length}, dots=${dots.length}. This may indicate DOM was updated after worker init.`);
            }
            applyVisibilityToDots(mask, dots, {
                onComplete: () => {
                    try { applyInvalidReasonFilter(); } catch(_) {}
                }
            });
        },
        onError: (error) => {
            console.error('Worker error, falling back to legacy filtering:', error);
            legacyFilterPacketsBySelectedFlows();
        }
    });
}

function reinitializeWorkerIfNeeded(packets) {
    if (workerManager && packets) {
        try {
            workerManager.initPackets(packets);
        } catch (err) {
            console.error('Failed to reinitialize worker:', err);
            legacyFilterPacketsBySelectedFlows();
        }
    }
}

function syncWorkerWithRenderedData() {
    if (!workerManager || !mainGroup) return;
    
    // Get currently rendered dots data
    const dots = mainGroup.selectAll('.direction-dot');
    const renderedData = [];
    
    dots.each(function(d) {
        if (d) {
            // Extract the data bound to each DOM element
            renderedData.push({
                src_ip: d.src_ip,
                dst_ip: d.dst_ip,
                src_port: d.src_port,
                dst_port: d.dst_port,
                _packetIndex: renderedData.length // Use array index as packet index
            });
        }
    });
    
    if (renderedData.length > 0) {
        try {
            workerManager.initPackets(renderedData);
        } catch (err) {
            console.error('Failed to sync worker with rendered data:', err);
        }
    }
}
let fullData = [];
let filteredData = [];
let svg, mainGroup, width, height, xScale, yScale, zoom;
// Bottom overlay (fixed area above overview) for main x-axis and legends
let bottomOverlaySvg = null;
let bottomOverlayRoot = null;
let bottomOverlayAxisGroup = null;
let bottomOverlayDurationLabel = null;
let bottomOverlayWidth = 0;
let bottomOverlayHeight = 140; // generous to fit axis + legends without changing sizes
let chartMarginLeft = 150;
let chartMarginRight = 120;
// Layers for performance tuning: persistent full-domain layer and dynamic zoom layer
let fullDomainLayer = null;
let dynamicLayer = null;
// The element that has the zoom behavior attached (svg container)
let zoomTarget = null;
let dotsSelection; // Cache the dots selection for performance
        
// Overview timeline variables moved to overview_chart.js
let isHardResetInProgress = false; // Programmatic Reset View fast-path
let timeExtent = [0, 0]; // Global time extent for the dataset
// Global bin count is sourced from shared config.js
let pairs = new Map(); // Global pairs map for IP pairing system
let ipPositions = new Map(); // Global IP positions map
let ipOrder = []; // Current vertical order of IPs

// Force layout for IP positioning
let forceLayout = null;
let forceNodes = [];
let forceLinks = [];
let isForceLayoutRunning = false;
let tcpFlows = []; // Store detected TCP flows (from CSV)
let currentFlows = []; // Flows matching current IP selection (subset of tcpFlows)
let selectedFlowIds = new Set(); // Store IDs of selected flows as strings
let showTcpFlows = true; // Toggle for TCP flow visualization (default ON)
let showEstablishment = true; // Toggle for establishment phase (default ON)
let showDataTransfer = true; // Toggle for data transfer phase (default ON)
let showClosing = true; // Toggle for closing phase (default ON)
let groundTruthData = []; // Store ground truth events
let showGroundTruth = false; // Toggle for ground truth visualization
// Global toggle state for invalid flow categories in legend
const hiddenInvalidReasons = new Set();
// Cache for IP filtered packet subsets (key: sorted IP list)
const filterCache = new Map();

// Cache for full-domain binned result to make Reset View fast
let dataVersion = 0; // increment when filteredData changes
let fullDomainBinsCache = { version: -1, data: [], binSize: null, sorted: false };
// Global radius scaling: anchor sizes across zooms
// - RADIUS_MIN: circle size for an individual packet (count = 1)
// - globalMaxBinCount: computed from the initial full-domain binning; reused at all zoom levels
let globalMaxBinCount = 1;

// User toggle: binning on/off
let useBinning = true;
// Render mode: 'circles' (default) or 'bars'
let renderMode = 'circles';

// Wrapper to call imported renderBars with required options
function renderBarsWithOptions(layer, binned) {
    renderBars(layer, binned, {
        xScale,
        flagColors,
        globalMaxBinCount,
        ROW_GAP,
        formatBytes,
        formatTimestamp,
        d3
    });
}

// Wrapper to call imported renderCircles with required options and event handlers
function renderCirclesWithOptions(layer, binned, rScale) {
    if (!layer) return;
    // Clear bar segments in this layer
    try { layer.selectAll('.bin-bar-segment').remove(); } catch {}
    try { layer.selectAll('.bin-stack').remove(); } catch {}
    const tooltip = d3.select('#tooltip');
    layer.selectAll('.direction-dot')
        .data(binned, d => d.binned ? `bin_${d.timestamp}_${d.yPos}_${d.flagType}` : `${d.src_ip}-${d.dst_ip}-${d.timestamp}`)
        .join(
            enter => enter.append('circle')
                .attr('class', d => `direction-dot ${d.binned && d.count > 1 ? 'binned' : ''}`)
                .attr('r', d => d.binned && d.count > 1 ? rScale(d.count) : RADIUS_MIN)
                .attr('data-orig-r', d => d.binned && d.count > 1 ? rScale(d.count) : RADIUS_MIN)
                .attr('fill', d => flagColors[d.binned ? d.flagType : classifyFlags(d.flags)] || flagColors.OTHER)
                .attr('cx', d => xScale(Math.floor(d.binned && Number.isFinite(d.binCenter) ? d.binCenter : d.timestamp)))
                .attr('cy', d => d.binned ? d.yPos : findIPPosition(d.src_ip, d.src_ip, d.dst_ip, pairs, ipPositions))
                .style('cursor', 'pointer')
                .on('mouseover', (event, d) => {
                    const dot = d3.select(event.currentTarget);
                    dot.classed('highlighted', true).style('stroke', '#000').style('stroke-width', '2px');
                    const baseR = +dot.attr('data-orig-r') || +dot.attr('r') || RADIUS_MIN;
                    dot.attr('r', baseR);
                    const packet = d.originalPackets ? d.originalPackets[0] : d;
                    const arcPath = arcPathGenerator(packet, { xScale, ipPositions, pairs, findIPPosition, flagCurvature: FLAG_CURVATURE });
                    if (arcPath) {
                        mainGroup.append('path').attr('class', 'hover-arc').attr('d', arcPath)
                            .style('stroke', flagColors[d.binned ? d.flagType : classifyFlags(d.flags)] || flagColors.OTHER)
                            .style('stroke-width', '2px')
                            .style('stroke-opacity', 0.8).style('fill', 'none').style('pointer-events', 'none');
                    }
                    tooltip.style('display', 'block').html(createTooltipHTML(d));
                })
                .on('mousemove', e => { tooltip.style('left', `${e.pageX + 40}px`).style('top', `${e.pageY - 40}px`); })
                .on('mouseout', e => {
                    const dot = d3.select(e.currentTarget);
                    dot.classed('highlighted', false).style('stroke', null).style('stroke-width', null);
                    const baseR = +dot.attr('data-orig-r') || RADIUS_MIN; dot.attr('r', baseR);
                    mainGroup.selectAll('.hover-arc').remove(); tooltip.style('display', 'none');
                }),
            update => update
                .attr('class', d => `direction-dot ${d.binned && d.count > 1 ? 'binned' : ''}`)
                .attr('r', d => d.binned && d.count > 1 ? rScale(d.count) : RADIUS_MIN)
                .attr('data-orig-r', d => d.binned && d.count > 1 ? rScale(d.count) : RADIUS_MIN)
                .attr('fill', d => flagColors[d.binned ? d.flagType : classifyFlags(d.flags)] || flagColors.OTHER)
                .attr('cx', d => xScale(Math.floor(d.binned && Number.isFinite(d.binCenter) ? d.binCenter : d.timestamp)))
                .attr('cy', d => d.binned ? d.yPos : findIPPosition(d.src_ip, d.src_ip, d.dst_ip, pairs, ipPositions))
                .style('cursor', 'pointer')
        );
}

// Unified render function - uses local wrappers that call imported modules
function renderMarksForLayerLocal(layer, data, rScale) {
    if (renderMode === 'bars') return renderBarsWithOptions(layer, data);
    return renderCirclesWithOptions(layer, data, rScale);
}

// Draw a circle-size legend (bottom-right) for smallest/middle/largest counts
function drawSizeLegend(targetSvgOverride = null, targetWidth = null, targetHeight = null, axisY = null) {
    try {
        const targetSvg = targetSvgOverride || svg;
        const w = (typeof targetWidth === 'number') ? targetWidth : width;
        const h = (typeof targetHeight === 'number') ? targetHeight : height;
        if (!targetSvg || !w || !h) return;
        // Remove previous legend if any
        targetSvg.select('.size-legend').remove();

        const maxCount = Math.max(1, globalMaxBinCount);
        const midCount = Math.max(1, Math.round(maxCount / 2));
        const values = [1, midCount, maxCount];

        const rScale = d3.scaleSqrt().domain([1, maxCount]).range([RADIUS_MIN, RADIUS_MAX]);
        const radii = values.map(v => rScale(v));
        const maxR = Math.max(...radii, RADIUS_MIN);

        // Layout constants
        const padding = 8;
        const labelGap = 32; // top headroom for title + labels
        const legendWidth = maxR * 2 + padding * 2; // compact width
        const legendHeight = 2 * maxR + padding + (padding + labelGap); // space for title + labels

    const anchorY = (typeof axisY === 'number') ? axisY : h;
    const legendX = Math.max(0, w - legendWidth - 12);
    const legendY = Math.max(0, (anchorY - legendHeight - 8));

    const g = targetSvg.append('g')
        .attr('class', 'size-legend')
        .attr('transform', `translate(${legendX},${legendY})`)
        .style('pointer-events', 'none');

        // Background
        g.append('rect')
            .attr('x', 0)
            .attr('y', 0)
            .attr('rx', 6)
            .attr('ry', 6)
            .attr('width', legendWidth)
            .attr('height', legendHeight)
            .style('fill', '#fff')
            .style('opacity', 0.85)
            .style('stroke', '#ccc');

        // Title
        g.append('text')
            .attr('x', legendWidth / 2)
            .attr('y', padding + 10)
            .attr('text-anchor', 'middle')
            .style('font-size', '12px')
            .style('font-weight', '600')
            .style('fill', '#333')
            .text('Circle Size');

        // Baseline at the bottom inside the box
        const innerTop = padding + labelGap; // extra top room for labels
        const baseline = innerTop + 2 * maxR;
        const cx = padding + maxR; // center x for all circles

        // Draw nested circles (bottom-aligned), no fill. Draw largest first.
        const order = [2, 1, 0]; // indices for [max, mid, min]
        order.forEach((idx) => {
            const v = values[idx];
            const r = Math.max(RADIUS_MIN, radii[idx]);
            const cy = baseline - r; // bottom-aligned

            g.append('circle')
                .attr('cx', cx)
                .attr('cy', cy)
                .attr('r', r)
                .style('fill', 'none')
                .style('stroke', '#555');

            // Label centered above each circle
            g.append('text')
                .attr('x', cx)
                .attr('y', cy - r - 4)
                .attr('text-anchor', 'middle')
                .style('font-size', '12px')
                .style('fill', '#333')
                .text(v);
        });
    } catch (_) { /* ignore legend draw errors */ }
}

// Wrapper function for the extracted flag legend
function drawFlagLegend() {
    // Default to bottom overlay if available; fallback to main svg
    const targetSvg = bottomOverlayRoot || svg;
    const w = bottomOverlayRoot ? width : width;
    const h = bottomOverlayRoot ? bottomOverlayHeight : height;
    const axisBaseY = bottomOverlayRoot ? Math.max(20, bottomOverlayHeight - 20) : (height - 12);
    drawFlagLegendFromModule({ 
        svg: targetSvg, 
        width: w, 
        height: h, 
        flagColors, 
        globalMaxBinCount, 
        RADIUS_MIN, 
        RADIUS_MAX, 
        d3,
        axisY: axisBaseY
    });
}

// TCP flag colors, now loaded from flag_colors.json with defaults
let flagColors = { ...DEFAULT_FLAG_COLORS };
// Flow-related colors (closing types and invalid reasons) loaded from flow_colors.json
let flowColors = {
    closing: {
        graceful: '#8e44ad',
        abortive: '#c0392b'
    },
    ongoing: {
        open: '#6c757d',
        incomplete: '#adb5bd'
    },
    invalid: {
        // Optional overrides; default invalid reason colors derive from flagColors
    }
};

// Load color mapping for ground truth events
let eventColors = {};
fetch('color_mapping.json')
    .then(response => response.json())
    .then(colors => {
        eventColors = colors;
        LOG('Loaded event colors:', eventColors);
    })
    .catch(error => {
        console.warn('Could not load color_mapping.json:', error);
        // Use default colors if file not found
        eventColors = {
            'normal': '#4B4B4B',
            'client compromise': '#D41159',
            'malware ddos': '#2A9D4F',
            'scan /usr/bin/nmap': '#C9A200',
            'ddos': '#264D99'
        };
    });

// Load colors for flags from external JSON, merging into the existing object
fetch('flag_colors.json')
    .then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
    .then(colors => {
        Object.assign(flagColors, colors);
        LOG('Loaded flag colors:', flagColors);
        try { drawFlagLegend(); } catch (_) {}
    })
    .catch(err => {
        console.warn('Could not load flag_colors.json:', err);
        // keep defaults in flagColors
    });

// Load colors for flows (closing + invalid) from external JSON, deep-merge
fetch('flow_colors.json')
    .then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
    .then(colors => {
        try {
            if (colors && typeof colors === 'object') {
                if (colors.closing && typeof colors.closing === 'object') {
                    flowColors.closing = { ...flowColors.closing, ...colors.closing };
                }
                if (colors.invalid && typeof colors.invalid === 'object') {
                    flowColors.invalid = { ...flowColors.invalid, ...colors.invalid };
                }
                if (colors.ongoing && typeof colors.ongoing === 'object') {
                    flowColors.ongoing = { ...flowColors.ongoing, ...colors.ongoing };
                }
            }
            LOG('Loaded flow colors:', flowColors);
        } catch (e) { console.warn('Merging flow_colors.json failed:', e); }
    })
    .catch(err => {
        console.warn('Could not load flow_colors.json:', err);
        // keep defaults in flowColors
    });

// Initialization function for the bar diagram module
function initializeBarVisualization() {
    // Initialize overview module with references
    initOverview({
        d3,
        applyZoomDomain: (domain, source) => applyZoomDomain(domain, source),
        getWidth: () => width,
        getTimeExtent: () => timeExtent,
        getCurrentFlows: () => currentFlows,
        getSelectedFlowIds: () => selectedFlowIds,
        updateTcpFlowPacketsGlobal: () => updateTcpFlowPacketsGlobal(),
        createFlowList: (flows) => createFlowList(flows),
        sbRenderInvalidLegend: (panel, html, title) => sbRenderInvalidLegend(panel, html, title),
        sbRenderClosingLegend: (panel, html, title) => sbRenderClosingLegend(panel, html, title),
        makeConnectionKey: (a,b,c,d) => makeConnectionKey(a,b,c,d),
        // Allow overview legend toggles to affect the arc graph immediately
        applyInvalidReasonFilter: () => applyInvalidReasonFilter(),
        hiddenInvalidReasons,
        hiddenCloseTypes,
        GLOBAL_BIN_COUNT,
        flagColors,
        flowColors
    });
    initSidebar({
        onResetView: () => {
            if (fullData.length > 0 && zoomTarget && zoom && timeExtent && timeExtent[1] > timeExtent[0]) {
                isHardResetInProgress = true;
                applyZoomDomain([timeExtent[0], timeExtent[1]], 'reset');
                if (showTcpFlows && selectedFlowIds && selectedFlowIds.size > 0) {
                    try { setTimeout(() => redrawSelectedFlowsView(), 0); } catch(_) {}
                }
            }
        }
    });
    // Delegate sidebar event wiring
    sbWireSidebarControls({
        onIpSearch: (term) => sbFilterIPList(term),
        onSelectAllIPs: () => { document.querySelectorAll('#ipCheckboxes input[type="checkbox"]').forEach(cb => cb.checked = true); updateIPFilter(); },
        onClearAllIPs: () => { document.querySelectorAll('#ipCheckboxes input[type="checkbox"]').forEach(cb => cb.checked = false); updateIPFilter(); },
        onToggleShowTcpFlows: (checked) => { showTcpFlows = checked; updateTcpFlowPacketsGlobal(); drawSelectedFlowArcs(); try { applyInvalidReasonFilter(); } catch(_) {} },
        onToggleEstablishment: (checked) => { showEstablishment = checked; drawSelectedFlowArcs(); try { applyInvalidReasonFilter(); } catch(_) {} },
        onToggleDataTransfer: (checked) => { showDataTransfer = checked; drawSelectedFlowArcs(); try { applyInvalidReasonFilter(); } catch(_) {} },
        onToggleClosing: (checked) => { showClosing = checked; drawSelectedFlowArcs(); try { applyInvalidReasonFilter(); } catch(_) {} },
        onToggleGroundTruth: (checked) => { showGroundTruth = checked; const selectedIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')).map(cb => cb.value); drawGroundTruthBoxes(selectedIPs); },
        onToggleBinning: (checked) => { 
            useBinning = checked; 
            isHardResetInProgress = true; 
            
            // Force immediate re-render of the visualization
            try {
                // Re-render the main visualization with current filtered data
                visualizeTimeArcs(filteredData);
                
                // Update TCP flow packets and arcs
                updateTcpFlowPacketsGlobal();
                
                // Redraw selected flow arcs with new binning
                drawSelectedFlowArcs();
                
                // Apply any active filters
                applyInvalidReasonFilter();
                
                // Update legends to reflect new scaling
                setTimeout(() => {
                    try { 
                        try {
                            const axisBaseY = Math.max(20, bottomOverlayHeight - 20);
                            drawSizeLegend(bottomOverlayRoot, width, bottomOverlayHeight, axisBaseY);
                        } catch {}
                        drawFlagLegend();
                        const selIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')).map(cb => cb.value); 
                        drawGroundTruthBoxes(selIPs); 
                    } catch(_) {}
                }, 50);
            } catch (e) {
                console.warn('Error updating visualization after binning toggle:', e);
                // Fallback to original behavior
                applyZoomDomain(xScale.domain(), 'program');
            }
        },
        onToggleRenderMode: (mode) => {
            try {
                renderMode = (mode === 'bars') ? 'bars' : 'circles';
                // Re-render marks in current domain using chosen mode
                isHardResetInProgress = true;
                visualizeTimeArcs(filteredData);
                updateTcpFlowPacketsGlobal();
                drawSelectedFlowArcs();
                applyInvalidReasonFilter();
            } catch (e) { console.warn('Render mode toggle failed', e); }
        }
    });

    // Window resize handler for responsive visualization
    setupWindowResizeHandler();

    // Wire Flow List modal controls
    try {
        sbWireFlowListModalControls({
            onSelectAll: () => {
                document.querySelectorAll('#flowListModalList .flow-checkbox').forEach(cb => { if (!cb.checked) cb.click(); });
            },
            onClearAll: () => {
                document.querySelectorAll('#flowListModalList .flow-checkbox').forEach(cb => { if (cb.checked) cb.click(); });
            },
            onSearch: (term) => {
                const items = document.querySelectorAll('#flowListModalList .flow-item');
                const t = (term || '').toLowerCase();
                items.forEach(it => {
                    const text = (it.innerText || it.textContent || '').toLowerCase();
                    it.style.display = text.includes(t) ? '' : 'none';
                });
            }
        });
    } catch (_) {}
}

// Window resize handler for responsive visualization
// Uses module for event handling, with custom onResize callback for app-specific logic
function setupWindowResizeHandler() {
    const handleResizeLogic = () => {
        try {
            // Only proceed if we have data and existing visualization
            if (!fullData || fullData.length === 0 || !svg || !xScale || !yScale) {
                return;
            }
            
            LOG('Handling window resize, updating visualization dimensions');
            
            // Store old dimensions for comparison
            const oldWidth = width;
            const oldHeight = height;
            
            const container = d3.select("#chart-container").node();
            if (!container) return;
            
            // Calculate new dimensions
            const containerRect = container.getBoundingClientRect();
            const newWidth = Math.max(400, containerRect.width - chartMarginLeft - chartMarginRight);
            const newHeight = Math.max(300, containerRect.height - 100); // Leave space for controls
            
            // Update global dimensions
            width = newWidth;
            height = newHeight;
            
            LOG(`Resize: ${oldWidth}x${oldHeight} -> ${width}x${height}`);
            
            // Resize main SVG
            svg.attr('width', width + chartMarginLeft + chartMarginRight)
               .attr('height', height + 100); // Extra space for bottom margin
            
            // Update scales with new width
            if (xScale && timeExtent) {
                xScale.range([0, width]);
            }
            
            // Update bottom overlay dimensions
            bottomOverlayWidth = Math.max(0, newWidth + chartMarginLeft + chartMarginRight);
            d3.select('#chart-bottom-overlay-svg')
                .attr('width', bottomOverlayWidth)
                .attr('height', bottomOverlayHeight);
            
            if (bottomOverlayRoot) {
                bottomOverlayRoot.attr('transform', `translate(${chartMarginLeft},0)`);
            }
            
            // Update main chart axis and legends
            if (bottomOverlayAxisGroup && xScale) {
                const axis = d3.axisBottom(xScale).tickFormat(d => {
                    const timestampInt = Math.floor(d);
                    const date = new Date(timestampInt / 1000);
                    return date.toISOString().split('T')[1].split('.')[0];
                });
                bottomOverlayAxisGroup.call(axis);
                
                // Redraw legends with new dimensions
                const axisBaseY = Math.max(20, bottomOverlayHeight - 20);
                if (bottomOverlayDurationLabel) {
                    bottomOverlayDurationLabel.attr('y', axisBaseY - 12);
                }
                
                try { 
                    drawSizeLegend(bottomOverlayRoot, newWidth, bottomOverlayHeight, axisBaseY); 
                } catch (e) { 
                    LOG('Error redrawing size legend:', e); 
                }
                
                try { 
                    drawFlagLegend(); 
                } catch (e) { 
                    LOG('Error redrawing flag legend:', e); 
                }
            }
            
            // Update zoom behavior with new dimensions
            if (zoom && zoomTarget) {
                const currentTransform = d3.zoomTransform(zoomTarget.node());
                zoom.extent([[0, 0], [width, height]])
                    .scaleExtent([1, Math.max(20, width / 50)]);
                
                // Clear the cache to force fresh calculations
                fullDomainBinsCache = { version: -1, data: [], binSize: null, sorted: false };
                
                // Also increment data version to invalidate other caches
                dataVersion++;
                
                // Clear cached selections to force fresh rendering
                dotsSelection = null;
                
                // Trigger the zoom event handler to redraw everything with new scale
                // We need to dispatch a zoom event to trigger the redraw
                const event = new CustomEvent('zoom');
                event.transform = currentTransform;
                event.sourceEvent = { type: 'resize' };
                
                // Get the zoom handler function and call it
                const zoomHandler = zoom.on('zoom');
                if (typeof zoomHandler === 'function') {
                    try {
                        LOG('Calling zoom handler to redraw with new dimensions');
                        zoomHandler.call(zoomTarget.node(), event);
                        LOG('Zoom handler called successfully');
                    } catch (e) {
                        LOG('Error calling zoom handler directly:', e);
                        // Fallback: manually trigger zoom transform
                        zoomTarget.call(zoom.transform, currentTransform);
                    }
                } else {
                    LOG('Zoom handler not found, using fallback');
                    // Fallback: manually trigger zoom transform
                    zoomTarget.call(zoom.transform, currentTransform);
                }
            }
            
            // Recreate overview chart with new dimensions
            if (timeExtent && timeExtent.length === 2) {
                try {
                    createOverviewChart(fullData, {
                        timeExtent: timeExtent,
                        width: width,
                        margins: { left: chartMarginLeft, right: chartMarginRight, top: 80, bottom: 50 }
                    });
                    
                    // Restore brush selection to current zoom domain if available
                    if (xScale && updateBrushFromZoom) {
                        updateBrushFromZoom();
                    }
                } catch (e) {
                    LOG('Error recreating overview chart on resize:', e);
                }
            }
            
            // The zoom handler will take care of redrawing dots and arcs
            // Just need to update any additional elements that aren't handled by zoom
            
            // Update clip path with new dimensions
            if (svg) {
                svg.select('#clip rect')
                    .attr('width', width + 40) // DOT_RADIUS equivalent
                    .attr('height', height + 80); // 2 * DOT_RADIUS equivalent
            }
            
            // Update global domain for overview sync
            try { 
                window.__arc_x_domain__ = xScale.domain(); 
            } catch {}
            
            LOG('Window resize handling complete');
            
        } catch (e) {
            console.warn('Error during window resize:', e);
        }
    };
    
    // Use module's resize handler with our custom logic
    return setupWindowResizeHandlerFromModule({
        debounceMs: 150,
        onResize: handleResizeLogic
    });
}



// Global update functions that preserve zoom state
let flowUpdateTimeout = null;

// Centralized helper to apply a new time domain to the main chart (keeps brush/wheel/flow zoom in sync)
// Wrapper that calls the module function with current global state
function applyZoomDomain(newDomain, source = 'program') {
    // If the source is the brush, notify overview to avoid circular updates
    if (source === 'brush') { try { setBrushUpdating(true); } catch(_) {} }
    
    applyZoomDomainFromModule(newDomain, {
        zoom,
        zoomTarget,
        xScale,
        timeExtent,
        width,
        d3
    }, source);
    
    if (source === 'brush') {
        // Release the flag after the event loop so zoomed() can run with the guard
        setTimeout(() => { try { setBrushUpdating(false); } catch(_) {} }, 0);
    }
}

function updateTcpFlowLinesGlobalDebounced() {
    // Clear any pending update
    if (flowUpdateTimeout) {
        clearTimeout(flowUpdateTimeout);
    }
    
    // Schedule a new update after a short delay
        flowUpdateTimeout = setTimeout(() => { 
        updateTcpFlowPacketsGlobal();
        flowUpdateTimeout = null;
    }, 100); // 100ms debounce
}

// Wrapper function that uses the module function with global state
function buildSelectedFlowKeySet() {
    return buildSelectedFlowKeySetFromModule(tcpFlows, selectedFlowIds);
}

function updateTcpFlowPacketsGlobal() {
    // Hide/show dots and draw lines based on current selection
    filterPacketsBySelectedFlows();
    // If no flows selected, ensure all dots are visible in both layers
    if (!showTcpFlows || selectedFlowIds.size === 0) {
        if (fullDomainLayer) {
            fullDomainLayer.selectAll('.direction-dot').style('display', 'block').style('opacity', 0.5);
            fullDomainLayer.selectAll('.bin-bar-segment').style('display', 'block').style('opacity', 0.7);
        }
        // Clear any stale selection-only marks to prevent size scale misreads
        if (dynamicLayer) {
            dynamicLayer.selectAll('.direction-dot').remove();
            dynamicLayer.selectAll('.bin-bar-segment').remove();
        }
        // Restore full-domain layer by default when no selection
        if (fullDomainLayer) fullDomainLayer.style('display', null);
        if (dynamicLayer) dynamicLayer.style('display', 'none');
    }
    drawSelectedFlowArcs();
    // Recompute radius scaling from currently visible dots
    setTimeout(() => {
        try { recomputeGlobalMaxBinCountFromVisibleDots(); } catch (_) {}
    }, 120);

    // If a flow selection is active, recompute bins for the selection and render in dynamic layer
    if (showTcpFlows && selectedFlowIds.size > 0) {
        try { redrawSelectedFlowsView(); } catch (e) { console.warn('Redraw for selected flows failed:', e); }
    }
    // Apply invalid-reason visibility on top of any selection
    try { applyInvalidReasonFilter(); } catch (_) {}
}

// Track hidden close types (graceful, abortive) from closing legend
const hiddenCloseTypes = new Set();

// Hide/show dots, arcs, and overview bars based on invalid-reason and closing-type toggles
function applyInvalidReasonFilter() {
    // If SVG not ready, nothing to do
    if (!svg) return;

    // Helper: build a mapping from connection key -> invalid reason
    const reasonByKey = new Map();
    // Helper: build a mapping from connection key -> closeType ('graceful','abortive', etc.)
    const closeTypeByKey = new Map();
    if (Array.isArray(tcpFlows)) {
        for (const f of tcpFlows) {
            if (!f) continue;
            const key = f.key || makeConnectionKey(f.initiator, f.initiatorPort, f.responder, f.responderPort);
            if (!key) continue;
            let r = f.invalidReason;
            if (!r && (f.closeType === 'invalid' || f.state === 'invalid')) r = 'unknown_invalid';
            reasonByKey.set(key, r || null);
            // Closing-type visibility: exclude invalid flows from ongoing group
            // Map non-invalid, non-closed flows to 'open' (established) or 'incomplete'
            const isInvalid = !!r || f.closeType === 'invalid' || f.state === 'invalid';
            let ct = null;
            if (!isInvalid) {
                if (f.closeType === 'graceful' || f.closeType === 'abortive') {
                    ct = f.closeType;
                } else {
                    ct = (f.establishmentComplete === true || f.state === 'established' || f.state === 'data_transfer') ? 'open' : 'incomplete';
                }
            }
            closeTypeByKey.set(key, ct);
        }
    }

    const keyIsHidden = (key) => {
        const r = reasonByKey.get(key);
        if (r && hiddenInvalidReasons && hiddenInvalidReasons.has(r)) return true;
        // If we also hide by close type, check the flow close type
        if (hiddenCloseTypes && hiddenCloseTypes.size > 0 && key) {
            const ct = closeTypeByKey.get(key);
            if (ct && hiddenCloseTypes.has(ct)) return true;
        }
        return false;
    };

    const nothingHidden = (!hiddenInvalidReasons || hiddenInvalidReasons.size === 0) && (!hiddenCloseTypes || hiddenCloseTypes.size === 0);

    // Dots (both layers live under mainGroup)
    if (mainGroup && mainGroup.selectAll) {
        mainGroup.selectAll('.direction-dot').each(function(d) {
            let hide = false;
            if (!nothingHidden) {
                if (d && Array.isArray(d.originalPackets) && d.originalPackets.length) {
                    let allHidden = true;
                    const arr = d.originalPackets;
                    // Sample up to first 50 packets for performance
                    const len = Math.min(arr.length, 50);
                    for (let i = 0; i < len; i++) {
                        const p = arr[i];
                        const key = makeConnectionKey(p.src_ip, p.src_port || 0, p.dst_ip, p.dst_port || 0);
                        if (!keyIsHidden(key)) { allHidden = false; break; }
                    }
                    hide = allHidden;
                } else if (d) {
                    const key = makeConnectionKey(d.src_ip, d.src_port || 0, d.dst_ip, d.dst_port || 0);
                    hide = keyIsHidden(key);
                }
            }
            // Apply phase-based visibility regardless of legend toggles
            if (!hide) {
                if (d && Array.isArray(d.originalPackets) && d.originalPackets.length) {
                    let anyVisibleByPhase = false;
                    const arr = d.originalPackets;
                    const len = Math.min(arr.length, 50);
                    for (let i = 0; i < len; i++) {
                        const p = arr[i];
                        const ftype = classifyFlags(p.flags);
                        if (isFlagVisibleByPhase(ftype, { showEstablishment, showDataTransfer, showClosing })) { anyVisibleByPhase = true; break; }
                    }
                    hide = !anyVisibleByPhase;
                } else if (d) {
                    const ftype = d.binned ? d.flagType : classifyFlags(d.flags);
                    hide = !isFlagVisibleByPhase(ftype, { showEstablishment, showDataTransfer, showClosing });
                }
            }
            d3.select(this)
                .style('display', hide ? 'none' : null)
                .style('opacity', hide ? 0 : null);
        });
        // Also apply to stacked bar segments if present
        mainGroup.selectAll('.bin-bar-segment').each(function(w) {
            const d = w && w.datum ? w.datum : w; // our bars bind an object {datum}
            let hide = false;
            if (!nothingHidden) {
                if (d && Array.isArray(d.originalPackets) && d.originalPackets.length) {
                    let allHidden = true;
                    const arr = d.originalPackets;
                    const len = Math.min(arr.length, 50);
                    for (let i = 0; i < len; i++) {
                        const p = arr[i];
                        const key = makeConnectionKey(p.src_ip, p.src_port || 0, p.dst_ip, p.dst_port || 0);
                        if (!keyIsHidden(key)) { allHidden = false; break; }
                    }
                    hide = allHidden;
                }
            }
            if (!hide) {
                const ftype = d && d.flagType ? d.flagType : 'OTHER';
                hide = !isFlagVisibleByPhase(ftype, { showEstablishment, showDataTransfer, showClosing });
            }
            d3.select(this).style('display', hide ? 'none' : null).style('opacity', hide ? 0 : null);
        });
    }

    // Flow arcs (drawn only for selected flows)
    if (mainGroup && mainGroup.selectAll) {
        mainGroup.selectAll('.flow-arc').each(function(d) {
            let hide = false;
            if (!nothingHidden && d) {
                const key = makeConnectionKey(d.src_ip, d.src_port || 0, d.dst_ip, d.dst_port || 0);
                hide = keyIsHidden(key);
            }
            d3.select(this)
                .style('display', hide ? 'none' : null)
                .style('opacity', hide ? 0 : null);
        });
    }

    // Overview stacked histogram segments (invalid reasons)
    try { updateOverviewInvalidVisibility(); } catch(_) {}

    // Update legend item styles to reflect toggled state
    const panel = document.getElementById('invalidLegendPanel');
    if (panel) {
        panel.querySelectorAll('.invalid-legend-item').forEach((el) => {
            const reason = el.getAttribute('data-reason');
            const disabled = !!(reason && hiddenInvalidReasons && hiddenInvalidReasons.has(reason));
            el.style.opacity = disabled ? '0.45' : '1';
        });
    }

    // Update closing and ongoing legend styles and hide specific closing lines
    const cpanel = document.getElementById('closingLegendPanel');
    if (cpanel) {
        cpanel.querySelectorAll('.closing-legend-item').forEach((el) => {
            const t = el.getAttribute('data-type');
            const disabled = !!(t && hiddenCloseTypes && hiddenCloseTypes.has(t));
            el.style.opacity = disabled ? '0.45' : '1';
        });
    }
    const opanel = document.getElementById('ongoingLegendPanel');
    if (opanel) {
        opanel.querySelectorAll('.closing-legend-item').forEach((el) => {
            const t = el.getAttribute('data-type');
            const disabled = !!(t && hiddenCloseTypes && hiddenCloseTypes.has(t));
            el.style.opacity = disabled ? '0.45' : '1';
        });
    }

    // Hide explicit closing line groups per type
    const closingGroup = svg.select('.closing-lines');
    if (closingGroup && !closingGroup.empty()) {
        closingGroup.selectAll('.closing-line').each(function(d){
            let hide = false;
            if (!nothingHidden && d) {
                // d.type is 'graceful_close' or 'half_close'
                if (hiddenCloseTypes && hiddenCloseTypes.size > 0) {
                    if (d.type === 'graceful_close' && hiddenCloseTypes.has('graceful')) hide = true;
                    if (d.type === 'half_close' && hiddenCloseTypes.has('abortive')) hide = true;
                }
            }
            d3.select(this).style('display', hide ? 'none' : null).style('opacity', hide ? 0 : null);
        });
    }
}

// Rebin and redraw dots specifically for currently selected flows at the current zoom domain
function redrawSelectedFlowsView() {
    if (!svg || !xScale || !dynamicLayer) return;
    // Hide cached full-domain dots; we will render fresh selection-only dots
    if (fullDomainLayer) fullDomainLayer.style('display', 'none');
    dynamicLayer.style('display', null);

    const selectedKeys = buildSelectedFlowKeySet();
    if (selectedKeys.size === 0) {
        // Nothing selected: clear dynamic layer; caller will restore full layer when appropriate
        dynamicLayer.selectAll('.direction-dot').remove();
        return;
    }

    // Compute visible packets in current domain, filtered by selected flow keys
    let visiblePackets = getVisiblePackets(filteredData, xScale);
    visiblePackets = visiblePackets.filter(p => {
        if (!p || !p.src_ip || !p.dst_ip) return false;
        const key = makeConnectionKey(p.src_ip, p.src_port || 0, p.dst_ip, p.dst_port || 0);
        return selectedKeys.has(key);
    });

    if (!visiblePackets || visiblePackets.length === 0) {
        dynamicLayer.selectAll('.direction-dot').remove();
        return;
    }

    // Bin using current settings (may resolve to per-packet if sparse)
    const binnedPackets = binPackets(visiblePackets, {
        xScale,
        timeExtent,
        findIPPosition,
        ipPositions,
        pairs,
        binCount: getEffectiveBinCount(GLOBAL_BIN_COUNT, renderMode),
        useBinning,
        width
    });
    const rScale = d3.scaleSqrt().domain([1, Math.max(1, globalMaxBinCount)]).range([RADIUS_MIN, RADIUS_MAX]);
    renderMarksForLayerLocal(dynamicLayer, binnedPackets, rScale);

    // After redraw, recompute sizes based on what is actually visible
    setTimeout(() => { 
        try { recomputeGlobalMaxBinCountFromVisibleDots(); } catch(_) {} 
        // Sync worker with updated dynamic layer data
        try { syncWorkerWithRenderedData(); } catch(_) {}
    }, 80);
    // Re-apply legend-based filtering
    try { applyInvalidReasonFilter(); } catch(_) {}
}

// Worker-enabled packet filtering (falls back to legacy if worker unavailable)
function filterPacketsBySelectedFlows() {
    if (!svg || !mainGroup) return;
    if (!workerManager) { 
        legacyFilterPacketsBySelectedFlows(); 
        return; 
    }
    
    // Check if we have a reasonable number of dots to match our data
    const dots = mainGroup.selectAll('.direction-dot').nodes();
    const currentMask = workerManager.getVisibilityMask();
    
    if (currentMask && dots.length !== currentMask.length) {
        // DOM has been updated, worker mask is stale - try to resync
        if (DEBUG) console.warn(`Worker mask stale (mask=${currentMask.length}, dots=${dots.length}), attempting resync`);
        syncWorkerWithRenderedData();
        
        // After resync, if still mismatched, fall back to legacy
        const newMask = workerManager.getVisibilityMask();
        if (newMask && dots.length !== newMask.length) {
            if (DEBUG) console.warn('Resync failed, using legacy filtering');
            legacyFilterPacketsBySelectedFlows();
            return;
        }
    }
    
    const showAll = !showTcpFlows || selectedFlowIds.size === 0;
    const selectedKeys = showAll ? [] : Array.from(buildSelectedFlowKeySet());
    workerManager.filterByKeys(selectedKeys, showAll);
}

// Legacy in-main-thread filtering retained for fallback/debug
function legacyFilterPacketsBySelectedFlows() {
    if (!svg || !mainGroup) return;
    const allDots = mainGroup.selectAll('.direction-dot');
    if (!showTcpFlows || selectedFlowIds.size === 0) {
        allDots.style('display', 'block').style('opacity', 0.5);
        // Bars as well
        try { mainGroup.selectAll('.bin-bar-segment').style('display','block').style('opacity', 0.7); } catch {}
        return;
    }
    const selectedKeys = buildSelectedFlowKeySet();
    const nodes = allDots.nodes();
    const BATCH = 2500;
    function processBatch(start) {
        const end = Math.min(start + BATCH, nodes.length);
        for (let i = start; i < end; i++) {
            const node = nodes[i];
            const d = node.__data__;
            let match = false;
            if (d && d.originalPackets && Array.isArray(d.originalPackets)) {
                const arr = d.originalPackets;
                const len = Math.min(arr.length, 50);
                for (let j = 0; j < len; j++) {
                    const p = arr[j];
                    const key = makeConnectionKey(p.src_ip, p.src_port, p.dst_ip, p.dst_port);
                    if (selectedKeys.has(key)) { match = true; break; }
                }
            } else if (d) {
                const key = makeConnectionKey(d.src_ip, d.src_port, d.dst_ip, d.dst_port);
                match = selectedKeys.has(key);
            }
            node.style.display = match ? 'block' : 'none';
            node.style.opacity = match ? 0.5 : 0.1;
        }
        if (end < nodes.length) {
            requestAnimationFrame(() => processBatch(end));
        }
    }
    requestAnimationFrame(() => processBatch(0));

    // Apply same logic for bar segments based on their bound datum
    const barNodes = mainGroup.selectAll('.bin-bar-segment').nodes();
    const BATCH2 = 2000;
    function processBars(start) {
        const end = Math.min(start + BATCH2, barNodes.length);
        for (let i = start; i < end; i++) {
            const node = barNodes[i];
            const w = node.__data__;
            const d = w && w.datum ? w.datum : w;
            let match = false;
            if (d && Array.isArray(d.originalPackets)) {
                const arr = d.originalPackets;
                const len = Math.min(arr.length, 50);
                for (let j = 0; j < len; j++) {
                    const p = arr[j];
                    const key = makeConnectionKey(p.src_ip, p.src_port, p.dst_ip, p.dst_port);
                    if (selectedKeys.has(key)) { match = true; break; }
                }
            }
            node.style.display = match ? 'block' : 'none';
            node.style.opacity = match ? 0.7 : 0.1;
        }
        if (end < barNodes.length) requestAnimationFrame(() => processBars(end));
    }
    requestAnimationFrame(() => processBars(0));
}

// Function to draw persistent lines for selected flows
function drawSelectedFlowArcs() {
    if (!svg || !mainGroup) return;

    // Clear previous persistent lines
    mainGroup.selectAll(".flow-arc").remove();

    // If TCP flows are off or nothing selected, don't draw persistent lines
    if (!showTcpFlows || selectedFlowIds.size === 0 || !tcpFlows || tcpFlows.length === 0) {
        return;
    }

    // Build lookup of selected flow connection keys
    const selectedKeys = buildSelectedFlowKeySet();
    if (selectedKeys.size === 0) return;

    // Only draw lines for packets in the visible time range
    const [t0, t1] = xScale.domain();
    
    // Get visible packets for selected flows
    let visiblePackets = filteredData.filter(p => {
        const ts = Math.floor(p.timestamp);
        if (ts < t0 || ts > t1) return false;
        const key = makeConnectionKey(p.src_ip, p.src_port, p.dst_ip, p.dst_port);
        return selectedKeys.has(key);
    });

    // Decide effective time bucketing for arcs (mirror binning heuristics)
    const zoomLevel = calculateZoomLevel(xScale, timeExtent);
    const currentDomain = xScale.domain();
    const relevantTimeRange = Math.max(1, currentDomain[1] - currentDomain[0]);
    const effectiveBinCount = getEffectiveBinCount(GLOBAL_BIN_COUNT, renderMode);
    const binSizeCandidate = getBinSize(zoomLevel, relevantTimeRange, effectiveBinCount, useBinning);
    const microsPerPixel = Math.max(1, Math.floor(relevantTimeRange / Math.max(1, (typeof width === 'number' ? width : 1))));
    const estBins = Math.max(1, Math.min(effectiveBinCount, Math.floor(typeof width === 'number' ? width : effectiveBinCount)));
    const expectedPktsPerBin = visiblePackets.length / estBins;
    const doBinning = (binSizeCandidate !== 0) && (binSizeCandidate > microsPerPixel) && (expectedPktsPerBin >= 1.15);

    // Group packets by time bucket + src/dst pair + flagType to get per-arc counts
    const arcGroups = new Map();
    for (const packet of visiblePackets) {
        const timestamp = Math.floor(packet.timestamp);
        const timeBucket = doBinning ? Math.floor(timestamp / binSizeCandidate) * binSizeCandidate : timestamp;
        const flagType = classifyFlags(packet.flags);
        const key = `${timeBucket}|${packet.src_ip}|${packet.src_port || 0}|${packet.dst_ip}|${packet.dst_port || 0}|${flagType}`;
        let g = arcGroups.get(key);
        if (!g) {
            g = {
                timestamp: timeBucket,
                src_ip: packet.src_ip,
                dst_ip: packet.dst_ip,
                src_port: packet.src_port || 0,
                dst_port: packet.dst_port || 0,
                flags: packet.flags,
                flagType,
                count: 0,
                originalPackets: [],
                rep: packet
            };
            arcGroups.set(key, g);
        }
        g.count++;
        g.originalPackets.push(packet);
    }

    const groups = Array.from(arcGroups.values());

    // Build a bin-count map from the same binning used for dots, so widths match the circle legend
        const ARC_STROKE_WIDTH = 2;
        const countMap = new Map();
        groups.forEach(g => {
            const key = `${g.timestamp}_${g.src_ip}_${g.src_port}_${g.dst_ip}_${g.dst_port}_${g.flagType}`;
            countMap.set(key, g.count);
        });

    // Build a global linear scale from 1 to globalMaxBinCount (matches circle legend)
    const MIN_THICKNESS = 0.5;
    const MAX_THICKNESS = 8;
    const thicknessScale = d3.scaleLinear()
        .domain([1, Math.max(1, globalMaxBinCount)])
        .range([MIN_THICKNESS, MAX_THICKNESS])
        .clamp(true);

    groups.forEach(g => {
        const ftype = g.flagType;
        if (!isFlagVisibleByPhase(ftype, { showEstablishment, showDataTransfer, showClosing })) return;

        const pathPacket = g.rep;
        const path = arcPathGenerator(pathPacket, { xScale, ipPositions, pairs, findIPPosition, flagCurvature: FLAG_CURVATURE });
        if (path && pathPacket.src_ip !== pathPacket.dst_ip) {
            // Lookup bin count using the group's time bucket (g.timestamp) and the source row y position
            const yPos = findIPPosition(pathPacket.src_ip, pathPacket.src_ip, pathPacket.dst_ip, pairs, ipPositions);
                const thickness = ARC_STROKE_WIDTH;
            const arc = mainGroup.append("path")
                .attr("class", "flow-arc")
                .attr("d", path)
                .style("stroke", flagColors[ftype] || flagColors.OTHER)
                .style("stroke-width", `${thickness}px`)
                .style("opacity", 0.5)
                .datum(g);

            // Add interactivity: show packet info on hover
            arc.on('mouseover', (event, d) => {
                const tooltip = d3.select('#tooltip');
                tooltip.style('display', 'block').html(createTooltipHTML(d));
            }).on('mousemove', (event) => {
                const tooltip = d3.select('#tooltip');
                tooltip.style('left', `${event.pageX + 40}px`).style('top', `${event.pageY - 40}px`);
            }).on('mouseout', () => {
                d3.select('#tooltip').style('display', 'none');
            });
        }
    });
}

function updateHandshakeLinesGlobal() { /* Handshake lines group present but disabled in UI */ }
function updateClosingLinesGlobal() { /* Closing lines group present but disabled in UI */ }

// Flow selection event listeners removed (handled by modal controls now)
        
// Sidebar event wiring moved to sidebar.js (sbWireSidebarControls)





// Function to draw ground truth event boxes
function drawGroundTruthBoxes(selectedIPs) {
    if (!showGroundTruth || !groundTruthData || groundTruthData.length === 0) {
        // Remove existing ground truth boxes if not showing
        mainGroup.selectAll('.ground-truth-box').remove();
        mainGroup.selectAll('.ground-truth-label').remove();
        return;
    }

    const matchingEvents = filterGroundTruthByIPs(groundTruthData, selectedIPs);
    if (matchingEvents.length === 0) {
        mainGroup.selectAll('.ground-truth-box').remove();
        mainGroup.selectAll('.ground-truth-label').remove();
        return;
    }

    // Create ground truth group if it doesn't exist
    let groundTruthGroup = mainGroup.select('.ground-truth-group');
    if (groundTruthGroup.empty()) {
        groundTruthGroup = mainGroup.append('g').attr('class', 'ground-truth-group');
    }

    // Prepare data for boxes using new module function
    const boxData = prepareGroundTruthBoxData(matchingEvents, {
        xScale,
        findIPPosition,
        pairs,
        ipPositions,
        eventColors
    });

    // Update boxes
    const boxes = groundTruthGroup.selectAll('.ground-truth-box')
        .data(boxData, d => `${d.event.source}-${d.event.destination}-${d.event.startTimeMicroseconds}-${d.ip}-${d.isSource ? 'src' : 'dst'}`);

    boxes.exit().remove();

    const newBoxes = boxes.enter()
        .append('rect')
        .attr('class', 'ground-truth-box')
        .attr('fill', d => d.color)
        .attr('stroke', d => d.color);

    function formatAdjStop(adjStop, wasExpanded) {
        let s = epochMicrosecondsToUTC(adjStop).replace(' UTC','');
        if (s.includes('.')) s = s.split('.')[0];
        if (wasExpanded) s += ' (+59s)';
        return s;
    }
    function showTooltip(event, d) {
        const tooltip = d3.select('#tooltip');
        const adjStop = d.adjustedStopMicroseconds || d.event.stopTimeMicroseconds;
        const adjStart = d.adjustedStartMicroseconds || d.event.startTimeMicroseconds;
        const durationSec = Math.round((adjStop - adjStart) / 1_000_000);
        const startStr = d.event.startTime;
        const expandedStopStr = formatAdjStop(adjStop, false);
        let tooltipContent = `
            <b>${d.event.eventType}</b><br>
            IP: ${d.ip} (${d.isSource ? 'Source' : 'Destination'})<br>
            From: ${d.event.source}<br>
            To: ${d.event.destination}<br>
            Start: ${startStr}<br>
        `;
        if (d.wasExpanded) {
            tooltipContent += `Original Stop: ${d.event.stopTime}<br>`;
            tooltipContent += `Estimated Stop (+59s): ${expandedStopStr}<br>`;
            tooltipContent += `Estimated Duration: ~${durationSec}s`;
        } else {
            tooltipContent += `Stop: ${d.event.stopTime}<br>`;
            tooltipContent += `Duration: ${durationSec}s`;
        }
        tooltip.style('display','block').html(tooltipContent);
    }
    function moveTooltip(e) { d3.select('#tooltip').style('left', `${e.pageX + 40}px`).style('top', `${e.pageY - 40}px`); }
    function hideTooltip() { d3.select('#tooltip').style('display','none'); }
    groundTruthGroup.selectAll('.ground-truth-box')
        .on('mouseover', showTooltip)
        .on('mousemove', moveTooltip)
        .on('mouseout', hideTooltip);

    // Update all boxes (existing and new)
    groundTruthGroup.selectAll('.ground-truth-box')
        .attr('x', d => d.x)
        .attr('y', d => d.y)
        .attr('width', d => d.width)
        .attr('height', d => d.height);

    // Add labels for events that are wide enough (only on source IP boxes to avoid duplication)
    const labels = groundTruthGroup.selectAll('.ground-truth-label')
        .data(boxData.filter(d => d.width > 50 && d.isSource), d => `${d.event.source}-${d.event.destination}-${d.event.startTimeMicroseconds}-label`);

    labels.exit().remove();

    const newLabels = labels.enter()
        .append('text')
        .attr('class', 'ground-truth-label')
        .attr('fill', '#2c3e50')
        .style('pointer-events', 'none');

    // Update all labels
    groundTruthGroup.selectAll('.ground-truth-label')
        .attr('x', d => d.x + d.width / 2)
        .attr('y', d => d.y + d.height / 2)
        .text(d => d.event.eventType.length > 20 ? 
            d.event.eventType.substring(0, 17) + '...' : 
            d.event.eventType);

    // Keep ground-truth boxes and labels above packet circles and arcs
    try { groundTruthGroup.raise(); } catch (_) {}
}

// IP selection event listeners
document.getElementById('selectAllIPs').addEventListener('click', async () => {
    document.querySelectorAll('#ipCheckboxes input[type="checkbox"]').forEach(cb => cb.checked = true);
    await updateIPFilter();
});
        
document.getElementById('clearAllIPs').addEventListener('click', async () => {
    document.querySelectorAll('#ipCheckboxes input[type="checkbox"]').forEach(cb => cb.checked = false);
    await updateIPFilter();
});

// IP search functionality
document.getElementById('ipSearch').addEventListener('input', (e) => {
    filterIPList(e.target.value);
});

let updateTimeout = null;
let isUpdating = false;

async function updateIPFilter() {
    // Prevent multiple simultaneous updates
    if (isUpdating) return;
    isUpdating = true;

    // Show loading indicator
    const loadingDiv = d3.select('body').append('div')
        .style('position', 'fixed')
        .style('top', '50%')
        .style('left', '50%')
        .style('transform', 'translate(-50%, -50%)')
        .style('background', 'rgba(0,0,0,0.8)')
        .style('color', 'white')
        .style('padding', '20px')
        .style('border-radius', '5px')
        .style('z-index', '9999')
        .text('Updating interface...');

    try {
        const selectedIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked'))
            .map(cb => cb.value);
        const selectedIPSet = new Set(selectedIPs);
        
        const cacheKey = selectedIPs.slice().sort().join('|');
        if (selectedIPs.length < 2) {
            // Only show packet links when 2 or more IPs are selected
            if (filterCache.has(cacheKey)) {
                filteredData = filterCache.get(cacheKey);
            } else {
                filteredData = [];
                filterCache.set(cacheKey, filteredData);
            }
            dataVersion++;
        } else {
            if (filterCache.has(cacheKey)) {
                filteredData = filterCache.get(cacheKey);
                if (DEBUG) console.log('Using cached filteredData for key', cacheKey, 'len', filteredData.length);
            } else {
                const result = fullData.filter(packet =>
                    selectedIPSet.has(packet.src_ip) && selectedIPSet.has(packet.dst_ip)
                );
                filterCache.set(cacheKey, result);
                filteredData = result;
                if (DEBUG) console.log('Cached filteredData for key', cacheKey, 'len', filteredData.length);
            }
            dataVersion++;
        }

        // ALWAYS filter flows by selected IPs (even if < 2 selected)
        if (selectedIPs.length === 0) {
            // No IPs selected - show no flows
            currentFlows = [];
        } else {
            // Filter flows: show flows where both endpoints are in selected IPs
            LOG(`Filtering ${tcpFlows.length} flows with selected IPs:`, selectedIPs);
            currentFlows = (Array.isArray(tcpFlows) ? tcpFlows : []).filter(f => selectedIPSet.has(f.initiator) && selectedIPSet.has(f.responder));
            LOG(`Filtered to ${currentFlows.length} flows matching selected IPs`);
        }

        // Clear selection to avoid stale selection across different IP filters
        selectedFlowIds.clear();

        // Update flow stats (flow list will be populated when user clicks on overview chart)
        updateTcpFlowStats(currentFlows);
        
        // Update ground truth statistics
        // Update ground truth stats using new module
        const stats = calculateGroundTruthStats(groundTruthData, selectedIPs, eventColors);
        sbUpdateGroundTruthStatsUI(stats.html, stats.hasMatches);

        // Sort selected IPs by earliest connection time (for chronological ordering)
        const dataForTimeCalc = filteredData.length > 0 ? filteredData : fullData;
        const earliestTimeForSelected = new Map();
        dataForTimeCalc.forEach(p => {
            const time = p.timestamp || Infinity;
            if (p.src_ip && selectedIPSet.has(p.src_ip)) {
                if (!earliestTimeForSelected.has(p.src_ip) || time < earliestTimeForSelected.get(p.src_ip)) {
                    earliestTimeForSelected.set(p.src_ip, time);
                }
            }
            if (p.dst_ip && selectedIPSet.has(p.dst_ip)) {
                if (!earliestTimeForSelected.has(p.dst_ip) || time < earliestTimeForSelected.get(p.dst_ip)) {
                    earliestTimeForSelected.set(p.dst_ip, time);
                }
            }
        });
        const sortedSelectedIPs = selectedIPs.slice().sort((a, b) => {
            const timeA = earliestTimeForSelected.get(a) || Infinity;
            const timeB = earliestTimeForSelected.get(b) || Infinity;
            if (timeA !== timeB) return timeA - timeB; // Earliest first (ascending)
            return a.localeCompare(b);
        });

        // Compute force layout positions for IPs before visualization
        computeForceLayoutPositions(filteredData, sortedSelectedIPs, () => {
            // Recreate visualization with filtered data after force layout completes
            visualizeTimeArcs(filteredData);
            // Sidebar flag stats suppressed; render flags legend in-canvas
            try { drawFlagLegend(); } catch (_) {}
            // Update IP statistics for the current filtered data
            updateIPStats(filteredData);
            // Recompute size scaling once DOM updates complete
            setTimeout(() => {
                try { recomputeGlobalMaxBinCountFromVisibleDots(); } catch (_) {}
            }, 150);
        });
    } finally {
        // Remove loading indicator
        loadingDiv.remove();
        isUpdating = false;
    }
}

// Recompute global max bin count from visible dots, then reapply radii consistently
function recomputeGlobalMaxBinCountFromVisibleDots() {
    if (!mainGroup) return;
    // Prefer the layer that is currently shown; avoids counting hidden groups
    let activeLayer = null;
    try {
        const dynDisplayed = dynamicLayer && dynamicLayer.style('display') !== 'none';
        activeLayer = dynDisplayed ? dynamicLayer : fullDomainLayer || mainGroup;
    } catch (_) {
        activeLayer = fullDomainLayer || mainGroup;
    }
    if (!activeLayer) return;
    let maxCount = 0;
    activeLayer.selectAll('.direction-dot').each(function(d) {
        if (!d) return;
        const sel = d3.select(this);
        const display = sel.style('display');
        const opacity = parseFloat(sel.style('opacity'));
        if (display === 'none' || opacity === 0) return;
        if (d.binned && d.count > 0) {
            if (d.count > maxCount) maxCount = d.count;
        }
    });
    // Consider bars too
    activeLayer.selectAll('.bin-bar-segment').each(function(w) {
        const d = w && w.datum ? w.datum : w;
        const sel = d3.select(this);
        const display = sel.style('display');
        const opacity = parseFloat(sel.style('opacity'));
        if (display === 'none' || opacity === 0) return;
        if (d && d.binned && d.count > 0) {
            if (d.count > maxCount) maxCount = d.count;
        }
    });
    // If we found no eligible bins, keep the previous scaling to avoid jumps
    if (maxCount <= 0) return;
    globalMaxBinCount = Math.max(1, maxCount);
    const scale = d3.scaleSqrt().domain([1, globalMaxBinCount]).range([RADIUS_MIN, RADIUS_MAX]);
    mainGroup.selectAll('.direction-dot')
        .attr('r', d => (d && d.binned && d.count > 1) ? scale(d.count) : RADIUS_MIN)
        .attr('data-orig-r', d => (d && d.binned && d.count > 1) ? scale(d.count) : RADIUS_MIN);
    // Keep the size legend in sync with the current scale
    try { const axisBaseY = Math.max(20, bottomOverlayHeight - 20); drawSizeLegend(bottomOverlayRoot, width, bottomOverlayHeight, axisBaseY); } catch (_) {}
    try { drawFlagLegend(); } catch (_) {}
}
        
// Delegated to sidebar.js
const createIPCheckboxes = (uniqueIPs) => sbCreateIPCheckboxes(uniqueIPs, async () => await updateIPFilter());

const updateFlagStats = (packets) => sbUpdateFlagStats(packets, classifyFlags, flagColors);

const updateIPStats = (packets) => sbUpdateIPStats(packets, flagColors, formatBytes);

// Initialize and run force layout to position IPs
// Uses extracted module functions with local state management
function computeForceLayoutPositions(packets, selectedIPs, onComplete) {
    if (isForceLayoutRunning) {
        LOG('Force layout already running, stopping previous layout');
        if (forceLayout) forceLayout.stop();
    }

    const simWidth = (typeof width !== 'undefined' && width > 0) ? width : 800;
    const simHeight = (typeof height !== 'undefined' && height > 0) ? height : 600;

    const { nodes, links } = buildForceLayoutData(packets, selectedIPs, { width: simWidth, height: simHeight });
    
    if (nodes.length === 0) {
        if (onComplete) onComplete();
        return;
    }

    forceNodes = nodes;
    forceLinks = links;
    
    console.log(`[Force Layout] Starting with ${nodes.length} nodes and ${links.length} links`);

    // Log link strengths for debugging
    if (links.length > 0) {
        const maxCount = Math.max(...links.map(l => l.count));
        const minCount = Math.min(...links.map(l => l.count));
        console.log(`[Force Layout] Link counts: min=${minCount}, max=${maxCount}`);
    }

    // Use module function but with local callback for state management
    forceLayout = computeForceLayoutPositionsBase(packets, selectedIPs, {
        d3,
        width: simWidth,
        height: simHeight,
        onComplete: (result) => {
            console.log('[Force Layout] Simulation ended');
            isForceLayoutRunning = false;
            
            // Apply positions from module result to global state
            if (result && result.ipOrder && result.ipPositions) {
                ipOrder = result.ipOrder;
                result.ipPositions.forEach((pos, ip) => {
                    ipPositions.set(ip, pos);
                });

                console.log('[Force Layout] Assigned screen positions:',
                    ipOrder.map((ip, idx) => ({ ip, y: ipPositions.get(ip) })));

                // Update the visualization to use new positions
                if (svg && mainGroup) {
                    try {
                        // Update node labels to new positions with smooth animation
                        svg.selectAll('.node')
                            .transition()
                            .duration(800)
                            .attr('transform', d => `translate(0,${ipPositions.get(d)})`);
                    } catch (e) {
                        console.error('[Force Layout] Error updating positions:', e);
                    }
                }
            }
            
            if (onComplete) onComplete();
        }
    });

    isForceLayoutRunning = true;
}

// TCP States (matching tcp_analysis.py) - now imported as TCP_STATES

// ---- Tunables - now imported as HANDSHAKE_TIMEOUT_MS, REORDER_WINDOW_PKTS, REORDER_WINDOW_MS

// ---- Minimal flag helpers - now imported from src/tcp/flags.js

// ---- Per-flow state --------------------------------------------------------
// HandshakeState type
// 'NEW' | 'SYN_SEEN' | 'SYNACK_SEEN' | 'ACK3_SEEN' | 'INVALID'

// InvalidReason type
// 'ack_without_handshake' | 'orphan_syn_timeout' | 'orphan_synack_timeout' | 'bad_seq_ack_numbers' | 'rst_during_handshake'

// FlowState interface
// { hs, established, syn, synAck, ack3, firstSeenTs, lastSeenTs, pending, pendingBytes, invalid, timers }

function getFlow(map, key, ts) {
    let f = map.get(key);
    if (!f) {
        f = {
            hs: 'NEW',
            established: false,
            firstSeenTs: ts,
            lastSeenTs: ts,
            pending: [],
            pendingBytes: 0,
            timers: {}
        };
        map.set(key, f);
    }
    return f;
}

function applyPacketToHandshake(flow, pkt, now) {
    flow.lastSeenTs = now;
    if (flow.hs === 'INVALID' || flow.established) return;
    if (has(pkt, 'rst') && (flow.hs !== 'ACK3_SEEN')) {
        flow.hs = 'INVALID';
        flow.invalid = { reason: 'rst_during_handshake', atTs: now };
        return;
    }
    const pushPending = () => {
        flow.pending.push(pkt);
        if (flow.pending.length > REORDER_WINDOW_PKTS) flow.pending.shift();
        const cutoff = now - REORDER_WINDOW_MS;
        while (flow.pending.length && flow.pending[0].ts < cutoff) flow.pending.shift();
    };
    if (flow.hs === 'NEW' && isACKonly(pkt)) {
        pushPending();
        const oldest = flow.pending[0]?.ts ?? now;
        if ((now - oldest) > REORDER_WINDOW_MS) {
            flow.hs = 'INVALID';
            flow.invalid = { reason: 'ack_without_handshake', atTs: now };
        }
        return;
    }
    if (isSYN(pkt)) {
        flow.syn = pkt;
        flow.hs = 'SYN_SEEN';
        flow.timers.synExpire = now + HANDSHAKE_TIMEOUT_MS;
        return;
    }
    if (isSYNACK(pkt)) {
        flow.synAck = pkt;
        if (flow.hs === 'SYN_SEEN') {
            flow.hs = 'SYNACK_SEEN';
            flow.timers.synAckExpire = now + HANDSHAKE_TIMEOUT_MS;
            return;
        }
        if (flow.hs === 'NEW') {
            pushPending();
            const oldest = flow.pending[0]?.ts ?? now;
            if ((now - oldest) > REORDER_WINDOW_MS) {
                flow.hs = 'INVALID';
                flow.invalid = { reason: 'orphan_synack_timeout', atTs: now };
            }
            return;
        }
    }
    if (has(pkt,'ack') && !has(pkt,'syn') && !has(pkt,'rst')) {
        if (flow.syn && flow.synAck) {
            const okAckToSynAckSeq   = (pkt.ackNum === (flow.synAck.seq + 1) >>> 0);
            const okAckFromSynToAck3 = (flow.synAck.ackNum === ((flow.syn.seq + 1) >>> 0));
            if (!okAckToSynAckSeq || !okAckFromSynToAck3) {
                flow.hs = 'INVALID';
                flow.invalid = { reason: 'bad_seq_ack_numbers', atTs: now };
                return;
            }
            flow.ack3 = pkt;
            flow.hs = 'ACK3_SEEN';
            flow.established = true;
            flow.timers = {};
            flow.pending = [];
            return;
        }
        if (flow.syn && !flow.synAck) {
            pushPending();
            if (flow.timers.synExpire && now > flow.timers.synExpire) {
                flow.hs = 'INVALID';
                flow.invalid = { reason: 'orphan_syn_timeout', atTs: now };
            }
            return;
        }
        if (flow.hs === 'NEW') {
            pushPending();
            const oldest = flow.pending[0]?.ts ?? now;
            if ((now - oldest) > REORDER_WINDOW_MS) {
                flow.hs = 'INVALID';
                flow.invalid = { reason: 'ack_without_handshake', atTs: now };
            }
            return;
        }
    }
    if (flow.hs === 'SYN_SEEN' && flow.timers.synExpire && now > flow.timers.synExpire) {
        flow.hs = 'INVALID';
        flow.invalid = { reason: 'orphan_syn_timeout', atTs: now };
        return;
    }
    if (flow.hs === 'SYNACK_SEEN' && flow.timers.synAckExpire && now > flow.timers.synAckExpire) {
        flow.hs = 'INVALID';
        flow.invalid = { reason: 'orphan_synack_timeout', atTs: now };
        return;
    }
}

function detectHandshakePatterns(packets) {
    const handshakes = [];
    const connectionMap = new Map();
    
    // Group packets by connection (src_ip:src_port -> dst_ip:dst_port)
    packets.forEach(packet => {
        if (packet.src_port && packet.dst_port) {
            const connectionKey = `${packet.src_ip}:${packet.src_port}-${packet.dst_ip}:${packet.dst_port}`;
            const reverseKey = `${packet.dst_ip}:${packet.dst_port}-${packet.src_ip}:${packet.src_port}`;
            
            // Use the lexicographically smaller key to ensure consistent ordering
            const key = connectionKey < reverseKey ? connectionKey : reverseKey;
            
            if (!connectionMap.has(key)) {
                connectionMap.set(key, []);
            }
            connectionMap.get(key).push(packet);
        }
    });
    
    // Analyze each connection for handshake patterns
    connectionMap.forEach((connectionPackets, connectionKey) => {
        // Sort packets by timestamp
        connectionPackets.sort((a, b) => a.timestamp - b.timestamp);
        
        // Look for SYN -> SYN+ACK -> ACK patterns
        const synPackets = connectionPackets.filter(p => classifyFlags(p.flags) === 'SYN');
        const synAckPackets = connectionPackets.filter(p => classifyFlags(p.flags) === 'SYN+ACK');
        const ackPackets = connectionPackets.filter(p => classifyFlags(p.flags) === 'ACK');
        
        // Try to match handshake sequences
        synPackets.forEach(synPacket => {
            // Find corresponding SYN+ACK packet
            const synAckPacket = synAckPackets.find(sa => 
                sa.timestamp > synPacket.timestamp &&
                sa.ack_num === synPacket.seq_num + 1 &&
                ((sa.src_ip === synPacket.dst_ip && sa.dst_ip === synPacket.src_ip) ||
                 (sa.src_ip === synPacket.src_ip && sa.dst_ip === synPacket.dst_ip))
            );
            
            if (synAckPacket) {
                // Find corresponding ACK packet
                const ackPacket = ackPackets.find(ack => 
                    ack.timestamp > synAckPacket.timestamp &&
                    ack.seq_num === synPacket.seq_num + 1 &&
                    ack.ack_num === synAckPacket.seq_num + 1 &&
                    ((ack.src_ip === synPacket.src_ip && ack.dst_ip === synPacket.dst_ip) ||
                     (ack.src_ip === synPacket.dst_ip && ack.dst_ip === synPacket.src_ip))
                );
                
                if (ackPacket) {
                    handshakes.push({
                        connectionKey: connectionKey,
                        syn: synPacket,
                        synAck: synAckPacket,
                        ack: ackPacket,
                        initiator: synPacket.src_ip,
                        responder: synPacket.dst_ip
                    });
                }
            }
        });
    });
    
    return handshakes;
}

function detectClosingPatterns(packets) {
    const closings = [];
    const connectionMap = new Map();
    const connectionStates = new Map(); // Track connection states like tcp_analysis.py
    
    // Group packets by connection (src_ip:src_port -> dst_ip:dst_port)
    packets.forEach(packet => {
        if (packet.src_port && packet.dst_port) {
            const connectionKey = `${packet.src_ip}:${packet.src_port}-${packet.dst_ip}:${packet.dst_port}`;
            const reverseKey = `${packet.dst_ip}:${packet.dst_port}-${packet.src_ip}:${packet.src_port}`;
            
            // Use the lexicographically smaller key to ensure consistent ordering
            const key = connectionKey < reverseKey ? connectionKey : reverseKey;
            
            if (!connectionMap.has(key)) {
                connectionMap.set(key, []);
                // Initialize connection state (matching tcp_analysis.py Conn structure)
                connectionStates.set(key, {
                    initiator: null,
                    responder: null,
                    isn_i: null,
                    isn_r: null,
                    state: TCP_STATES.S_NEW,
                    t_syn: null,
                    t_synack: null,
                    t_ack3: null,
                    t_close: null,
                    close_reason: null,
                    saw_syn_in_capture: false
                });
            }
            connectionMap.get(key).push(packet);
        }
    });
    
    // Process each connection with state machine (matching tcp_analysis.py logic)
    connectionMap.forEach((connectionPackets, connectionKey) => {
        // Sort packets by timestamp
        connectionPackets.sort((a, b) => a.timestamp - b.timestamp);
        
        let state = connectionStates.get(connectionKey);
        let fin1Packet = null, fin2Packet = null, finalAckPacket = null;
        
        // Process packets in order to build state machine
        for (const packet of connectionPackets) {
            const flags = packet.flags;
            const syn = (flags & 0x02) !== 0;
            const ackf = (flags & 0x10) !== 0;
            const fin = (flags & 0x01) !== 0;
            const rst = (flags & 0x04) !== 0;
            
            // SYN packet (handshake start)
            if (syn && !ackf && !rst) {
                if (state.initiator === null) {
                    state.initiator = [packet.src_ip, packet.src_port];
                    state.responder = [packet.dst_ip, packet.dst_port];
                    state.isn_i = packet.seq_num;
                    state.t_syn = packet.timestamp;
                    state.state = TCP_STATES.S_INIT;
                    state.saw_syn_in_capture = true;
                }
            }
            
            // SYN+ACK packet
            else if (syn && ackf && !rst && state.state === TCP_STATES.S_INIT) {
                if (packet.ack_num === state.isn_i + 1) {
                    state.isn_r = packet.seq_num;
                    state.t_synack = packet.timestamp;
                    state.state = TCP_STATES.S_SYN_RCVD;
                }
            }
            
            // Final ACK (handshake complete)
            else if (ackf && !syn && !fin && !rst && state.state === TCP_STATES.S_SYN_RCVD) {
                if (packet.ack_num === state.isn_r + 1) {
                    state.t_ack3 = packet.timestamp;
                    state.state = TCP_STATES.S_EST;
                }
            }
            
            // RST (abortive close)
            else if (rst && state.state >= TCP_STATES.S_EST) {
                state.t_close = packet.timestamp;
                state.close_reason = "rst";
                state.state = TCP_STATES.S_ABORTED;
                break; // Connection terminated
            }
            
            // FIN-based graceful close (matching tcp_analysis.py state machine)
            else if (fin && state.state >= TCP_STATES.S_EST) {
                if (state.state === TCP_STATES.S_EST) {
                    // First FIN received
                    state.state = TCP_STATES.S_FIN_1;
                    fin1Packet = packet;
                } else if (state.state === TCP_STATES.S_FIN_1) {
                    // Second FIN received (from other side)
                    state.state = TCP_STATES.S_FIN_2;
                    fin2Packet = packet;
                }
            }
            // Final ACK after second FIN (normal TCP close)
            else if (ackf && !fin && !syn && !rst && state.state === TCP_STATES.S_FIN_2) {
                state.state = TCP_STATES.S_CLOSED;
                state.t_close = packet.timestamp;
                state.close_reason = "fin";
                finalAckPacket = packet;
                break; // Connection terminated
            }
        }
        
        // If we have a complete closing sequence, add it to results
        if (state.state === TCP_STATES.S_CLOSED && state.close_reason === "fin" && fin1Packet && fin2Packet && finalAckPacket) {
            closings.push({
                connectionKey: connectionKey,
                type: 'graceful_close',
                fin1: fin1Packet,
                fin2: fin2Packet,
                ack: finalAckPacket,
                initiator: state.initiator[0],
                responder: state.responder[0],
                state: state
            });
        }
        // Handle half-close (only one FIN received before connection ends)
        else if (state.state === TCP_STATES.S_FIN_1 && fin1Packet) {
            // Look for ACK to the FIN
            const ackPacket = connectionPackets.find(p => 
                p.timestamp > fin1Packet.timestamp &&
                (p.flags & 0x10) !== 0 && // ACK flag
                p.ack_num === fin1Packet.seq_num + 1 &&
                ((p.src_ip === fin1Packet.dst_ip && p.dst_ip === fin1Packet.src_ip) ||
                 (p.src_ip === fin1Packet.src_ip && p.dst_ip === fin1Packet.dst_ip))
            );
            
            if (ackPacket) {
                closings.push({
                    connectionKey: connectionKey,
                    type: 'half_close',
                    fin1: fin1Packet,
                    ack: ackPacket,
                    initiator: state.initiator[0],
                    responder: state.responder[0],
                    state: state
                });
            }
        }
    });
    
    return closings;
}

function updateHandshakeStats(handshakes) {
    const container = document.getElementById('handshakeStats');
    if (handshakes.length === 0) {
        container.innerHTML = 'No handshakes detected';
        container.style.color = '#666';
    } else {
        container.innerHTML = `Found ${handshakes.length} handshake(s)`;
        container.style.color = '#27ae60';
        
        // Debug info
        LOG('Handshake patterns detected:', handshakes);
    }
}

function updateClosingStats(closings) {
    const container = document.getElementById('closingStats');
    if (closings.length === 0) {
        container.innerHTML = 'No closing patterns detected';
        container.style.color = '#666';
    } else {
        // Group by type
        const typeCounts = {};
        closings.forEach(closing => {
            typeCounts[closing.type] = (closing.typeCounts || 0) + 1;
        });
        
        let statsHTML = `<strong>Found ${closings.length} closing pattern(s)</strong><br>`;
        Object.entries(typeCounts).forEach(([type, count]) => {
            const typeLabel = type.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase());
            statsHTML += `${typeLabel}: ${count}<br>`;
        });
        
        container.innerHTML = statsHTML;
        container.style.color = '#27ae60';
    }
}

// Wrapper for exportFlowToCSV that provides the fullData and helpers
function exportFlowToCSV(flow) {
    return exportFlowToCSVFromModule(flow, fullData, { classifyFlags, formatTimestamp });
}

const createFlowList = (flows) => sbCreateFlowListCapped(flows, selectedFlowIds, formatBytes, formatTimestamp, exportFlowToCSV, zoomToFlow, updateTcpFlowPacketsGlobal, flowColors);

const updateTcpFlowStats = (flows) => sbUpdateTcpFlowStats(flows, selectedFlowIds, formatBytes);

function filterIPList(searchTerm) {
    const ipItems = document.querySelectorAll('.ip-item');
    ipItems.forEach(item => {
        const ip = item.dataset.ip;
        const matches = ip.toLowerCase().includes(searchTerm.toLowerCase());
        item.style.display = matches ? 'block' : 'none';
    });
}

// createTooltipHTML is now imported from './src/rendering/tooltip.js'

// Global function to find the correct Y position for an IP (single row per IP)
function findIPPosition(ip, _src_ip, _dst_ip, _pairs, ipPositions) {
    if (!ipPositions) return 0;
    return ipPositions.get(ip) || 0;
}

// Async CSV parsing with progress tracking
async function parseCSVAsync(csvText, onProgress) {
    const lines = csvText.split('\n').filter(line => line.trim().length > 0);
    if (lines.length < 2) return [];
    
    // Parse header line
    const headerLine = lines[0];
    const headers = [];
    let current = '';
    let inQuotes = false;
    
    for (let j = 0; j < headerLine.length; j++) {
        const char = headerLine[j];
        if (char === '"') {
            inQuotes = !inQuotes;
        } else if (char === ',' && !inQuotes) {
            headers.push(current.trim());
            current = '';
        } else {
            current += char;
        }
    }
    headers.push(current.trim());
    
    const packets = [];
    const totalLines = lines.length - 1; // Exclude header
    const BATCH_SIZE = 1000; // Process in batches for progress updates
    
    for (let i = 1; i < lines.length; i += BATCH_SIZE) {
        const endIndex = Math.min(i + BATCH_SIZE, lines.length);
        
        for (let lineIndex = i; lineIndex < endIndex; lineIndex++) {
            const line = lines[lineIndex];
            if (!line.trim()) continue;
            
            const values = [];
            current = '';
            inQuotes = false;
            
            for (let j = 0; j < line.length; j++) {
                const char = line[j];
                if (char === '"') {
                    inQuotes = !inQuotes;
                } else if (char === ',' && !inQuotes) {
                    values.push(current.trim());
                    current = '';
                } else {
                    current += char;
                }
            }
            values.push(current.trim());
            
            if (values.length >= headers.length) {
                const packet = {};
                for (let k = 0; k < headers.length; k++) {
                    const header = headers[k].toLowerCase().replace(/[^a-z0-9]/g, '_');
                    let value = values[k];
                    
                    // Type conversion
                    if (header.includes('time') || header.includes('timestamp')) {
                        value = parseFloat(value) || 0;
                    } else if (header.includes('length') || header.includes('size') || header.includes('port') || header.includes('seq') || header.includes('ack')) {
                        value = parseInt(value) || 0;
                    }
                    
                    packet[header] = value;
                }
                
                if (packet.src_ip && packet.dst_ip && packet.timestamp) {
                    packets.push(packet);
                }
            }
        }
        
        // Update progress
        if (onProgress) {
            const progress = (endIndex - 1) / totalLines;
            onProgress(progress, `Parsing CSV... ${(endIndex - 1).toLocaleString()}/${totalLines.toLocaleString()} lines`);
        }
        
        // Allow UI to update
        if (i % (BATCH_SIZE * 5) === 0) {
            await new Promise(resolve => setTimeout(resolve, 0));
        }
    }
    
    LOG(`Parsed ${packets.length} packets from ${lines.length - 1} CSV lines`);
    return packets;
}

// CSV parsing helper function
function parseCSV(csvText) {
    const lines = csvText.split('\n').filter(line => line.trim().length > 0);
    if (lines.length < 2) return [];
    
    // Parse header line
    const headerLine = lines[0];
    const headers = [];
    let current = '';
    let inQuotes = false;
    
    for (let j = 0; j < headerLine.length; j++) {
        const char = headerLine[j];
        if (char === '"') {
            inQuotes = !inQuotes;
        } else if (char === ',' && !inQuotes) {
            headers.push(current.trim().replace(/"/g, ''));
            current = '';
        } else {
            current += char;
        }
    }
    headers.push(current.trim().replace(/"/g, ''));
    
    LOG(`CSV has ${headers.length} columns:`, headers.slice(0, 10));
    
    const packets = [];
    
    // Parse data lines
    for (let i = 1; i < lines.length; i++) {
        const values = [];
        const line = lines[i];
        current = '';
        inQuotes = false;
        
        // Parse each field in the line
        for (let j = 0; j < line.length; j++) {
            const char = line[j];
            if (char === '"') {
                inQuotes = !inQuotes;
            } else if (char === ',' && !inQuotes) {
                values.push(current.trim().replace(/"/g, ''));
                current = '';
            } else {
                current += char;
            }
        }
        values.push(current.trim().replace(/"/g, ''));
        
        // Only process lines with enough values
        if (values.length >= headers.length - 5) { // Allow some tolerance for missing fields
            const packet = {};
            headers.forEach((header, index) => {
                const value = values[index] || '';
                
                // Convert numeric fields
                if (['timestamp', 'src_port', 'dst_port', 'flags', 'seq_num', 'ack_num', 'length', 
                     'flow_start_time', 'flow_end_time', 'flow_total_packets', 'flow_total_bytes',
                     'establishment_packets', 'data_transfer_packets', 'closing_packets',
                     'src_sent_packets', 'src_recv_packets', 'src_sent_bytes', 'src_recv_bytes',
                     'src_first_ts', 'src_last_ts', 'dst_sent_packets', 'dst_recv_packets',
                     'dst_sent_bytes', 'dst_recv_bytes', 'dst_first_ts', 'dst_last_ts'].includes(header)) {
                    packet[header] = parseFloat(value) || 0;
                } else if (['establishment_complete', 'data_transfer_started', 'closing_started'].includes(header)) {
                    packet[header] = value.toLowerCase() === 'true';
                } else {
                    packet[header] = value || '';
                }
            });
            
            packet.timestamp = Math.floor(packet.timestamp);
            if (packet.timestamp > 0 && packet.src_ip && packet.dst_ip) {
                packets.push(packet);
            }
        }
        if (i % 10000 === 0) {
            LOG(`Parsed ${i}/${lines.length} lines...`);
        }
    }
    
    LOG(`Successfully parsed ${packets.length} packets from ${lines.length - 1} CSV lines`);
    return packets;
}

function handleFileLoad(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    // Show CSV loading progress
    try { sbShowCsvProgress('Reading CSV file...', 0); } catch (_) {}
    
    const reader = new FileReader();
    reader.onload = async e => {
        try {
            const csvText = e.target.result;
            
            // Update progress for parsing phase
            try { sbUpdateCsvProgress(0.1, 'Parsing CSV data...'); } catch (_) {}
            
            const packets = await parseCSVAsync(csvText, (progress, label) => {
                try { sbUpdateCsvProgress(0.1 + (progress * 0.4), label); } catch (_) {}
            });
            
            if (packets && packets.length > 0) {
                // Packets
                fullData = packets;
                filteredData = [];

                // Process TCP flows with progress
                try { sbUpdateCsvProgress(0.5, 'Processing TCP flows...'); } catch (_) {}
                try { sbShowFlowProgress('Processing flows…', 0); } catch (_) {}
                const flowsFromCSV = await reconstructFlowsFromCSVAsync(packets, (processed, total) => {
                    try {
                        const pct = total > 0 ? processed / total : 0;
                        sbUpdateFlowProgress(pct, `Processing flows… ${processed.toLocaleString()}/${total.toLocaleString()}`);
                        // Update CSV progress (flows processing is 50-90% of total)
                        sbUpdateCsvProgress(0.5 + (pct * 0.4), `Processing flows… ${processed.toLocaleString()}/${total.toLocaleString()}`);
                    } catch (_) {}
                });
                tcpFlows = flowsFromCSV;
                currentFlows = []; // Initialize as empty - will be populated when IPs are selected
                selectedFlowIds.clear(); // Clear selected flow IDs
                // Don't populate flow list or stats until IPs are selected
                updateTcpFlowStats(currentFlows); // Show initial message about selecting IPs

                // IPs - extract unique IPs from packet data
                try { sbUpdateCsvProgress(0.9, 'Extracting IP addresses...'); } catch (_) {}
                const uniqueIPs = Array.from(new Set(fullData.flatMap(p => [p.src_ip, p.dst_ip]))).filter(Boolean);
                createIPCheckboxes(uniqueIPs);

                // Wait for user selection
                document.getElementById('loadingMessage').textContent = 'Please select 2 or more IP addresses to view connections.';
                document.getElementById('loadingMessage').style.display = 'block';
                
                LOG(`Loaded ${packets.length} packets from CSV with ${uniqueIPs.length} unique IPs`);
                
                // Verify flow-packet connection
                verifyFlowPacketConnection(packets, flowsFromCSV);
                // Initialize web worker after packets parsed - will sync with rendered data later
                try {
                    try { sbUpdateCsvProgress(0.95, 'Initializing web worker...'); } catch (_) {}
                    if (!workerManager) {
                        initializeWorkerManager();
                    }
                    // Don't init packets here - will sync with rendered data after visualization is built
                } catch (err) {
                    console.error('Worker init failed', err);
                }
                
                // Complete loading
                try { sbUpdateCsvProgress(1.0, 'Loading complete!'); } catch (_) {}
                try { sbHideFlowProgress(); } catch (_) {}
                setTimeout(() => {
                    try { sbHideCsvProgress(); } catch (_) {}
                }, 1000);
            } else {
                try { sbHideCsvProgress(); } catch (_) {}
                alert('Invalid CSV format: No valid packet data found.');
            }
        } catch (error) { 
            try { sbHideCsvProgress(); } catch (_) {}
            alert('Error parsing CSV file: ' + error.message); 
        }
    };
    reader.readAsText(file);
}

function highlight(selected) {
    const hasSelection = selected && (selected.ip || selected.flag);
    
    if (hasSelection && selected.ip) {
        // Simple IP-based highlighting
        svg.selectAll(".node-label")
            .classed("faded", d => d !== selected.ip)
            .classed("highlighted", d => d === selected.ip);
        
        mainGroup.selectAll(".direction-dot")
            .classed("faded", d => d.src_ip !== selected.ip && d.dst_ip !== selected.ip)
            .classed("highlighted", d => d.src_ip === selected.ip || d.dst_ip === selected.ip);
    } else if (hasSelection && selected.flag) {
        // Flag-based highlighting
        mainGroup.selectAll(".direction-dot")
            .classed("faded", d => classifyFlags(d.flags) !== selected.flag)
            .classed("highlighted", d => classifyFlags(d.flags) === selected.flag);
    } else {
        // No selection - reset all highlighting
        mainGroup.selectAll(".direction-dot")
            .classed("faded", false)
            .classed("highlighted", false);
        svg.selectAll(".node-label")
            .classed("faded", false)
            .classed("highlighted", false);
    }
    
    // Update flag stats highlighting
    document.querySelectorAll('#flagStats [data-flag]').forEach(item => {
        if (hasSelection && selected.flag) {
            if (item.dataset.flag === selected.flag) {
                item.style.backgroundColor = '#e9ecef';
                item.style.fontWeight = 'bold';
            } else {
                item.style.opacity = '0.3';
            }
        } else {
            item.style.backgroundColor = '';
            item.style.fontWeight = '';
            item.style.opacity = '';
        }
    });
}


function zoomToFlow(flow) {
    if (!flow || !svg || !zoom || !xScale || !timeExtent || !Array.isArray(fullData)) {
        console.warn('Cannot zoom to flow: missing required objects');
        return;
    }
    let minTs = Math.floor(typeof flow.startTime === 'number' ? flow.startTime : NaN);
    let maxTs = Math.floor(typeof flow.endTime === 'number' ? flow.endTime : NaN);
    if (!Number.isFinite(minTs) || !Number.isFinite(maxTs)) {
        console.warn('zoomToFlow: Could not determine packet time range for flow', flow);
        return;
    }
    const totalRange = timeExtent[1] - timeExtent[0];
    const minPaddingUs = 50000; // 0.05s minimum margin on each side
    const paddingPixels = 2; // desired pixel padding on each side (very tight)
    const paddingPercent = 0.005; // 0.5% of the flow duration on each side (very tight)
    const timePerPixel = totalRange / Math.max(1, width);
    const paddingFromPixels = Math.ceil(paddingPixels * timePerPixel);
    const flowDuration = Math.max(1, maxTs - minTs);
    const paddingFromPercent = Math.ceil(flowDuration * paddingPercent);
    const cappedPercentPadding = Math.min(paddingFromPercent, Math.ceil(flowDuration * 0.25));
    const padding = Math.max(minPaddingUs, Math.min(paddingFromPixels, cappedPercentPadding));
    let zoomStart = minTs - padding;
    let zoomEnd = maxTs + padding;
    zoomStart = Math.max(timeExtent[0], Math.floor(zoomStart));
    zoomEnd = Math.min(timeExtent[1], Math.ceil(zoomEnd));
    if (zoomEnd <= zoomStart) zoomEnd = zoomStart + 1;
    applyZoomDomain([zoomStart, zoomEnd], 'flow');
    if (typeof updateBrushFromZoom === 'function') {
        try { window.__arc_x_domain__ = xScale.domain(); updateBrushFromZoom(); } catch (_) {}
    }
}

async function processTcpFlowsChunked(packets) { /* Not invoked by default; omitted in externalization */ }

function visualizeTimeArcs(packets) {
    d3.select("#chart").html("");
    document.getElementById('loadingMessage').style.display = 'none';

    if (!packets || packets.length === 0) {
        document.getElementById('loadingMessage').textContent = 'No data to visualize.';
        document.getElementById('loadingMessage').style.display = 'block';
        return;
    }

    const flagCounts = {};
    packets.forEach(packet => {
        const flagType = classifyFlags(packet.flags);
        flagCounts[flagType] = (flagCounts[flagType] || 0) + 1;
    });

    const uniqueIPs = Array.from(new Set(packets.flatMap(p => [p.src_ip, p.dst_ip]))).filter(Boolean);
    timeExtent = d3.extent(packets, d => d.timestamp);
    try {
        const span = Math.max(1, timeExtent[1] - timeExtent[0]);
        const pad = Math.max(1, Math.floor(span * 0.02));
        timeExtent = [timeExtent[0] - pad, timeExtent[1] + pad];
    } catch {}
    fullDomainBinsCache = { version: dataVersion, data: [], binSize: null, sorted: false };

    const margin = {top: 80, right: 120, bottom: 50, left: 150};
    width = d3.select("#chart-container").node().clientWidth - margin.left - margin.right;

    const DOT_RADIUS = 40;
    ipPositions.clear();

    const ipCounts = new Map();
    packets.forEach(p => {
        if (p.src_ip) ipCounts.set(p.src_ip, (ipCounts.get(p.src_ip) || 0) + 1);
        if (p.dst_ip) ipCounts.set(p.dst_ip, (ipCounts.get(p.dst_ip) || 0) + 1);
    });

    // Calculate earliest timestamp for each IP (for chronological ordering)
    const earliestTime = new Map();
    packets.forEach(p => {
        const time = p.timestamp || Infinity;
        if (p.src_ip) {
            if (!earliestTime.has(p.src_ip) || time < earliestTime.get(p.src_ip)) {
                earliestTime.set(p.src_ip, time);
            }
        }
        if (p.dst_ip) {
            if (!earliestTime.has(p.dst_ip) || time < earliestTime.get(p.dst_ip)) {
                earliestTime.set(p.dst_ip, time);
            }
        }
    });

    const ipList = Array.from(new Set(Array.from(ipCounts.keys())));

    // Check if force layout has already computed positions
    if (ipOrder.length === 0 || ipPositions.size === 0 || ipOrder.length !== ipList.length) {
        // Force layout hasn't run yet or IP set has changed - sort by earliest connection time
        ipList.sort((a, b) => {
            const timeA = earliestTime.get(a) || Infinity;
            const timeB = earliestTime.get(b) || Infinity;
            if (timeA !== timeB) return timeA - timeB; // Earliest first (ascending)
            // If times are equal, fall back to name comparison
            return a.localeCompare(b);
        });
        // Initialize positions and order
        ipOrder = ipList.slice();
        ipList.forEach((ip, idx) => { ipPositions.set(ip, TOP_PAD + idx * ROW_GAP); });
    }
    // Otherwise use the force layout computed positions in ipOrder and ipPositions

    // Use ipOrder for yDomain to respect the force layout ordering
    const yDomain = ipOrder.length > 0 ? ipOrder : ipList;
    const yRange = yDomain.map(ip => ipPositions.get(ip));
    const [minY, maxY] = d3.extent(yRange.length ? yRange : [0]);

    height = Math.max(500, (maxY ?? 0) + ROW_GAP + DOT_RADIUS + TOP_PAD);

    xScale = d3.scaleLinear().domain(timeExtent).range([0, width]);
    yScale = d3.scaleLinear().domain([minY, maxY]).range([minY, maxY]);

    const svgContainer = d3.select("#chart").append("svg")
        .attr("width", width + margin.left + margin.right)
        .attr("height", height + margin.top + margin.bottom);

    svg = svgContainer.append("g").attr("transform", `translate(${margin.left},${margin.top})`);

    // Initialize zoom, clip, and rendering layers
    // Defer zoom initialization until after zoomed() is defined

    svg.append('defs').append('clipPath').attr('id', 'clip').append('rect')
        .attr('x', 0)
        .attr('y', -DOT_RADIUS)
        .attr('width', width + DOT_RADIUS)
        .attr('height', height + (2 * DOT_RADIUS));

    mainGroup = svg.append('g').attr('clip-path', 'url(#clip)');
    fullDomainLayer = mainGroup.append('g').attr('class', 'dots-full-domain');
    dynamicLayer = mainGroup.append('g').attr('class', 'dots-dynamic');

    // zoom will be initialized after zoomed() is declared below

    // Initialize bottom overlay axis + legends container
    try {
        chartMarginLeft = margin.left; chartMarginRight = margin.right;
        bottomOverlaySvg = d3.select('#chart-bottom-overlay-svg');
        bottomOverlayWidth = Math.max(0, width + chartMarginLeft + chartMarginRight);
        bottomOverlaySvg.attr('width', bottomOverlayWidth).attr('height', bottomOverlayHeight);
        bottomOverlayRoot = bottomOverlaySvg.select('g.overlay-root');
        if (bottomOverlayRoot.empty()) bottomOverlayRoot = bottomOverlaySvg.append('g').attr('class', 'overlay-root');
        bottomOverlayRoot.attr('transform', `translate(${chartMarginLeft},0)`);
        const axisY = Math.max(20, bottomOverlayHeight - 20);
        bottomOverlaySvg.select('.main-bottom-axis').remove();
        bottomOverlayAxisGroup = bottomOverlayRoot.append('g')
            .attr('class', 'x-axis axis main-bottom-axis')
            .attr('transform', `translate(0,${axisY})`)
            .call(d3.axisBottom(xScale).tickFormat(d => {
                const timestampInt = Math.floor(d);
                const date = new Date(timestampInt / 1000);
                return date.toISOString().split('T')[1].split('.')[0];
            }));
        bottomOverlaySvg.select('.overlay-duration-label').remove();
        bottomOverlayDurationLabel = bottomOverlayRoot.append('text')
            .attr('class', 'overlay-duration-label')
            .attr('x', width / 2)
            .attr('y', axisY - 12)
            .attr('text-anchor', 'middle')
            .style('font-size', '36px')
            .style('font-weight', '600')
            .style('fill', '#000')
            .style('opacity', 0.12)
            .text('');

    } catch (e) { LOG('Overlay init failed', e); }

    // Duration formatting helper function
    function formatDuration(us) {
        const s = us / 1_000_000;
        if (s < 0.001) return `${(s * 1000 * 1000).toFixed(0)} μs`;
        if (s < 1) return `${(s * 1000).toFixed(0)} ms`;
        if (s < 60) return `${s.toFixed(3)} s`;
        const m = Math.floor(s / 60);
        const rem = s - m * 60;
        return `${m}m ${rem.toFixed(3)}s`;
    }

    // Update zoom duration label function
    function updateZoomDurationLabel() {
        if (!bottomOverlayDurationLabel || !xScale) return;
        try {
            const domain = xScale.domain();
            const durUs = Math.max(0, Math.floor(domain[1]) - Math.floor(domain[0]));
            const label = formatDuration(durUs);
            const center = xScale((domain[0] + domain[1]) / 2);
            bottomOverlayDurationLabel.attr('x', center).text(label);
        } catch (e) { /* ignore */ }
    }

    // Initial label render
    try { updateZoomDurationLabel(); } catch(_) {}

    // Build IP row labels on the left gutter
    try {
        const node = svg.selectAll('.node')
            .data(yDomain)
            .enter()
            .append('g')
            .attr('class', 'node')
            .attr('transform', d => `translate(0,${ipPositions.get(d)})`);
        node.append('text')
            .attr('class', 'node-label')
            .attr('x', -10)
            .attr('dy', '.35em')
            .attr('text-anchor', 'end')
            .text(d => d)
            .on('mouseover', (e, d) => { try { highlight({ ip: d }); } catch(_) {} })
            .on('mouseout', () => { try { highlight(null); } catch(_) {} });
    } catch (e) { LOG('Failed to build IP labels', e); }

    // Make overview read current domain
    try { window.__arc_x_domain__ = xScale.domain(); } catch {}
    createOverviewChart(packets, { timeExtent, width });

    LOG('SVG setup:', {
        containerWidth: width + margin.left + margin.right,
        containerHeight: height + margin.top + margin.bottom,
        chartWidth: width,
        chartHeight: height,
        margin: margin,
        xScaleDomain: timeExtent,
        yScaleDomain: yDomain,
        yScaleRange: yRange
    });

    const xAxis = d3.axisBottom(xScale).tickFormat(d => {
        const timestampInt = Math.floor(d);
        const date = new Date(timestampInt / 1000);
        return date.toISOString().split('T')[1].split('.')[0];
    });

    // Now that scaffolding is ready, define the zoom handler and then initialize zoom
    let zoomTimeout;
    let handshakeTimeout;
    const zoomed = ({ transform, sourceEvent }) => {
        if (sourceEvent && sourceEvent.type === "wheel" && sourceEvent.deltaX !== 0) {
            const panAmount = sourceEvent.deltaX * 0.5;
            const currentDomain = xScale.domain();
            const domainRange = currentDomain[1] - currentDomain[0];
            const panRatio = panAmount / width;
            const panOffset = domainRange * panRatio;
            xScale.domain([currentDomain[0] - panOffset, currentDomain[1] - panOffset]);
        } else {
            const newXScale = transform.rescaleX(d3.scaleLinear().domain(timeExtent).range([0, width]));
            xScale.domain(newXScale.domain());
        }
        const currentDomain = xScale.domain();
        xScale.domain([Math.floor(currentDomain[0]), Math.floor(currentDomain[1])]);

        const flowsFilteringActiveImmediate = (showTcpFlows && selectedFlowIds.size > 0 && tcpFlows.length > 0);
        const atFullDomainImmediate = Math.floor(xScale.domain()[0]) <= Math.floor(timeExtent[0]) && Math.floor(xScale.domain()[1]) >= Math.floor(timeExtent[1]);

    // Update bottom overlay axis instead of in-chart axis
    try {
        if (bottomOverlayAxisGroup) {
            bottomOverlayAxisGroup.call(xAxis);
        }
    } catch(_) {}
    try { window.__arc_x_domain__ = xScale.domain(); } catch {}
    updateBrushFromZoom();
    try { updateZoomDurationLabel(); } catch(_) {}

        if ((isHardResetInProgress || (atFullDomainImmediate && !flowsFilteringActiveImmediate)) &&
            !flowsFilteringActiveImmediate && fullDomainLayer && fullDomainBinsCache.data.length > 0) {
            if (fullDomainLayer) fullDomainLayer.style("display", null);
            if (dynamicLayer) dynamicLayer.style("display", "none");
            try { mainGroup.selectAll('.direction-dot').style('display', 'block').style('opacity', 0.5); } catch {}
            clearTimeout(zoomTimeout);
            clearTimeout(handshakeTimeout);
            isHardResetInProgress = false;
            return;
        }

        if (showTcpFlows && tcpFlows.length > 0 && selectedFlowIds.size > 0) {
            clearTimeout(handshakeTimeout);
            handshakeTimeout = setTimeout(() => { drawSelectedFlowArcs(); }, 8);
        }

        if (showGroundTruth) {
            const selectedIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')).map(cb => cb.value);
            drawGroundTruthBoxes(selectedIPs);
        }

        clearTimeout(zoomTimeout);
        zoomTimeout = setTimeout(() => {
            const flowsFilteringActive = (showTcpFlows && selectedFlowIds.size > 0 && tcpFlows.length > 0);
            const atFullDomain = Math.floor(xScale.domain()[0]) <= Math.floor(timeExtent[0]) && Math.floor(xScale.domain()[1]) >= Math.floor(timeExtent[1]);
            if (atFullDomain && !flowsFilteringActive && fullDomainLayer && fullDomainBinsCache.data.length > 0) {
                fullDomainLayer.style("display", null);
                if (dynamicLayer) dynamicLayer.style("display", "none");
                try { updateZoomDurationLabel(); } catch(_) {}
                return;
            } else {
                if (fullDomainLayer) fullDomainLayer.style("display", "none");
                if (dynamicLayer) dynamicLayer.style("display", null);
            }
            let binnedPackets;
            if (atFullDomain && !flowsFilteringActive && fullDomainBinsCache.version === dataVersion && fullDomainBinsCache.data.length > 0) {
                binnedPackets = fullDomainBinsCache.data;
            } else {
                let visiblePackets = getVisiblePackets(filteredData, xScale);
                if (flowsFilteringActive) {
                    const selectedKeys = buildSelectedFlowKeySet();
                    visiblePackets = visiblePackets.filter(packet => {
                        if (!packet || !packet.src_ip || !packet.dst_ip) return false;
                        const key = makeConnectionKey(packet.src_ip, packet.src_port || 0, packet.dst_ip, packet.dst_port || 0);
                        return selectedKeys.has(key);
                    });
                }
                if (!visiblePackets || visiblePackets.length === 0) {
                    if (dynamicLayer) dynamicLayer.selectAll('.direction-dot').remove();
                    return;
                }
                binnedPackets = binPackets(visiblePackets, {
                    xScale,
                    timeExtent,
                    findIPPosition,
                    ipPositions,
                    pairs,
                    binCount: getEffectiveBinCount(GLOBAL_BIN_COUNT, renderMode),
                    useBinning,
                    width
                });
                if (atFullDomain && !flowsFilteringActive) {
                    fullDomainBinsCache = { version: dataVersion, data: binnedPackets, binSize: null, sorted: false };
                }
            }
            if (!(atFullDomain && !flowsFilteringActive && fullDomainBinsCache.sorted)) {
                binnedPackets.sort((a, b) => {
                    const flagA = a.flagType || classifyFlags(a.flags);
                    const flagB = b.flagType || classifyFlags(b.flags);
                    const countA = flagCounts[flagA] || 0;
                    const countB = flagCounts[flagB] || 0;
                    if (countA !== countB) {
                        return countB - countA;
                    }
                    return a.timestamp - b.timestamp;
                });
                if (atFullDomain && !flowsFilteringActive) {
                    fullDomainBinsCache.sorted = true;
                }
            }
            try { updateZoomDurationLabel(); } catch(_) {}
            let rScale = d3.scaleSqrt().domain([1, Math.max(1, globalMaxBinCount)]).range([RADIUS_MIN, RADIUS_MAX]);
            renderMarksForLayerLocal(dynamicLayer, binnedPackets, rScale);
        });
    };

    // Initialize zoom now that zoomed() exists - using module function
    zoom = createZoomBehavior({
        d3,
        scaleExtent: [1, 1e9],
        onZoom: zoomed
    });
    zoomTarget = svgContainer;
    zoomTarget.call(zoom);

    // Enable drag-to-reorder for IP rows using module function
    const dragBehavior = createDragReorderBehavior({
        d3,
        svg,
        ipOrder,
        ipPositions,
        onReorder: () => {
            // Invalidate cached full-domain bins so subsequent renders recompute with updated y positions
            try { fullDomainBinsCache = { version: -1, data: [], binSize: null, sorted: false }; } catch(_) {}
            // Force a lightweight re-render at current zoom domain (will trigger zoom handler logic)
            try { isHardResetInProgress = true; applyZoomDomain(xScale.domain(), 'program'); } catch(_) {}

            // Redraw flow arcs & ground truth overlays with new vertical positions
            try { drawSelectedFlowArcs(); } catch(_) {}
            try {
                if (showGroundTruth) {
                    const selectedIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')).map(cb => cb.value);
                    drawGroundTruthBoxes(selectedIPs);
                }
            } catch(_) {}
            try { updateZoomDurationLabel(); } catch(_) {}
        }
    });
    svg.selectAll('.node').call(dragBehavior).style('cursor', 'grab');

    let initialVisiblePackets = getVisiblePackets(packets, xScale);
    if (showTcpFlows && selectedFlowIds.size > 0 && tcpFlows.length > 0) {
        const selectedKeys = buildSelectedFlowKeySet();
        initialVisiblePackets = initialVisiblePackets.filter(packet => {
            if (!packet || !packet.src_ip || !packet.dst_ip) return false;
            const key = makeConnectionKey(packet.src_ip, packet.src_port || 0, packet.dst_ip, packet.dst_port || 0);
            return selectedKeys.has(key);
        });
    }

    const initialBinnedPackets = binPackets(initialVisiblePackets, {
        xScale,
        timeExtent,
        findIPPosition,
        ipPositions,
        pairs,
        binCount: getEffectiveBinCount(GLOBAL_BIN_COUNT, renderMode),
        useBinning,
        width
    });
    try {
        const counts = initialBinnedPackets.filter(d => d.binned && d.count > 0).map(d => d.count);
        const maxCount = counts.length > 0 ? Math.max(...counts) : 1;
        globalMaxBinCount = Math.max(1, maxCount);
    } catch (_) {
        globalMaxBinCount = 1;
    }
    let initialRScale = d3.scaleSqrt().domain([1, globalMaxBinCount]).range([RADIUS_MIN, RADIUS_MAX]);
    fullDomainBinsCache = { version: dataVersion, data: initialBinnedPackets, binSize: null, sorted: false };

    initialBinnedPackets.sort((a, b) => {
        const flagA = a.flagType || classifyFlags(a.flags);
        const flagB = b.flagType || classifyFlags(b.flags);
        const countA = flagCounts[flagA] || 0;
        const countB = flagCounts[flagB] || 0;
        if (countA !== countB) return countB - countA;
        return a.timestamp - b.timestamp;
    });
    fullDomainBinsCache.sorted = true;

    renderMarksForLayerLocal(fullDomainLayer, initialBinnedPackets, initialRScale);

    if (fullDomainLayer) fullDomainLayer.style("display", null);
    if (dynamicLayer) dynamicLayer.style("display", "none");

    updateTcpFlowPacketsGlobal();
    
    // Sync worker with rendered data after initial rendering
    try {
        setTimeout(() => syncWorkerWithRenderedData(), 100); // Small delay to ensure DOM is updated
    } catch (err) {
        console.error('Failed to sync worker after initial render:', err);
    }
    
    // Draw size + flag legends into bottom overlay (fixed position)
    try { drawSizeLegend(bottomOverlayRoot, width, bottomOverlayHeight); } catch (_) {}
    try { drawFlagLegend(); } catch (_) {}

    const selectedIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked'))
        .map(cb => cb.value);
    drawGroundTruthBoxes(selectedIPs);
    drawSelectedFlowArcs();
    // Sidebar flag stats suppressed; show compact legend in bottom overlay
    try { drawFlagLegend(); } catch (_) {}

    // Keep overlay sized to current chart width
    try {
        bottomOverlayWidth = Math.max(0, width + chartMarginLeft + chartMarginRight);
        d3.select('#chart-bottom-overlay-svg')
            .attr('width', bottomOverlayWidth)
            .attr('height', bottomOverlayHeight);
        if (bottomOverlayRoot) bottomOverlayRoot.attr('transform', `translate(${chartMarginLeft},0)`);
        if (bottomOverlayAxisGroup) bottomOverlayAxisGroup.call(d3.axisBottom(xScale).tickFormat(d => {
            const timestampInt = Math.floor(d);
            const date = new Date(timestampInt / 1000);
            return date.toISOString().split('T')[1].split('.')[0];
        }));
    } catch(_) {}
}

// Make resize handler available globally for testing and debugging
window.setupWindowResizeHandler = setupWindowResizeHandler;

// Test function to manually trigger resize (for debugging)
window.testResize = function() {
    console.log('Testing manual resize...');
    const event = new Event('resize');
    window.dispatchEvent(event);
};

// Cleanup function to remove event listeners and clear state
function cleanup() {
    console.log('Cleaning up bar visualization...');
    
    // Clear timeouts and intervals
    if (typeof resizeTimeout !== 'undefined') {
        clearTimeout(resizeTimeout);
    }
    
    // Remove event listeners
    const dataFileInput = document.getElementById('dataFile');
    if (dataFileInput) {
        dataFileInput.removeEventListener('change', handleFileLoad);
    }
    
    // Clear chart content
    const chartContainer = document.getElementById('chart');
    if (chartContainer) {
        chartContainer.innerHTML = '';
    }
    
    // Clear overview
    const overviewContainer = document.getElementById('overview-chart');
    if (overviewContainer) {
        overviewContainer.innerHTML = '';
    }
    
    // Clear bottom overlay
    const bottomOverlay = document.getElementById('chart-bottom-overlay-svg');
    if (bottomOverlay) {
        bottomOverlay.innerHTML = '';
    }
    
    // Terminate worker if exists
    if (workerManager) {
        workerManager.terminate();
        workerManager = null;
    }
    
    // Reset global state
    fullData = [];
    filteredData = [];
    currentFlows = [];
    selectedFlowIds.clear();
    
    // Clear SVG references
    svg = null;
    mainGroup = null;
}

// Initialize the module
function init() {
    console.log('Initializing bar visualization...');
    
    // Add file input listener
    const dataFileInput = document.getElementById('dataFile');
    if (dataFileInput) {
        dataFileInput.addEventListener('change', handleFileLoad);
    }
    
    // Add folder data listener
    document.addEventListener('folderDataLoaded', handleFolderDataLoaded);
    
    // Initialize the visualization
    initializeBarVisualization();
    
    // Load ground truth data in the background
    // Load ground truth data asynchronously
    loadGroundTruthData().then(data => {
        groundTruthData = data;
        
        // Update ground truth stats display
        const container = document.getElementById('groundTruthStats');
        if (data.length > 0) {
            container.innerHTML = `Loaded ${data.length} ground truth events<br>Select 2+ IPs to view matching events`;
            container.style.color = '#27ae60';
        } else {
            container.innerHTML = 'Ground truth data not loaded';
            container.style.color = '#e74c3c';
        }
    });
}

// Handle folder data loaded event
function handleFolderDataLoaded(event) {
    console.log('Folder data loaded event received:', event.detail);
    
    try {
        const { packets, flowsIndex, ipStats, flagStats, manifest } = event.detail;
        
        if (!packets || packets.length === 0) {
            console.error('No packets in folder data');
            alert('Error: No packets found in folder data');
            return;
        }
        
        console.log(`Processing ${packets.length} packets from folder...`);
        
        // Set data
        fullData = packets;
        filteredData = [];
        
        // Convert flows index to flow objects (simplified format for now)
        tcpFlows = flowsIndex.map(flowSummary => ({
            id: flowSummary.id,
            key: flowSummary.key,
            initiator: flowSummary.initiator,
            responder: flowSummary.responder,
            initiatorPort: flowSummary.initiatorPort,
            responderPort: flowSummary.responderPort,
            state: flowSummary.state,
            closeType: flowSummary.closeType,
            startTime: flowSummary.startTime,
            endTime: flowSummary.endTime,
            totalPackets: flowSummary.totalPackets,
            totalBytes: flowSummary.totalBytes,
            establishmentComplete: flowSummary.establishmentComplete,
            dataTransferStarted: flowSummary.dataTransferStarted,
            closingStarted: flowSummary.closingStarted,
            invalidReason: flowSummary.invalidReason,
            ongoing: flowSummary.ongoing,
            phases: {
                establishment: Array(flowSummary.establishment_packets || 0).fill({}),
                dataTransfer: Array(flowSummary.data_transfer_packets || 0).fill({}),
                closing: Array(flowSummary.closing_packets || 0).fill({})
            }
        }));
        
        console.log(`Loaded ${tcpFlows.length} flows from folder`);
        
        // Initialize currentFlows as empty - will be populated when IPs are selected
        currentFlows = [];
        selectedFlowIds.clear();
        
        // Update TCP flow stats to show initial message
        updateTcpFlowStats(currentFlows);
        
        // Extract unique IPs from packet data
        const uniqueIPs = Array.from(new Set(fullData.flatMap(p => [p.src_ip, p.dst_ip]))).filter(Boolean);
        createIPCheckboxes(uniqueIPs);
        
        // Initialize web worker for packet filtering
        try {
            if (!workerManager) {
                initializeWorkerManager();
            }
            // Will sync with rendered data after visualization is built
        } catch (err) {
            console.error('Worker init failed', err);
        }
        
        // Show message asking user to select IPs
        document.getElementById('loadingMessage').textContent = 'Please select 2 or more IP addresses to view connections.';
        document.getElementById('loadingMessage').style.display = 'block';
        
        console.log(`Folder data ready with ${packets.length} packets and ${uniqueIPs.length} unique IPs`);
        
        // Hide progress
        try { sbHideCsvProgress(); } catch (_) {}
        
    } catch (err) {
        console.error('Error handling folder data:', err);
        alert(`Error processing folder data: ${err.message}`);
        try { sbHideCsvProgress(); } catch (_) {}
    }
}

// Export functions for dynamic loading
export { init, cleanup };

