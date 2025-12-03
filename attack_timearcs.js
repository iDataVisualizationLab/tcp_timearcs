import { MARGIN, DEFAULT_WIDTH, DEFAULT_HEIGHT, INNER_HEIGHT, PROTOCOL_COLORS, DEFAULT_COLOR, NEUTRAL_GREY, LENS_DEFAULTS, FISHEYE_DEFAULTS } from './src/config/constants.js';
import { toNumber, sanitizeId, canonicalizeName, showTooltip, hideTooltip, setStatus } from './src/utils/helpers.js';
import { decodeIp, decodeAttack, decodeAttackGroup, lookupAttackColor, lookupAttackGroupColor } from './src/mappings/decoders.js';
import { buildRelationships, computeConnectivityFromRelationships, computeLinks, findConnectedComponents } from './src/data/aggregation.js';
import { linkArc, gradientIdForLink } from './src/rendering/arcPath.js';
import { buildLegend as createLegend, updateLegendVisualState as updateLegendUI, isolateAttack as isolateLegendAttack } from './src/ui/legend.js';
import { parseCSVStream, parseCSVLine } from './src/data/csvParser.js';
import { detectTimestampUnit, createToDateConverter, createTimeScale, createIpScale, createWidthScale, calculateMaxArcRadius } from './src/scales/scaleFactory.js';
import { createForceSimulation, runUntilConverged, createComponentSeparationForce, createWeakComponentSeparationForce, createComponentCohesionForce, createHubCenteringForce, createComponentYForce, initializeNodePositions, calculateComponentCenters, findComponentHubIps, calculateIpDegrees } from './src/layout/forceSimulation.js';
import { applyLens1D, createLensXScale, createFisheyeScale, createHorizontalFisheyeScale, fisheyeDistort } from './src/scales/distortion.js';
import { computeIpSpans, createSpanData, renderRowLines, renderIpLabels, createLabelHoverHandler, createLabelMoveHandler, createLabelLeaveHandler, attachLabelHoverHandlers } from './src/rendering/rows.js';
import { createArcHoverHandler, createArcMoveHandler, createArcLeaveHandler, attachArcHandlers } from './src/rendering/arcInteractions.js';
import { loadAllMappings } from './src/mappings/loaders.js';

// Network TimeArcs visualization
// Input CSV schema: timestamp,length,src_ip,dst_ip,protocol,count
// - timestamp: integer absolute minutes. If very large (>1e6), treated as minutes since Unix epoch.
//   Otherwise treated as relative minutes and displayed as t=.. labels.

(function () {
  const fileInput = document.getElementById('fileInput');
  const ipMapInput = document.getElementById('ipMapInput');
  const eventMapInput = document.getElementById('eventMapInput');
  const statusEl = document.getElementById('status');
  const svg = d3.select('#chart');
  const container = document.getElementById('chart-container');
  const legendEl = document.getElementById('legend');
  const tooltip = document.getElementById('tooltip');
  const labelModeRadios = document.querySelectorAll('input[name="labelMode"]');
  const lensingMulSlider = document.getElementById('lensingMulSlider');
  const lensingMulValue = document.getElementById('lensingMulValue');
  const lensingToggleBtn = document.getElementById('lensingToggle');

  // User-selected labeling mode: 'attack' or 'attack_group'
  let labelMode = 'attack';
  labelModeRadios.forEach(r => r.addEventListener('change', () => {
    const sel = Array.from(labelModeRadios).find(r=>r.checked);
    labelMode = sel ? sel.value : 'attack';
    if (lastRawCsvRows) {
      render(rebuildDataFromRawRows(lastRawCsvRows));
    }
  }));

  // Handle lens magnification slider
  if (lensingMulSlider && lensingMulValue) {
    lensingMulSlider.addEventListener('input', (e) => {
      lensingMul = parseFloat(e.target.value);
      fisheyeDistortion = lensingMul; // Sync fisheye distortion with slider
      lensingMulValue.textContent = `${lensingMul}x`;

      // Update vertical fisheye scale distortion if it exists
      if (fisheyeScale && typeof fisheyeScale.distortion === 'function') {
        fisheyeScale.distortion(fisheyeDistortion);
      }

      // Update horizontal fisheye scale distortion if it exists
      if (horizontalFisheyeScale && typeof horizontalFisheyeScale.distortion === 'function') {
        horizontalFisheyeScale.distortion(fisheyeDistortion);
      }

      // If lensing is active, update visualization immediately
      if (isLensing && updateLensVisualizationFn) {
        updateLensVisualizationFn();
      }
    });
  }

  // Handle lens toggle button
  function updateLensingButtonState() {
    if (!lensingToggleBtn) return;
    if (fisheyeEnabled) {
      lensingToggleBtn.style.background = '#0d6efd';
      lensingToggleBtn.style.color = '#fff';
      lensingToggleBtn.style.borderColor = '#0d6efd';
    } else {
      lensingToggleBtn.style.background = '#fff';
      lensingToggleBtn.style.color = '#000';
      lensingToggleBtn.style.borderColor = '#dee2e6';
    }
  }

  // Store reference to resetFisheye function so it can be called from button handler
  let resetFisheyeFn = null;

  if (lensingToggleBtn) {
    lensingToggleBtn.addEventListener('click', () => {
      fisheyeEnabled = !fisheyeEnabled;
      console.log('Fisheye toggled:', fisheyeEnabled);

      // Reset to original positions when disabled
      if (!fisheyeEnabled && resetFisheyeFn) {
        resetFisheyeFn();
      }

      // Update cursor on SVG
      const svgEl = d3.select('#chart');
      svgEl.style('cursor', fisheyeEnabled ? 'crosshair' : 'default');

      updateLensingButtonState();
    });
  }

  // Handle keyboard shortcut: Shift + L to toggle lensing
  document.addEventListener('keydown', (e) => {
    // Check for Shift + L (case insensitive)
    if (e.shiftKey && (e.key === 'L' || e.key === 'l')) {
      e.preventDefault(); // Prevent default browser behavior
      fisheyeEnabled = !fisheyeEnabled;
      console.log('Fisheye toggled (keyboard):', fisheyeEnabled);

      // Reset to original positions when disabled
      if (!fisheyeEnabled && resetFisheyeFn) {
        resetFisheyeFn();
      }

      // Update cursor on SVG
      const svgEl = d3.select('#chart');
      svgEl.style('cursor', fisheyeEnabled ? 'crosshair' : 'default');

      updateLensingButtonState();
    }
  });

  let width = DEFAULT_WIDTH; // updated on render
  let height = DEFAULT_HEIGHT; // updated on render

  // Lens magnification state (horizontal time only, matching main.js)
  let isLensing = false;
  let lensingMul = 5; // Magnification factor (5x)
  let lensCenter = 0; // Focused timestamp position (horizontal)
  let XGAP_BASE = null; // Base X-scale gap for lens calculations
  let labelsCompressedMode = false; // When true, hide baseline labels and only show magnified ones

  // Fisheye state (vertical row distortion)
  let fisheyeEnabled = false;
  let fisheyeScale = null;
  let fisheyeDistortion = 5; // Initial distortion amount (linked to lensingMul slider)
  let originalRowPositions = new Map(); // Store original Y positions for each IP

  // Horizontal fisheye state (timeline distortion)
  let horizontalFisheyeScale = null;
  let currentMouseX = null; // Current mouse X position for horizontal fisheye

  // IP map state (id -> dotted string)
  let ipIdToAddr = null; // Map<number, string>
  let ipMapLoaded = false;

  // Attack/event mapping: id -> name, and color mapping: name -> color
  let attackIdToName = null; // Map<number, string>
  let colorByAttack = null; // Map<string, string> by canonicalized name
  let rawColorByAttack = null; // original keys
  // Attack group mapping/color
  let attackGroupIdToName = null; // Map<number,string>
  let colorByAttackGroup = null; // canonical map
  let rawColorByAttackGroup = null;

  // Track visible attacks for legend filtering
  let visibleAttacks = new Set(); // Set of attack names that are currently visible
  let currentArcPaths = null; // Reference to arc paths selection for visibility updates
  let currentLabelMode = 'attack'; // Track current label mode for filtering
  
  // Reference to updateLensVisualization function so slider can trigger updates
  let updateLensVisualizationFn = null;
  // Reference to toggleLensing function so button can trigger it
  let toggleLensingFn = null;

  // Initialize mappings, then try a default CSV load
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
    // After maps are ready (or failed gracefully), try default CSV
    tryLoadDefaultCsv();
  })();

  // Stream-parse a CSV file incrementally to avoid loading entire file into memory
  // Pushes transformed rows directly into combinedData, returns {totalRows, validRows}
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

  // Transform raw CSV rows to processed data
  function transformRows(rows, startIdx = 0) {
    return rows.map((d, i) => {
      const attackName = _decodeAttack(d.attack);
      const attackGroupName = _decodeAttackGroup(d.attack_group, d.attack);
      const srcIp = _decodeIp(d.src_ip);
      const dstIp = _decodeIp(d.dst_ip);
      return {
        idx: startIdx + i,
        timestamp: toNumber(d.timestamp),
        length: toNumber(d.length),
        src_ip: srcIp,
        dst_ip: dstIp,
        protocol: (d.protocol || '').toUpperCase() || 'OTHER',
        count: toNumber(d.count) || 1,
        attack: attackName,
        attack_group: attackGroupName,
      };
    }).filter(d => {
      // Filter out records with invalid data
      const hasValidTimestamp = isFinite(d.timestamp);
      const hasValidSrcIp = d.src_ip && d.src_ip !== 'N/A' && !d.src_ip.startsWith('IP_');
      const hasValidDstIp = d.dst_ip && d.dst_ip !== 'N/A' && !d.dst_ip.startsWith('IP_');
      
      // Debug logging for filtered records
      if (!hasValidSrcIp || !hasValidDstIp) {
        console.log('Filtering out record:', { 
          src_ip: d.src_ip, 
          dst_ip: d.dst_ip, 
          hasValidSrcIp, 
          hasValidDstIp,
          ipMapLoaded,
          ipMapSize: ipIdToAddr ? ipIdToAddr.size : 0
        });
      }
      
      return hasValidTimestamp && hasValidSrcIp && hasValidDstIp;
    });
  }

  // Handle CSV upload - supports multiple files
  fileInput?.addEventListener('change', async (e) => {
    const files = Array.from(e.target.files || []);
    if (files.length === 0) return;
    
    // Show loading status
    if (files.length === 1) {
      setStatus(statusEl,`Loading ${files[0].name} …`);
    } else {
      setStatus(statusEl,`Loading ${files.length} files…`);
    }
    
    try {
      console.log('Processing CSV files with IP map status:', { 
        fileCount: files.length,
        ipMapLoaded, 
        ipMapSize: ipIdToAddr ? ipIdToAddr.size : 0 
      });
      
      // Warn if IP map is not loaded
      if (!ipMapLoaded || !ipIdToAddr || ipIdToAddr.size === 0) {
        console.warn('IP map not loaded or empty. Some IP IDs may not be mapped correctly.');
        setStatus(statusEl,'Warning: IP map not loaded. Some data may be filtered out.');
      }
      
      // Process files sequentially to bound memory; stream-parse to avoid full-file buffers
      const combinedData = [];
      const fileStats = [];
      const errors = [];
      for (const file of files) {
        try {
          const res = await processCsvFile(file, combinedData, { hasHeader: true, delimiter: ',' });
          const filteredRows = res.totalRows - res.validRows;
          fileStats.push({ fileName: file.name, totalRows: res.totalRows, validRows: res.validRows, filteredRows });
        } catch (err) {
          errors.push({ fileName: file.name, error: err });
          console.error(`Failed to load ${file.name}:`, err);
        }
      }
      
      // Disable rebuild cache for huge datasets to avoid memory spikes
      lastRawCsvRows = null;

      if (combinedData.length === 0) {
        if (errors.length > 0) {
          setStatus(statusEl,`Failed to load files. ${errors.length} error(s) occurred.`);
        } else {
          setStatus(statusEl,'No valid rows found. Ensure CSV files have required columns and IP mappings are available.');
        }
        clearChart();
        return;
      }
      
      // Build status message with summary
      const successfulFiles = fileStats.length;
      const totalValidRows = combinedData.length;
      const totalFilteredRows = fileStats.reduce((sum, stat) => sum + stat.filteredRows, 0);
      
      let statusMsg = '';
      if (files.length === 1) {
        // Single file: show simple message
        if (totalFilteredRows > 0) {
          statusMsg = `Loaded ${totalValidRows} valid rows (${totalFilteredRows} rows filtered due to missing IP mappings)`;
        } else {
          statusMsg = `Loaded ${totalValidRows} records`;
        }
      } else {
        // Multiple files: show detailed summary
        const fileSummary = fileStats.map(stat => 
          `${stat.fileName} (${stat.validRows} valid${stat.filteredRows > 0 ? `, ${stat.filteredRows} filtered` : ''})`
        ).join('; ');
        
        statusMsg = `Loaded ${successfulFiles} file(s): ${fileSummary}. Total: ${totalValidRows} records`;
        
        if (errors.length > 0) {
          statusMsg += `. ${errors.length} file(s) failed to load.`;
        }
      }
      
      setStatus(statusEl,statusMsg);
      
      render(combinedData);
    } catch (err) {
      console.error(err);
      setStatus(statusEl,'Failed to read CSV file(s).');
      clearChart();
    }
  });


  // Allow user to upload a custom ip_map JSON (expected format: { "1.2.3.4": 123, ... } OR reverse { "123": "1.2.3.4" })
  ipMapInput?.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setStatus(statusEl,`Loading IP map ${file.name} …`);
    try {
      const text = await file.text();
      const obj = JSON.parse(text);
      const rev = new Map();
      const entries = Object.entries(obj);
      // Detect orientation: sample if keys look like IPs
      let ipKeyMode = 0, numericKeyMode = 0;
      for (const [k,v] of entries.slice(0,20)) {
        if (/^\d+\.\d+\.\d+\.\d+$/.test(k) && Number.isFinite(Number(v))) ipKeyMode++;
        if (!isNaN(+k) && typeof v === 'string' && /^\d+\.\d+\.\d+\.\d+$/.test(v)) numericKeyMode++;
      }
      if (ipKeyMode >= numericKeyMode) {
        // ipString -> idNumber
        for (const [ip,id] of entries) {
          const num = Number(id);
            if (Number.isFinite(num) && /^\d+\.\d+\.\d+\.\d+$/.test(ip)) rev.set(num, ip);
        }
      } else {
        // idNumber -> ipString
        for (const [idStr, ip] of entries) {
          const num = Number(idStr);
          if (Number.isFinite(num) && /^\d+\.\d+\.\d+\.\d+$/.test(ip)) rev.set(num, ip);
        }
      }
      ipIdToAddr = rev;
      ipMapLoaded = true;
      console.log(`Custom IP map loaded with ${rev.size} entries`);
      console.log('Sample entries:', Array.from(rev.entries()).slice(0, 5));
      setStatus(statusEl,`Custom IP map loaded (${rev.size} entries). Re-rendering…`);
      if (lastRawCsvRows) {
        // rebuild to decode IP ids again
        render(rebuildDataFromRawRows(lastRawCsvRows));
      }
    } catch (err) {
      console.error(err);
      setStatus(statusEl,'Failed to parse IP map JSON.');
    }
  });

  // Allow user to upload a custom event_type_mapping JSON (expected format: { "attack_name": 123, ... } OR reverse { "123": "attack_name" })
  eventMapInput?.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setStatus(statusEl,`Loading event type map ${file.name} …`);
    try {
      const text = await file.text();
      const obj = JSON.parse(text);
      const rev = new Map();
      const entries = Object.entries(obj);
      
      // Detect orientation: sample if keys look like numbers (IDs) or strings (names)
      let nameKeyMode = 0, idKeyMode = 0;
      for (const [k, v] of entries.slice(0, 20)) {
        if (typeof k === 'string' && !isNaN(+v) && Number.isFinite(Number(v))) nameKeyMode++;
        if (!isNaN(+k) && typeof v === 'string') idKeyMode++;
      }
      
      if (nameKeyMode >= idKeyMode) {
        // name -> id format: { "attack_name": 123 }
        for (const [name, id] of entries) {
          const num = Number(id);
          if (Number.isFinite(num)) rev.set(num, name);
        }
      } else {
        // id -> name format: { "123": "attack_name" }
        for (const [idStr, name] of entries) {
          const num = Number(idStr);
          if (Number.isFinite(num) && typeof name === 'string') rev.set(num, name);
        }
      }
      
      attackIdToName = rev;
      console.log(`Custom event type map loaded with ${rev.size} entries`);
      console.log('Sample entries:', Array.from(rev.entries()).slice(0, 5));
      setStatus(statusEl,`Custom event type map loaded (${rev.size} entries). Re-rendering…`);
      if (lastRawCsvRows) {
        // rebuild to decode attack IDs again
        render(rebuildDataFromRawRows(lastRawCsvRows));
      }
    } catch (err) {
      console.error(err);
      setStatus(statusEl,'Failed to parse event type map JSON.');
    }
  });

  // Keep last raw CSV rows so we can rebuild when mappings change
  let lastRawCsvRows = null; // array of raw objects from csvParse

  function rebuildDataFromRawRows(rows){
    return rows.map((d, i) => {
      const attackName = _decodeAttack(d.attack);
      const attackGroupName = _decodeAttackGroup(d.attack_group, d.attack);
      return {
        idx: i,
        timestamp: toNumber(d.timestamp),
        length: toNumber(d.length),
        src_ip: _decodeIp(d.src_ip),
        dst_ip: _decodeIp(d.dst_ip),
        protocol: (d.protocol || '').toUpperCase() || 'OTHER',
        count: toNumber(d.count) || 1,
        attack: attackName,
        attack_group: attackGroupName,
      };
    }).filter(d => {
      // Filter out records with invalid data
      const hasValidTimestamp = isFinite(d.timestamp);
      const hasValidSrcIp = d.src_ip && d.src_ip !== 'N/A' && !d.src_ip.startsWith('IP_');
      const hasValidDstIp = d.dst_ip && d.dst_ip !== 'N/A' && !d.dst_ip.startsWith('IP_');
      return hasValidTimestamp && hasValidSrcIp && hasValidDstIp;
    });
  }

  async function tryLoadDefaultCsv() {
    const defaultPath = './set1_first90_minutes.csv';
    try {
      const res = await fetch(defaultPath, { cache: 'no-store' });
      if (!res.ok) return; // quietly exit if not found
      const text = await res.text();
      const rows = d3.csvParse((text || '').trim());
      lastRawCsvRows = rows; // cache raw rows
      const data = rows.map((d, i) => {
        const attackName = _decodeAttack(d.attack);
        const attackGroupName = _decodeAttackGroup(d.attack_group, d.attack);
        return {
          idx: i,
          timestamp: toNumber(d.timestamp),
          length: toNumber(d.length),
          src_ip: _decodeIp(d.src_ip),
          dst_ip: _decodeIp(d.dst_ip),
          protocol: (d.protocol || '').toUpperCase() || 'OTHER',
          count: toNumber(d.count) || 1,
          attack: attackName,
          attack_group: attackGroupName,
        };
      }).filter(d => {
        // Filter out records with invalid data
        const hasValidTimestamp = isFinite(d.timestamp);
        const hasValidSrcIp = d.src_ip && d.src_ip !== 'N/A' && !d.src_ip.startsWith('IP_');
        const hasValidDstIp = d.dst_ip && d.dst_ip !== 'N/A' && !d.dst_ip.startsWith('IP_');
        return hasValidTimestamp && hasValidSrcIp && hasValidDstIp;
      });

      if (!data.length) {
        setStatus(statusEl,'Default CSV loaded but no valid rows found. Check IP mappings.');
        return;
      }
      
      // Report how many rows were filtered out
      const totalRows = rows.length;
      const filteredRows = totalRows - data.length;
      if (filteredRows > 0) {
        setStatus(statusEl,`Loaded default: set1_first90_minutes.csv (${data.length} valid rows, ${filteredRows} filtered due to missing IP mappings)`);
      } else {
        setStatus(statusEl,`Loaded default: set1_first90_minutes.csv (${data.length} rows)`);
      }
      
      render(data);
    } catch (err) {
      // ignore if file isn't present; keep waiting for upload
    }
  }

  function clearChart() {
    svg.selectAll('*').remove();
    legendEl.innerHTML = '';
  }

  // Use d3 formatters consistently; we prefer UTC to match axis

  // Function to update arc visibility based on visible attacks
  function updateArcVisibility() {
    if (!currentArcPaths) return;
    
    currentArcPaths.style('display', d => {
      const attackName = (currentLabelMode === 'attack_group' ? d.attack_group : d.attack) || 'normal';
      return visibleAttacks.has(attackName) ? 'block' : 'none';
    });
  }

  function buildLegend(items, colorFn) {
    createLegend(legendEl, items, colorFn, visibleAttacks, {
      onToggle: (attackName) => {
        if (visibleAttacks.has(attackName)) {
          visibleAttacks.delete(attackName);
        } else {
          visibleAttacks.add(attackName);
        }
        updateArcVisibility();
        updateLegendUI(legendEl, visibleAttacks);
      },
      onIsolate: (attackName) => {
        isolateLegendAttack(attackName, visibleAttacks, legendEl);
        updateArcVisibility();
        updateLegendUI(legendEl, visibleAttacks);
      }
    });
  }

  function render(data) {
    // Determine timestamp handling
    const tsMin = d3.min(data, d => d.timestamp);
    const tsMax = d3.max(data, d => d.timestamp);
    // Heuristic timestamp unit detection by magnitude:
    // Detect timestamp unit and create converter using factory
    const timeInfo = detectTimestampUnit(tsMin, tsMax);
    const { unit, looksAbsolute, unitMs, unitSuffix, base } = timeInfo;
    const toDate = createToDateConverter(timeInfo);
    
    console.log('Timestamp debug:', {
      tsMin,
      tsMax,
      looksAbsolute,
      inferredUnit: unit,
      base,
      sampleTimestamps: data.slice(0, 5).map(d => d.timestamp)
    });

    // Aggregate links; then order IPs using the React component's approach:
    // primary-attack grouping, groups ordered by earliest time, nodes within group by force-simulated y
    const links = computeLinks(data); // aggregated per pair per minute
    
    // Collect ALL IPs from links (not just from nodes) to ensure scale includes all referenced IPs
    const allIpsFromLinks = new Set();
    links.forEach(l => {
      allIpsFromLinks.add(l.source);
      allIpsFromLinks.add(l.target);
    });
    
    const nodeData = computeNodesByAttackGrouping(links);
    const nodes = nodeData.nodes;
    const ips = nodes.map(n => n.name);
    const { simNodes, simLinks, yMap, components, ipToComponent } = nodeData;
    
    // Create simulation using the factory function
    const simulation = createForceSimulation(d3, simNodes, simLinks);
    simulation._components = components;
    simulation._ipToComponent = ipToComponent;
    
    // Ensure all IPs from links are included in the initial IP list
    // This prevents misalignment when arcs reference IPs not in the nodes list
    const allIps = Array.from(new Set([...ips, ...allIpsFromLinks]));
    
    console.log('Render debug:', {
      dataLength: data.length,
      linksLength: links.length,
      nodesLength: nodes.length,
      ipsLength: ips.length,
      allIpsLength: allIps.length,
      sampleIps: ips.slice(0, 5),
      sampleLinks: links.slice(0, 3)
    });
  // Determine which label dimension we use (attack vs group) for legend and coloring
  const activeLabelKey = labelMode === 'attack_group' ? 'attack_group' : 'attack';
    const attacks = Array.from(new Set(links.map(l => l[activeLabelKey] || 'normal'))).sort();
    
    // Always enable ALL attacks on each fresh render (e.g., new data loaded)
    // This ensures the legend starts fully enabled regardless of previous toggles
    visibleAttacks = new Set(attacks);
    currentLabelMode = labelMode;

    // Sizing based on fixed height (matching main.js: height = 780)
    // main.js uses: height = 780 - MARGIN.top - MARGIN.bottom = 780 (since MARGIN.top=0, MARGIN.bottom=5)
    // Match main.js: use fixed height instead of scaling with number of IPs
    // Fit width to container - like main.js: width accounts for MARGINs
    const availableWidth = container.clientWidth || 1200;
    const viewportWidth = Math.max(availableWidth, 800);
    // Calculate width accounting for MARGINs (like main.js: width = clientWidth - MARGIN.left - MARGIN.right)
    width = viewportWidth - MARGIN.left - MARGIN.right;
    height = MARGIN.top + INNER_HEIGHT + MARGIN.bottom;

    // Initial SVG size - will be updated after calculating actual arc extents
    svg.attr('width', width + MARGIN.left + MARGIN.right).attr('height', height);

    const xMinDate = toDate(tsMin);
    const xMaxDate = toDate(tsMax);
    
    console.log('X-scale debug:', {
      tsMin,
      tsMax,
      xMinDate,
      xMaxDate,
      xMinValid: isFinite(xMinDate.getTime()),
      xMaxValid: isFinite(xMaxDate.getTime())
    });
    
    // Timeline width is the available width after accounting for left MARGIN offset
    // Like main.js, we use the full width (after MARGINs) for the timeline
    const timelineWidth = width;
    
    console.log('Timeline fitting:', {
      containerWidth: container.clientWidth,
      viewportWidth,
      timelineWidth,
      MARGINLeft: MARGIN.left,
      MARGINRight: MARGIN.right
    });
    
    // X scale for timeline that fits in container
    // Calculate max arc radius to reserve space for arc curves
    const ipIndexMap = new Map(allIps.map((ip, idx) => [ip, idx]));
    let maxIpIndexDist = 0;
    links.forEach(l => {
      const srcIdx = ipIndexMap.get(l.source);
      const tgtIdx = ipIndexMap.get(l.target);
      if (srcIdx !== undefined && tgtIdx !== undefined) {
        const dist = Math.abs(srcIdx - tgtIdx);
        if (dist > maxIpIndexDist) maxIpIndexDist = dist;
      }
    });
    // Estimate final spacing after auto-fit (scalePoint with padding 0.5)
    const estimatedStep = allIps.length > 1 ? INNER_HEIGHT / allIps.length : INNER_HEIGHT;
    const maxArcRadius = (maxIpIndexDist * estimatedStep) / 2;

    const svgWidth = width + MARGIN.left + MARGIN.right;
    const xStart = MARGIN.left;
    const xEnd = svgWidth - MARGIN.right - maxArcRadius;

    const x = createTimeScale(d3, xMinDate, xMaxDate, xStart, xEnd);

    // Calculate base gap for lens calculations
    XGAP_BASE = timelineWidth / (tsMax - tsMin);

    // Initialize lens center to middle of data range
    if (lensCenter === 0 || lensCenter < tsMin || lensCenter > tsMax) {
      lensCenter = (tsMin + tsMax) / 2;
    }

    // Track the current xEnd value (will be updated after arc radius calculation)
    let currentXEnd = xEnd;

    // Lens-aware x scale function using imported factory
    const xScaleLens = createLensXScale({
      xScale: x,
      tsMin,
      tsMax,
      xStart,
      xEnd: xEnd, // Use initial xEnd, will be updated via getter
      toDate,
      getIsLensing: () => isLensing,
      getLensCenter: () => lensCenter,
      getLensingMul: () => lensingMul,
      getHorizontalFisheyeScale: () => horizontalFisheyeScale,
      getFisheyeEnabled: () => fisheyeEnabled,
      getXEnd: () => currentXEnd // Dynamic getter for updated xEnd
    });

    // Use allIps for the y scale to ensure all IPs referenced in arcs are included
    const y = createIpScale(d3, allIps, MARGIN.top, MARGIN.top + INNER_HEIGHT, 0.5);
    
    console.log('Y-scale debug:', {
      domain: allIps,
      domainLength: allIps.length,
      sampleYValues: allIps.slice(0, 5).map(ip => ({ ip, y: y(ip) }))
    });

    // Store evenly distributed positions after auto-fit animation
    let evenlyDistributedYPositions = null;
    
    // Y scale function (matching main.js: no vertical lensing, just return y position)
    function yScaleLens(ip) {
      // If we have evenly distributed positions (after animation), use those
      if (evenlyDistributedYPositions && evenlyDistributedYPositions.has(ip)) {
        return evenlyDistributedYPositions.get(ip);
      }
      // Otherwise use the base y scale (matching main.js: no vertical lensing)
      return y(ip);
    }

    // Width scale by aggregated link count (log scale like the React version)
    const minLinkCount = d3.min(links, d => Math.max(1, d.count)) || 1;
    const maxLinkCount = d3.max(links, d => Math.max(1, d.count)) || 1;
    const widthScale = createWidthScale(d3, minLinkCount, maxLinkCount);
    // Keep lengthScale (unused) for completeness
    const maxLen = d3.max(data, d => d.length || 0) || 0;
    const lengthScale = d3.scaleLinear().domain([0, Math.max(1, maxLen)]).range([0.6, 2.2]);

    const colorForAttack = (name) => {
      if (labelMode === 'attack_group') return _lookupAttackGroupColor(name) || _lookupAttackColor(name) || DEFAULT_COLOR;
      return _lookupAttackColor(name) || _lookupAttackGroupColor(name) || DEFAULT_COLOR;
    };

    // Clear
    svg.selectAll('*').remove();

    // Axes — render to sticky top SVG
    const axisScale = d3.scaleTime()
      .domain([xMinDate, xMaxDate])
      .range([0, xEnd - xStart]);
    
    const utcTick = d3.utcFormat('%Y-%m-%d %H:%M');
    const xAxis = d3.axisTop(axisScale).ticks(looksAbsolute ? 7 : 7).tickFormat(d => {
      if (looksAbsolute) return utcTick(d);
      const relUnits = Math.round((d.getTime()) / unitMs);
      return `t=${relUnits}${unitSuffix}`;
    });
    
    // Create axis SVG that matches the viewport width
    const axisSvg = d3.select('#axis-top')
      .attr('width', width + MARGIN.left + MARGIN.right)
      .attr('height', 36);
    axisSvg.selectAll('*').remove();
    
    // Create axis group
    const axisGroup = axisSvg.append('g')
      .attr('transform', `translate(${xStart}, 28)`)
      .call(xAxis);

    // Utility for safe gradient IDs per link
    // Use original IP strings (sourceIp/targetIp) for gradient IDs
    const gradIdForLink = (d) => gradientIdForLink(d, sanitizeId);

    // Row labels and span lines: draw per-IP line only from first to last activity
    const rows = svg.append('g');
    // compute first/last minute per IP based on aggregated links
    const ipSpans = computeIpSpans(links);
    // Use allIps to ensure all IPs have row lines, matching the labels and arcs
    const spanData = createSpanData(allIps, ipSpans);

    renderRowLines(rows, spanData, MARGIN.left, yScaleLens);

    // Build legend (attack types)
    buildLegend(attacks, colorForAttack);

    // Create node objects for each IP with x/y properties (matching main.js structure)
    // This allows links to reference node objects with x/y coordinates
    const ipToNode = new Map();
    allIps.forEach(ip => {
      const node = { name: ip, x: 0, y: 0 };
      ipToNode.set(ip, node);
    });

    // Transform links to have source/target as node objects (matching main.js)
    // Keep original IP strings for gradient/display purposes
    const linksWithNodes = links.map(link => {
      const sourceNode = ipToNode.get(link.source);
      const targetNode = ipToNode.get(link.target);
      if (!sourceNode || !targetNode) {
        console.warn('Missing node for link:', link);
        return null;
      }
      return {
        ...link,
        // Preserve original IP strings for gradient IDs and other uses
        sourceIp: link.source,
        targetIp: link.target,
        // Store node objects separately
        sourceNode: sourceNode,
        targetNode: targetNode,
        // For linkArc function, use source/target as node objects (will be set per-arc)
        source: sourceNode,
        target: targetNode
      };
    }).filter(l => l !== null);

    // Function to update node positions from scales (called during render/update)
    // Match main.js: nodes maintain their x/y positions and xConnected
    function updateNodePositions() {
      // X position for all labels: first time tick in the timeline
      const firstTimeTickX = xScaleLens(tsMin);
      allIps.forEach(ip => {
        const node = ipToNode.get(ip);
        if (node) {
          // Y position comes from the scale (matching main.js n.y)
          node.y = yScaleLens(ip);
          // X position: first time tick in the timeline (keep current y position logic)
          node.xConnected = firstTimeTickX;
        }
      });
    }
    
    // Initialize node positions (matching main.js where nodes have n.y and xConnected)
    updateNodePositions();

    // Create labels for all IPs to ensure alignment with arcs
    // Match main.js: labels positioned at first arc time (xConnected) initially
    // Must be created after nodes are set up and positions are calculated
    const ipLabels = renderIpLabels(rows, allIps, ipToNode, MARGIN.left, yScaleLens);

    // Create per-link gradients from grey (source) to attack color (destination)
    const defs = svg.append('defs');

    const gradients = defs.selectAll('linearGradient')
      .data(linksWithNodes)
      .join('linearGradient')
      .attr('id', d => gradIdForLink(d))
      .attr('gradientUnits', 'userSpaceOnUse')
      .attr('x1', d => xScaleLens(d.minute))
      .attr('x2', d => xScaleLens(d.minute))
      .attr('y1', d => yScaleLens(d.sourceNode.name))
      .attr('y2', d => yScaleLens(d.targetNode.name));

    gradients.each(function(d) {
      const g = d3.select(this);
      // Reset stops to avoid duplicates on re-renders
      g.selectAll('stop').remove();
      g.append('stop')
        .attr('offset', '0%')
        .attr('stop-color', NEUTRAL_GREY);
      g.append('stop')
        .attr('offset', '100%')
        .attr('stop-color', colorForAttack((labelMode==='attack_group'? d.attack_group : d.attack) || 'normal'));
    });

    // Draw arcs using linkArc function (matching main.js)
    const arcs = svg.append('g');
    const arcPaths = arcs.selectAll('path')
      .data(linksWithNodes)
      .join('path')
      .attr('class', 'arc')
      .attr('data-attack', d => (labelMode === 'attack_group' ? d.attack_group : d.attack) || 'normal')
      .attr('stroke', d => `url(#${gradIdForLink(d)})`)
      .attr('stroke-width', d => widthScale(Math.max(1, d.count)))
      .attr('d', d => {
        // Update node positions for this link (matching main.js pattern)
        // In main.js, nodes have x/y from force layout; here we compute from scales
        const xp = xScaleLens(d.minute);
        const y1 = yScaleLens(d.sourceNode.name);
        const y2 = yScaleLens(d.targetNode.name);

        // Validate coordinates
        if (xp === undefined || !isFinite(xp) || y1 === undefined || !isFinite(y1) || y2 === undefined || !isFinite(y2)) {
          console.warn('Invalid coordinates for arc:', {
            minute: d.minute,
            source: d.sourceNode.name,
            target: d.targetNode.name,
            xp, y1, y2
          });
          return 'M0,0 L0,0';
        }

        // Set node positions for linkArc function (matching main.js)
        // All arcs at the same time share the same x position
        d.source.x = xp;
        d.source.y = y1;
        d.target.x = xp;
        d.target.y = y2;

        return linkArc(d);
      });

    // Create arc interaction handlers using factory functions
    const arcHoverHandler = createArcHoverHandler({
      arcPaths,
      svg,
      ipToNode,
      widthScale,
      xScaleLens: (m) => xScaleLens(m),
      yScaleLens: (ip) => yScaleLens(ip),
      colorForAttack,
      showTooltip: (evt, html) => showTooltip(tooltip, evt, html),
      getLabelMode: () => labelMode,
      toDate,
      timeFormatter: utcTick,
      looksAbsolute,
      unitSuffix,
      base,
      getLabelsCompressedMode: () => labelsCompressedMode,
      marginLeft: MARGIN.left
    });

    const arcMoveHandler = createArcMoveHandler({ tooltip });

    const arcLeaveHandler = createArcLeaveHandler({
      arcPaths,
      svg,
      ipToNode,
      widthScale,
      hideTooltip: () => hideTooltip(tooltip),
      yScaleLens: (ip) => yScaleLens(ip),
      getLabelsCompressedMode: () => labelsCompressedMode,
      marginLeft: MARGIN.left
    });

    attachArcHandlers(arcPaths, arcHoverHandler, arcMoveHandler, arcLeaveHandler);
    
    // Store arcPaths reference for legend filtering (after all handlers are attached)
    currentArcPaths = arcPaths;
    
    // Apply initial visibility based on visibleAttacks
    updateArcVisibility();

    // Add hover handlers to IP labels to highlight connected arcs
    const labelHoverHandler = createLabelHoverHandler({
      linksWithNodes,
      arcPaths,
      svg,
      widthScale,
      showTooltip,
      tooltip
    });
    const labelMoveHandler = createLabelMoveHandler(tooltip);
    const labelLeaveHandler = createLabelLeaveHandler({
      arcPaths,
      svg,
      widthScale,
      hideTooltip,
      tooltip
    });
    attachLabelHoverHandlers(ipLabels, labelHoverHandler, labelMoveHandler, labelLeaveHandler);

    // Phase 1: Run force simulation for natural clustering with component separation
    setStatus(statusEl,'Stabilizing network layout...');
    
    // Run simulation to completion immediately (not visually)
    const centerX = (MARGIN.left + width - MARGIN.right) / 2;
    
    // Calculate degree (number of connections) for each IP from links using imported function
    const ipDegree = calculateIpDegrees(linksWithNodes);
    
    // Find hub IPs using imported function
    const componentHubIps = findComponentHubIps(components, ipDegree);
    componentHubIps.forEach((hubIp, compIdx) => {
      console.log(`Component ${compIdx} hub IP: ${hubIp} (degree: ${ipDegree.get(hubIp) || 0})`);
    });

    // Initialize nodes based on component membership for better separation
    if (components.length > 1) {
      console.log(`Applying force layout separation for ${components.length} components`);
      
      // Calculate component centers using imported function
      const componentSpacing = INNER_HEIGHT / components.length;
      
      // Log component sizes for debugging
      components.forEach((comp, idx) => {
        console.log(`Component ${idx}: ${comp.length} nodes`);
      });
      
      // Calculate target Y positions for each component center
      const componentCenters = calculateComponentCenters(components, MARGIN.top, INNER_HEIGHT);
      
      // Initialize node positions using imported function
      initializeNodePositions(simNodes, ipToComponent, componentCenters, centerX, ipDegree, componentSpacing);
      
      // Stage 1: Strong component separation - push components apart
      // Use the Y force from the imported function
      simulation.force('y', createComponentYForce(d3, ipToComponent, componentCenters, MARGIN.top + INNER_HEIGHT / 2));
      
      // Use imported force functions
      const componentSeparationForce = createComponentSeparationForce(ipToComponent, simNodes);
      const componentCohesionForce = createComponentCohesionForce(ipToComponent, simNodes);
      const hubCenteringForce = createHubCenteringForce(componentHubIps, componentCenters, simNodes);
      
      // Register the custom forces with the simulation
      simulation.force('componentSeparation', componentSeparationForce);
      simulation.force('componentCohesion', componentCohesionForce);
      simulation.force('hubCentering', hubCenteringForce);

      // Stage 1: Run simulation with strong component separation
      simulation.alpha(0.3).restart();
      runUntilConverged(simulation, 300, 0.001);
      
      // Stage 2: Reduce component forces and allow internal optimization
      simulation.force('y').strength(0.4); // Reduce Y force strength
      simulation.force('componentSeparation', createWeakComponentSeparationForce(ipToComponent, simNodes));
      
      // Continue simulation for internal optimization
      simulation.alpha(0.15).restart();
      runUntilConverged(simulation, 200, 0.0005);
    } else {
      // Single component: use original positioning
      const componentCenter = (MARGIN.top + INNER_HEIGHT) / 2;
      
      // Find hub IP for single component using the already computed componentHubIps
      const hubIp = componentHubIps.get(0) || null;
      if (hubIp) {
        console.log(`Single component hub IP: ${hubIp} (degree: ${ipDegree.get(hubIp) || 0})`);
      }
      
      // Sort nodes deterministically by degree (descending), then by IP string
      const sortedNodes = [...simNodes].sort((a, b) => {
        const degreeA = ipDegree.get(a.id) || 0;
        const degreeB = ipDegree.get(b.id) || 0;
        if (degreeB !== degreeA) return degreeB - degreeA; // Higher degree first
        return a.id.localeCompare(b.id); // Then by IP string for consistency
      });
      
      // Initialize positions deterministically: distribute evenly with hub at center
      sortedNodes.forEach((n, idx) => {
        n.x = centerX;
        if (sortedNodes.length === 1) {
          n.y = componentCenter;
        } else {
          // Distribute nodes evenly around center, with hub (first) at center
          const spread = Math.min(INNER_HEIGHT * 0.3, 50);
          const step = spread / (sortedNodes.length - 1);
          const offset = (idx - (sortedNodes.length - 1) / 2) * step;
          n.y = componentCenter + offset;
        }
        n.vx = 0;
        n.vy = 0;
      });
      
      // Add hub centering force for single component
      if (hubIp) {
        const singleComponentCenters = new Map([[0, componentCenter]]);
        const singleHubIps = new Map([[0, hubIp]]);
        simulation.force('hubCentering', createHubCenteringForce(singleHubIps, singleComponentCenters, simNodes, { hubStrength: 1.0 }));
      }
      
      // Run simulation for single component
      simulation.alpha(0.15).restart();
      runUntilConverged(simulation, 200, 0.001);
      
      // Remove hub centering force
      if (hubIp) {
        simulation.force('hubCentering', null);
      }
    }
    
    simulation.stop();
    
    // Remove the temporary forces after simulation
    simulation.force('y', null);
    simulation.force('componentSeparation', null);
    simulation.force('componentCohesion', null);
    simulation.force('hubCentering', null);
    
    // Store final positions in yMap, ensuring all are valid
    simNodes.forEach(n => {
      if (n.y !== undefined && isFinite(n.y)) {
        yMap.set(n.id, n.y);
      } else {
        console.warn('Invalid Y position for node:', n.id, n.y);
        yMap.set(n.id, (MARGIN.top + INNER_HEIGHT) / 2);
      }
    });

    // Compact IP positions to eliminate gaps (inspired by detactTimeSeries in main.js)
    // This redistributes IPs evenly across the vertical space while:
    //  - preserving connected-component separation when multiple components exist
    //  - maintaining each component's internal ordering from the force layout
    compactIPPositions(simNodes, yMap, MARGIN.top, INNER_HEIGHT, components, ipToComponent);

    // Ensure all IPs in allIps have positions in yMap (safety check for any edge cases)
    // This handles any IPs that might not be in simNodes
    let maxY = MARGIN.top + 12;
    simNodes.forEach(n => {
      const y = yMap.get(n.id);
      if (y > maxY) maxY = y;
    });
    allIps.forEach(ip => {
      if (!yMap.has(ip)) {
        maxY += 15; // Add with same spacing as compaction
        yMap.set(ip, maxY);
        console.warn(`IP ${ip} not in simNodes, assigned fallback position ${maxY}`);
      }
    });

    // Phase 2: Animate from current positions to sorted timeline positions
    // This follows main.js detactTimeSeries() approach - sort by Y position
    setStatus(statusEl,'Animating to timeline...');

    // Sort all IPs by their Y positions from force simulation (like main.js)
    const sortedIps = [...allIps];
    sortedIps.sort((a, b) => {
      return (yMap.get(a) || 0) - (yMap.get(b) || 0);
    });

    // Distribute evenly across available height (matching main.js detactTimeSeries)
    // main.js uses: step = Math.min((height-25)/(numNode+1), 15) and y = 12 + i*step
    // In main.js, 'height' is INNER_HEIGHT (780 - MARGIN.top - MARGIN.bottom) and MARGIN.top=0
    // Match main.js exactly: use fixed max step of 15px, start at y=12 (relative to SVG, so add MARGIN.top)
    const finalYMap = new Map();
    const step = Math.min((INNER_HEIGHT - 25) / (sortedIps.length + 1), 15);
    for (let i = 0; i < sortedIps.length; i++) {
      finalYMap.set(sortedIps[i], MARGIN.top + 12 + i * step);
    }

    // Create finalY function that returns the computed positions
    const finalY = (ip) => finalYMap.get(ip);

    // Recalculate max arc radius based on actual final Y positions
    let actualMaxArcRadius = 0;
    linksWithNodes.forEach(l => {
      const y1 = finalY(l.sourceNode.name);
      const y2 = finalY(l.targetNode.name);
      if (y1 !== undefined && y2 !== undefined) {
        const arcRadius = Math.abs(y2 - y1) / 2;
        if (arcRadius > actualMaxArcRadius) actualMaxArcRadius = arcRadius;
      }
    });

    // Update x-scale range to fit arcs within viewport
    const actualXEnd = svgWidth - MARGIN.right - actualMaxArcRadius;
    currentXEnd = actualXEnd; // Update the dynamic xEnd for xScaleLens
    x.range([xStart, actualXEnd]);

    // Update axis to match new x-scale
    const actualAxisScale = d3.scaleTime()
      .domain([xMinDate, xMaxDate])
      .range([0, actualXEnd - xStart]);

    const axisSvgUpdate = d3.select('#axis-top');
    axisSvgUpdate.selectAll('*').remove();
    axisSvgUpdate.append('g')
      .attr('transform', `translate(${xStart}, 28)`)
      .call(d3.axisTop(actualAxisScale).ticks(looksAbsolute ? 7 : 7).tickFormat(d => {
        if (looksAbsolute) return utcTick(d);
        const relUnits = Math.round((d.getTime()) / unitMs);
        return `t=${relUnits}${unitSuffix}`;
      }));

    const finalSpanData = createSpanData(sortedIps, ipSpans);
    
    // Animate everything to timeline (with correct final alignment)
    // Update lines - rebind to sorted data
    rows.selectAll('line')
      .data(finalSpanData, d => d.ip)
      .transition().duration(1200)
      .attr('x1', d => d.span ? xScaleLens(d.span.min) : MARGIN.left)
      .attr('x2', d => d.span ? xScaleLens(d.span.max) : MARGIN.left)
      .tween('y-line', function(d) {
        const yStart = y(d.ip);
        const yEnd = finalY(d.ip);
        const interp = d3.interpolateNumber(yStart, yEnd);
        const self = d3.select(this);
        return function(t) {
          const yy = interp(t);
          self.attr('y1', yy).attr('y2', yy);
        };
      })
      .style('opacity', 1);
    
    // Update labels - rebind to sorted order to ensure alignment
    const finalIpLabelsSelection = rows.selectAll('text')
      .data(sortedIps, d => d); // Use key function to match by IP string
    
    // Add hover handlers to the selection (they persist through transition)
    finalIpLabelsSelection
      .on('mouseover', function (event, hoveredIp) {
        // Find all arcs connected to this IP (as source or target)
        const connectedArcs = linksWithNodes.filter(l => l.sourceNode.name === hoveredIp || l.targetNode.name === hoveredIp);
        const connectedIps = new Set();
        connectedArcs.forEach(l => {
          connectedIps.add(l.sourceNode.name);
          connectedIps.add(l.targetNode.name);
        });

        // Highlight connected arcs: full opacity for connected, dim others
        arcPaths.style('stroke-opacity', d => {
          const isConnected = d.sourceNode.name === hoveredIp || d.targetNode.name === hoveredIp;
          return isConnected ? 1 : 0.2;
        })
        .attr('stroke-width', d => {
          const isConnected = d.sourceNode.name === hoveredIp || d.targetNode.name === hoveredIp;
          if (isConnected) {
            const baseW = widthScale(Math.max(1, d.count));
            return Math.max(3, baseW < 2 ? baseW * 2.5 : baseW * 1.3);
          }
          return widthScale(Math.max(1, d.count));
        });

        // Highlight row lines for connected IPs
        svg.selectAll('.row-line')
          .attr('stroke-opacity', s => s && s.ip && connectedIps.has(s.ip) ? 0.8 : 0.1)
          .attr('stroke-width', s => s && s.ip && connectedIps.has(s.ip) ? 1 : 0.4);

        // Highlight IP labels for connected IPs
        const hoveredLabel = d3.select(this);
        const hoveredColor = hoveredLabel.style('fill') || '#343a40';
        svg.selectAll('.ip-label')
          .attr('font-weight', s => connectedIps.has(s) ? 'bold' : null)
          .style('font-size', s => connectedIps.has(s) ? '14px' : null)
          .style('fill', s => {
            if (s === hoveredIp) return hoveredColor;
            return connectedIps.has(s) ? '#007bff' : '#343a40';
          });

        // Show tooltip with IP information
        const arcCount = connectedArcs.length;
        const uniqueConnections = new Set();
        connectedArcs.forEach(l => {
          if (l.sourceNode.name === hoveredIp) uniqueConnections.add(l.targetNode.name);
          if (l.targetNode.name === hoveredIp) uniqueConnections.add(l.sourceNode.name);
        });
        const content = `IP: ${hoveredIp}<br>` +
          `Connected arcs: ${arcCount}<br>` +
          `Unique connections: ${uniqueConnections.size}`;
        showTooltip(tooltip, event, content);
      })
      .on('mousemove', function (event) {
        // Keep tooltip following cursor
        if (tooltip && tooltip.style.display !== 'none') {
          const pad = 10;
          tooltip.style.left = (event.clientX + pad) + 'px';
          tooltip.style.top = (event.clientY + pad) + 'px';
        }
      })
      .on('mouseout', function () {
        hideTooltip(tooltip);
        // Restore default state
        arcPaths.style('stroke-opacity', 0.6)
                .attr('stroke-width', d => widthScale(Math.max(1, d.count)));
        svg.selectAll('.row-line').attr('stroke-opacity', 1).attr('stroke-width', 0.4);
        svg.selectAll('.ip-label')
          .attr('font-weight', null)
          .style('font-size', null)
          .style('fill', '#343a40');
      });
    
    // Animate labels to final positions (matching main.js updateTransition)
    // Update node positions first, then animate labels to xConnected positions
    updateNodePositions();
    finalIpLabelsSelection
      .transition().duration(1200)
      .tween('y-text', function(d) {
        const yStart = y(d);
        const yEnd = finalY(d);
        const interp = d3.interpolateNumber(yStart, yEnd);
        const self = d3.select(this);
        return function(t) { self.attr('y', interp(t)); };
      })
      .attr('x', d => {
        // Match main.js: position at xConnected (strongest connection time)
        const node = ipToNode.get(d);
        return node && node.xConnected !== undefined ? node.xConnected : MARGIN.left;
      })
      .text(d => d); // Re-apply text in case order changed
    
    // Animate arcs with proper interpolation to final positions (matching main.js pattern)
    arcPaths.transition().duration(1200)
      .attrTween('d', function(d) {
        const xp = xScaleLens(d.minute);
        // Start at current scale positions; end at finalY
        const y1Start = y(d.sourceNode.name);
        const y2Start = y(d.targetNode.name);
        const y1End = finalY(d.sourceNode.name) ?? y1Start;
        const y2End = finalY(d.targetNode.name) ?? y2Start;
        if (!isFinite(xp) || !isFinite(y1End) || !isFinite(y2End)) {
          return function() { return 'M0,0 L0,0'; };
        }
        return function(t) {
          const y1t = y1Start + (y1End - y1Start) * t;
          const y2t = y2Start + (y2End - y2Start) * t;
          // Update node positions for linkArc (matching main.js)
          d.source.x = xp;
          d.source.y = y1t;
          d.target.x = xp;
          d.target.y = y2t;
          return linkArc(d);
        };
      })
      .on('end', (d, i) => {
        // Update gradient to final positions so grey->attack aligns with endpoints
        const xp = xScaleLens(d.minute);
        const y1f = finalY(d.sourceNode.name);
        const y2f = finalY(d.targetNode.name);
        svg.select(`#${gradIdForLink(d)}`)
          .attr('x1', xp)
          .attr('x2', xp)
          .attr('y1', y1f)
          .attr('y2', y2f);
        if (i === 0) {
          // Recompute arc paths using finalY positions to lock alignment (matching main.js)
          arcPaths.attr('d', dd => {
            const xp2 = xScaleLens(dd.minute);
            const a = finalY(dd.sourceNode.name);
            const b = finalY(dd.targetNode.name);
            if (!isFinite(xp2) || !isFinite(a) || !isFinite(b)) return 'M0,0 L0,0';
            // Update node positions for linkArc
            dd.source.x = xp2;
            dd.source.y = a;
            dd.target.x = xp2;
            dd.target.y = b;
            return linkArc(dd);
          });
          
          // Store evenly distributed positions for yScaleLens to use
          evenlyDistributedYPositions = new Map();
          sortedIps.forEach(ip => {
            evenlyDistributedYPositions.set(ip, finalY(ip));
          });

          // Update node positions to reflect the new evenly distributed y positions
          updateNodePositions();

          // Initialize fisheye AFTER animation completes and positions are finalized
          initFisheye();

          setStatus(statusEl,`${data.length} records • ${sortedIps.length} IPs • ${attacks.length} ${labelMode==='attack_group' ? 'attack groups' : 'attack types'}`);

          // Auto-fit disabled to match main.js detactTimeSeries() behavior
          // setTimeout(() => autoFitArcs(), 100);
        }
      });

    // Auto-fit arcs function: adaptively space IPs to fit in viewport
    function autoFitArcs() {
      console.log('Auto-fit called, IPs:', sortedIps.length);

      const hasMultipleComponents = components && components.length > 1;
      const gapTokenPrefix = '__gap__';

      function buildComponentAwareDomain() {
        if (!hasMultipleComponents) return sortedIps.slice();
        const domain = [];
        const gapSlots = 3; // virtual slots to enforce breathing room between disconnected clusters
        for (let i = 0; i < sortedIps.length; i++) {
          const ip = sortedIps[i];
          domain.push(ip);
          const nextIp = sortedIps[i + 1];
          if (!nextIp) continue;
          const currComp = ipToComponent.has(ip) ? ipToComponent.get(ip) : -1;
          const nextComp = ipToComponent.has(nextIp) ? ipToComponent.get(nextIp) : -1;
          if (currComp !== nextComp) {
            for (let slot = 0; slot < gapSlots; slot++) {
              domain.push(`${gapTokenPrefix}${currComp}_${i}_${slot}`);
            }
          }
        }
        return domain;
      }

      const autoFitDomain = buildComponentAwareDomain();
      const availableHeight = Math.max(60, height - MARGIN.top - MARGIN.bottom - 25);
      const maxStep = 12; // tighter maximum spacing between rows
      const padding = 0.3;
      const domainSpan = Math.max(1, autoFitDomain.length - 1);
      const desiredSpan = Math.min(availableHeight, domainSpan * maxStep);
      const rangeStart = MARGIN.top + 12;
      const rangeEnd = rangeStart + desiredSpan;

      // Snapshot current scale so we can tween from existing positions
      const startYScale = finalY.copy();

      const autoFitY = d3.scalePoint()
        .domain(autoFitDomain)
        .range([rangeStart, rangeEnd])
        .padding(padding);

      const targetPositions = new Map();
      autoFitDomain.forEach(token => {
        if (!token.startsWith(gapTokenPrefix)) {
          targetPositions.set(token, autoFitY(token));
        }
      });

      // Animate to new positions while preserving component separation
      rows.selectAll('line')
        .transition().duration(800)
        .tween('y-line', function(d) {
          const yStart = startYScale(d.ip);
          const yEnd = targetPositions.get(d.ip) ?? yStart;
          const interp = d3.interpolateNumber(yStart, yEnd);
          const self = d3.select(this);
          return function(t) {
            const yy = interp(t);
            self.attr('y1', yy).attr('y2', yy);
          };
        });

      rows.selectAll('text')
        .transition().duration(800)
        .tween('y-text', function(d) {
          const yStart = startYScale(d);
          const yEnd = targetPositions.get(d) ?? yStart;
          const interp = d3.interpolateNumber(yStart, yEnd);
          const self = d3.select(this);
          return function(t) { self.attr('y', interp(t)); };
        })
        .attr('x', d => {
          // Maintain xConnected position (strongest connection time) during auto-fit
          const node = ipToNode.get(d);
          return node && node.xConnected !== undefined ? node.xConnected : MARGIN.left;
        });

      arcPaths.transition().duration(800)
        .attrTween('d', function(d) {
          const xp = xScaleLens(d.minute);
          const y1Start = startYScale(d.sourceNode.name);
          const y2Start = startYScale(d.targetNode.name);
          const y1End = targetPositions.get(d.sourceNode.name) ?? y1Start;
          const y2End = targetPositions.get(d.targetNode.name) ?? y2Start;
          return function(t) {
            const y1t = y1Start + (y1End - y1Start) * t;
            const y2t = y2Start + (y2End - y2Start) * t;
            // Update node positions for linkArc (matching main.js)
            d.source.x = xp;
            d.source.y = y1t;
            d.target.x = xp;
            d.target.y = y2t;
            return linkArc(d);
          };
        })
        .on('end', () => {
          const newRange = autoFitY.range();
          y.domain(autoFitDomain).range(newRange);
          finalY.domain(autoFitDomain).range(newRange);
          const spacingSample = sortedIps.length > 1
            ? Math.abs((targetPositions.get(sortedIps[1]) ?? 0) - (targetPositions.get(sortedIps[0]) ?? 0))
            : 0;
          const compMsg = hasMultipleComponents ? ' (component gaps preserved)' : '';
          setStatus(statusEl,`Auto-fit: ${sortedIps.length} IPs${compMsg} with ${(spacingSample || maxStep).toFixed(1)}px spacing`);

          // Determine whether baseline labels have enough vertical space.
          let minSpacing = Infinity;
          if (sortedIps.length > 1) {
            for (let i = 1; i < sortedIps.length; i++) {
              const prev = sortedIps[i - 1];
              const curr = sortedIps[i];
              const yPrev = y(prev);
              const yCurr = y(curr);
              if (isFinite(yPrev) && isFinite(yCurr)) {
                const dy = Math.abs(yCurr - yPrev);
                if (dy < minSpacing) minSpacing = dy;
              }
            }
          }
          const labelSpacingThreshold = 10; // px
          labelsCompressedMode = minSpacing < labelSpacingThreshold;
          const baseLabelSel = rows.selectAll('text');
          if (labelsCompressedMode) {
            // Hide baseline labels when there is not enough space (matching main.js: no vertical lensing)
            baseLabelSel.style('opacity', 0);
          } else {
            baseLabelSel.style('opacity', 1);
          }

        });

      linksWithNodes.forEach(d => {
        const xp = xScaleLens(d.minute);
        svg.select(`#${gradIdForLink(d)}`)
          .transition().duration(800)
          .attr('y1', targetPositions.get(d.sourceNode.name) ?? startYScale(d.sourceNode.name))
          .attr('y2', targetPositions.get(d.targetNode.name) ?? startYScale(d.targetNode.name));
      });
    }

    // Toggle lens magnification
    function toggleLensing() {
      isLensing = !isLensing;
      console.log('Lens toggled:', isLensing, 'Center:', lensCenter);

      if (isLensing) {
        // Add invisible overlay for mouse tracking - only on top axis timeline
        axisSvg.append('rect')
          .attr('class', 'lens-overlay')
          .attr('x', xStart)
          .attr('y', 0)
          .attr('width', timelineWidth)
          .attr('height', 36)
          .style('fill', 'none')
          .style('pointer-events', 'all')
          .style('cursor', 'crosshair')
          .on('mousemove', function(event) {
            const [mx, my] = d3.pointer(event);
            // Clamp mouse position to timeline area
            const clampedX = Math.max(xStart, Math.min(mx, xStart + timelineWidth));
            // Convert mouse X to timestamp
            lensCenter = tsMin + ((clampedX - xStart) / timelineWidth) * (tsMax - tsMin);
            updateLensVisualization();
          });

      } else {
        // Remove overlay when lens is disabled (matching main.js: only horizontal lensing)
        axisSvg.select('.lens-overlay').remove();
      }
    }
    
    // Store reference to toggleLensing so button can trigger it
    toggleLensingFn = toggleLensing;

    // Initialize fisheye scale for vertical row distortion
    function initFisheye() {
      // Store original row positions from current node positions
      // This should be called AFTER the force simulation and auto-fit complete
      originalRowPositions.clear();

      // Use sortedIps order (from force simulation) not allIps
      const ipsToUse = sortedIps && sortedIps.length > 0 ? sortedIps : allIps;
      ipsToUse.forEach(ip => {
        const node = ipToNode.get(ip);
        const currentY = node && node.y !== undefined ? node.y : y(ip);
        originalRowPositions.set(ip, currentY);
      });

      // Create vertical fisheye scale using imported factory
      fisheyeScale = createFisheyeScale({
        sortedIps: ipsToUse,
        originalPositions: originalRowPositions,
        marginTop: MARGIN.top,
        innerHeight: INNER_HEIGHT,
        getDistortion: () => fisheyeDistortion
      });

      // Create horizontal fisheye scale using imported factory
      horizontalFisheyeScale = createHorizontalFisheyeScale({
        xStart,
        xEnd: currentXEnd,
        tsMin,
        tsMax,
        getDistortion: () => fisheyeDistortion
      });

      console.log('Fisheye initialized:', {
        numIps: ipsToUse.length,
        focus: fisheyeScale._focus,
        distortion: fisheyeDistortion,
        sampleOriginalPositions: Array.from(originalRowPositions.entries()).slice(0, 3)
      });
    }

    // Apply fisheye distortion based on mouse position
    function applyFisheye(mouseX, mouseY) {
      if (!fisheyeEnabled || !fisheyeScale) return;

      // Debug: log focus positions and ranges
      console.log('Applying fisheye:', {
        mouseX,
        mouseY,
        verticalRange: `${MARGIN.top} to ${MARGIN.top + INNER_HEIGHT}`,
        horizontalRange: `${xStart} to ${xEnd}`,
        verticalFocusNormalized: (mouseY - MARGIN.top) / INNER_HEIGHT,
        horizontalFocusNormalized: (mouseX - xStart) / (xEnd - xStart)
      });

      // Update vertical fisheye focus point
      fisheyeScale.focus(mouseY);

      // Update horizontal fisheye focus point
      if (horizontalFisheyeScale) {
        horizontalFisheyeScale.focus(mouseX);
      }

      // Use sortedIps (from force simulation) to maintain the original order
      const ipsToUse = fisheyeScale._sortedIps || sortedIps || allIps;

      // Transform all row positions, ensuring monotonicity
      let prevY = -Infinity;
      ipsToUse.forEach((ip) => {
        let distortedY = fisheyeScale.apply(ip);

        // Ensure monotonicity: each row must be at or below the previous row
        if (distortedY <= prevY) {
          distortedY = prevY + 1; // Minimum spacing of 1 pixel
        }
        prevY = distortedY;

        // Update node positions
        const node = ipToNode.get(ip);
        if (node) {
          node.y = distortedY;
        }
      });

      // Update row lines
      rows.selectAll('line')
        .attr('y1', d => {
          const node = ipToNode.get(d.ip);
          return node ? node.y : y(d.ip);
        })
        .attr('y2', d => {
          const node = ipToNode.get(d.ip);
          return node ? node.y : y(d.ip);
        });

      // Update IP labels
      rows.selectAll('text')
        .attr('y', d => {
          const node = ipToNode.get(d);
          return node ? node.y : y(d);
        });

      // Update arc paths with new Y positions
      arcPaths.attr('d', d => {
        const xp = xScaleLens(d.minute);
        const y1 = ipToNode.get(d.sourceNode.name)?.y || y(d.sourceNode.name);
        const y2 = ipToNode.get(d.targetNode.name)?.y || y(d.targetNode.name);

        // Update node positions for linkArc
        d.source.x = xp;
        d.source.y = y1;
        d.target.x = xp;
        d.target.y = y2;

        return linkArc(d);
      });

      // Update gradients
      linksWithNodes.forEach(d => {
        const xp = xScaleLens(d.minute);
        const y1 = ipToNode.get(d.sourceNode.name)?.y || y(d.sourceNode.name);
        const y2 = ipToNode.get(d.targetNode.name)?.y || y(d.targetNode.name);

        svg.select(`#${gradIdForLink(d)}`)
          .attr('x1', xp)
          .attr('x2', xp)
          .attr('y1', y1)
          .attr('y2', y2);
      });

      // Update time axis to reflect horizontal fisheye distortion
      updateTimeAxisWithFisheye();
    }

    // Update time axis based on horizontal fisheye distortion
    function updateTimeAxisWithFisheye() {
      if (!fisheyeEnabled || !horizontalFisheyeScale) return;

      const axisSvg = d3.select('#axis-top');
      const axisGroup = axisSvg.select('g');

      // Create tick values
      const tempScale = d3.scaleTime()
        .domain([xMinDate, xMaxDate])
        .range([0, xEnd - xStart]);

      const tickValues = tempScale.ticks(7);

      // Update tick positions based on horizontal fisheye
      axisGroup.selectAll('.tick')
        .data(tickValues, d => d.getTime()) // Use key function for data binding
        .attr('transform', function(d) {
          // Convert date to timestamp
          let timestamp;
          if (looksAbsolute) {
            if (unit === 'microseconds') timestamp = d.getTime() * 1000;
            else if (unit === 'milliseconds') timestamp = d.getTime();
            else if (unit === 'seconds') timestamp = d.getTime() / 1000;
            else if (unit === 'minutes') timestamp = d.getTime() / 60000;
            else timestamp = d.getTime() / 3600000; // hours
          } else {
            timestamp = (d.getTime() / unitMs) + base;
          }

          // Apply horizontal fisheye
          const newX = horizontalFisheyeScale.apply(timestamp) - xStart;
          return `translate(${newX},0)`;
        });
    }

    // Reset fisheye to original positions
    function resetFisheye() {
      if (!originalRowPositions.size) return;

      // Use sortedIps (from force simulation) to maintain the original order
      const ipsToUse = (fisheyeScale && fisheyeScale._sortedIps) || sortedIps || allIps;

      // Restore original node positions
      ipsToUse.forEach((ip) => {
        const node = ipToNode.get(ip);
        if (node) {
          node.y = originalRowPositions.get(ip) || y(ip);
        }
      });

      // Animate row lines back to original positions
      rows.selectAll('line')
        .transition()
        .duration(200)
        .attr('y1', d => {
          const node = ipToNode.get(d.ip);
          return node ? node.y : y(d.ip);
        })
        .attr('y2', d => {
          const node = ipToNode.get(d.ip);
          return node ? node.y : y(d.ip);
        });

      // Animate IP labels back to original positions
      rows.selectAll('text')
        .transition()
        .duration(200)
        .attr('y', d => {
          const node = ipToNode.get(d);
          return node ? node.y : y(d);
        });

      // Animate arcs back to original positions
      arcPaths
        .transition()
        .duration(200)
        .attr('d', d => {
          const xp = xScaleLens(d.minute);
          const y1 = ipToNode.get(d.sourceNode.name)?.y || y(d.sourceNode.name);
          const y2 = ipToNode.get(d.targetNode.name)?.y || y(d.targetNode.name);

          // Update node positions for linkArc
          d.source.x = xp;
          d.source.y = y1;
          d.target.x = xp;
          d.target.y = y2;

          return linkArc(d);
        });

      // Animate gradients back to original positions
      linksWithNodes.forEach(d => {
        const xp = xScaleLens(d.minute);
        const y1 = ipToNode.get(d.sourceNode.name)?.y || y(d.sourceNode.name);
        const y2 = ipToNode.get(d.targetNode.name)?.y || y(d.targetNode.name);

        svg.select(`#${gradIdForLink(d)}`)
          .transition()
          .duration(200)
          .attr('x1', xp)
          .attr('x2', xp)
          .attr('y1', y1)
          .attr('y2', y2);
      });

      // Reset time axis to original positions
      resetTimeAxis();
    }

    // Reset time axis to original positions
    function resetTimeAxis() {
      const axisSvg = d3.select('#axis-top');
      const axisGroup = axisSvg.select('g');

      // Create tick values
      const tempScale = d3.scaleTime()
        .domain([xMinDate, xMaxDate])
        .range([0, xEnd - xStart]);

      const tickValues = tempScale.ticks(7);

      // Animate ticks back to original positions
      axisGroup.selectAll('.tick')
        .data(tickValues, d => d.getTime())
        .transition()
        .duration(200)
        .attr('transform', function(d) {
          // Use original x scale (without fisheye)
          const originalX = tempScale(d);
          return `translate(${originalX},0)`;
        });
    }

    // Note: initFisheye() is now called AFTER the animation completes
    // (see line ~2119 in the animation 'end' handler)

    // Store reference to resetFisheye so button handler can call it
    resetFisheyeFn = resetFisheye;

    // Add mouse event handlers for fisheye
    svg
      .style('cursor', () => fisheyeEnabled ? 'crosshair' : 'default')
      .on('mousemove', function(event) {
        if (fisheyeEnabled) {
          const [mouseX, mouseY] = d3.pointer(event);
          currentMouseX = mouseX; // Store for potential axis updates
          applyFisheye(mouseX, mouseY);
        }
      })
      .on('mouseleave', function() {
        if (fisheyeEnabled) {
          currentMouseX = null;
          resetFisheye();
        }
      });

    // Update visualization with current lens state
    function updateLensVisualization() {
      console.log('Updating lens visualization, isLensing:', isLensing, 'arcPaths:', arcPaths ? arcPaths.size() : 0);

      // Animate arcs to new positions (matching main.js pattern)
      arcPaths.transition().duration(250)
        .attr('d', d => {
          const xp = xScaleLens(d.minute);
          const y1 = yScaleLens(d.sourceNode.name);
          const y2 = yScaleLens(d.targetNode.name);
          // Update node positions for linkArc (matching main.js)
          d.source.x = xp;
          d.source.y = y1;
          d.target.x = xp;
          d.target.y = y2;
          return linkArc(d);
        });

      // Update gradients
      linksWithNodes.forEach(d => {
        const xp = xScaleLens(d.minute);
        svg.select(`#${gradIdForLink(d)}`)
          .transition().duration(250)
          .attr('x1', xp)
          .attr('x2', xp)
          .attr('y1', yScaleLens(d.sourceNode.name))
          .attr('y2', yScaleLens(d.targetNode.name));
      });

      // Update row lines (both horizontal span and vertical position)
      rows.selectAll('line')
        .transition().duration(250)
        .attr('x1', d => d.span ? xScaleLens(d.span.min) : MARGIN.left)
        .attr('x2', d => d.span ? xScaleLens(d.span.max) : MARGIN.left)
        .attr('y1', d => yScaleLens(d.ip))
        .attr('y2', d => yScaleLens(d.ip));

      // Update node positions first (xConnected depends on xScaleLens which may have changed)
      updateNodePositions();

      // Update IP label positions (matching main.js: no vertical lensing, just update Y from scale)
      const labelSelection = rows.selectAll('text');
      labelSelection
        .transition().duration(250)
        .attr('y', d => yScaleLens(d))
        .attr('x', d => {
          // Maintain xConnected position (first arc time) during lens updates
          const node = ipToNode.get(d);
          return node && node.xConnected !== undefined ? node.xConnected : MARGIN.left;
        });

      // Update label visibility based on compressed mode (matching main.js: no vertical lensing)
      labelSelection.style('opacity', labelsCompressedMode ? 0 : 1);

      // Update axis to follow lens transformation
      const axisSvg = d3.select('#axis-top');
      const axisGroup = axisSvg.select('g');

      // Create a temporary scale to get tick values
      const tempScale = d3.scaleTime()
        .domain([xMinDate, xMaxDate])
        .range([0, timelineWidth]);

      const tickValues = tempScale.ticks(7);

      // Update tick positions based on lens
      axisGroup.selectAll('.tick')
        .data(tickValues)
        .transition().duration(250)
        .attr('transform', function(d) {
          // d is a Date object
          // Convert to timestamp in the data's unit
          let timestamp;
          if (looksAbsolute) {
            if (unit === 'microseconds') timestamp = d.getTime() * 1000;
            else if (unit === 'milliseconds') timestamp = d.getTime();
            else if (unit === 'seconds') timestamp = d.getTime() / 1000;
            else if (unit === 'minutes') timestamp = d.getTime() / 60000;
            else timestamp = d.getTime() / 3600000; // hours
          } else {
            timestamp = (d.getTime() / unitMs) + base;
          }

          // Calculate new position using lens
          const newX = xScaleLens(timestamp) - xStart;
          return `translate(${newX},0)`;
        });
    }
    
    // Store reference to updateLensVisualization so slider can trigger updates
    updateLensVisualizationFn = updateLensVisualization;
  }

  // Compute nodes array with connectivity metric akin to legacy computeNodes
  function computeNodes(data) {
    const relationships = buildRelationships(data);
    const totals = new Map(); // ip -> total count across records
    const ipMinuteCounts = new Map(); // ip -> Map(minute -> sum)
    const ipSet = new Set();
    for (const row of data) {
      ipSet.add(row.src_ip); ipSet.add(row.dst_ip);
      totals.set(row.src_ip, (totals.get(row.src_ip) || 0) + (row.count || 1));
      totals.set(row.dst_ip, (totals.get(row.dst_ip) || 0) + (row.count || 1));
      if (!ipMinuteCounts.has(row.src_ip)) ipMinuteCounts.set(row.src_ip, new Map());
      if (!ipMinuteCounts.has(row.dst_ip)) ipMinuteCounts.set(row.dst_ip, new Map());
      const m = row.timestamp, c = (row.count || 1);
      ipMinuteCounts.get(row.src_ip).set(m, (ipMinuteCounts.get(row.src_ip).get(m) || 0) + c);
      ipMinuteCounts.get(row.dst_ip).set(m, (ipMinuteCounts.get(row.dst_ip).get(m) || 0) + c);
    }

    // Connectivity per IP using legacy-style rule: take the max pair frequency over time,
    // filtered by a threshold (valueSlider-equivalent). Lower time wins on ties.
    const connectivityThreshold = 1;
    const isConnected = computeConnectivityFromRelationships(relationships, connectivityThreshold, ipSet);

    // Build nodes list
    let id = 0;
    const nodes = Array.from(ipSet).map(ip => {
      const series = ipMinuteCounts.get(ip) || new Map();
      let maxMinuteVal = 0; let maxMinute = null;
      for (const [m, v] of series.entries()) { if (v > maxMinuteVal) { maxMinuteVal = v; maxMinute = m; } }
      const conn = isConnected.get(ip) || { max: 0, time: null };
      return {
        id: id++,
        name: ip,
        total: totals.get(ip) || 0,
        maxMinuteVal,
        maxMinute,
        isConnected: conn.max,
        isConnectedMaxTime: conn.time,
      };
    });

    // Sort: connectivity desc, then total desc, then name asc
    nodes.sort((a, b) => {
      if (b.isConnected !== a.isConnected) return b.isConnected - a.isConnected;
      if (b.total !== a.total) return b.total - a.total;
      return a.name.localeCompare(b.name, 'en');
    });

    return { nodes, relationships };
  }

  // Compact IP positions to eliminate vertical gaps and minimize arc crossing.
  // When information about connected components is available, we keep each
  // disconnected component in its own contiguous vertical block so that
  // isolated clusters of IPs/links do not get interleaved visually.
  // Similar in spirit to detactTimeSeries() in main.js.
  function compactIPPositions(simNodes, yMap, topMargin, INNER_HEIGHT, components, ipToComponent) {
    // Simple uniform spacing (like main.js detactTimeSeries)
    // Collect all IPs and sort by their current Y positions
    const ipArray = [];
    simNodes.forEach(n => {
      const yPos = yMap.get(n.id);
      if (yPos !== undefined && isFinite(yPos)) {
        ipArray.push({ ip: n.id, y: yPos });
      }
    });

    ipArray.sort((a, b) => a.y - b.y);

    const numIPs = ipArray.length;
    if (numIPs === 0) return;

    // Uniform spacing across full height
    const step = Math.min((INNER_HEIGHT - 25) / (numIPs + 1), 15);

    ipArray.forEach((item, i) => {
      const newY = topMargin + 12 + i * step;
      yMap.set(item.ip, newY);
    });

    console.log(`Compacted ${numIPs} IPs with uniform step size ${step.toFixed(2)}px`);
  }

  // Order nodes like the TSX component:
  // 1) Build force-simulated y for natural local ordering
  // 2) Determine each IP's primary (most frequent) non-normal attack type
  // 3) Order attack groups by earliest time they appear
  // 4) Within each group, order by simulated y; then assign evenly spaced positions later via scale
  function computeNodesByAttackGrouping(links) {
    const ipSet = new Set();
    for (const l of links) { ipSet.add(l.source); ipSet.add(l.target); }

    // Build pair weights ignoring minute to feed simulation, and track
    // whether each pair ever participates in a non-'normal' attack. We
    // will use only those non-normal edges for component detection so
    // that benign/background traffic does not glue unrelated attack
    // clusters into a single component.
    const pairKey = (a,b)=> a<b?`${a}__${b}`:`${b}__${a}`;
    const pairWeights = new Map();
    const pairHasNonNormalAttack = new Map(); // key -> boolean
    for (const l of links) {
      const k = pairKey(l.source,l.target);
      pairWeights.set(k,(pairWeights.get(k)||0)+ (l.count||1));
      if (l.attack && l.attack !== 'normal') {
        pairHasNonNormalAttack.set(k, true);
      }
    }

    const simNodes = Array.from(ipSet).map(id=>({id}));
    const simLinks = [];
    const componentLinks = [];
    for (const [k,w] of pairWeights.entries()) {
      const [a,b] = k.split('__');
      const link = {source:a,target:b,value:w};
      simLinks.push(link);
      if (pairHasNonNormalAttack.get(k)) {
        componentLinks.push({ source: a, target: b });
      }
    }

    // Detect connected components for better separation. Prefer to use
    // only edges that have at least one non-'normal' attack so that
    // purely-normal background traffic does not connect unrelated
    // attack clusters. If everything is 'normal', fall back to using
    // the full link set.
    const components = findConnectedComponents(
      simNodes,
      componentLinks.length > 0 ? componentLinks : simLinks
    );
    const ipToComponent = new Map();
    components.forEach((comp, compIdx) => {
      comp.forEach(ip => ipToComponent.set(ip, compIdx));
    });
    
    // Debug: log component information
    if (components.length > 1) {
      console.log(`Detected ${components.length} disconnected components:`, 
        components.map((comp, idx) => `Component ${idx}: ${comp.length} nodes`).join(', '));
    }

    // Return raw data for simulation - simulation will be created in render()
    // using the imported createForceSimulation function
    
    // Initialize empty yMap - will be populated during render
    const yMap = new Map();

    // Primary attack per IP (exclude 'normal')
    const ipAttackCounts = new Map(); // ip -> Map(attack->count)
    for (const l of links) {
      if (l.attack && l.attack !== 'normal'){
        for (const ip of [l.source,l.target]){
          if (!ipAttackCounts.has(ip)) ipAttackCounts.set(ip,new Map());
          const m = ipAttackCounts.get(ip); m.set(l.attack,(m.get(l.attack)||0)+(l.count||1));
        }
      }
    }
    const primaryAttack = new Map();
    for (const ip of ipSet){
      const m = ipAttackCounts.get(ip);
      if (!m || m.size===0) { primaryAttack.set(ip,'unknown'); continue; }
      let best='unknown',bestC=-1; for (const [att,c] of m.entries()) if (c>bestC){best=att;bestC=c;}
      primaryAttack.set(ip,best);
    }

    // Earliest time per attack type
    const earliest = new Map();
    for (const l of links){
      if (!l.attack || l.attack==='normal') continue;
      const t = earliest.get(l.attack);
      earliest.set(l.attack, t===undefined? l.minute : Math.min(t,l.minute));
    }

    // Group IPs by attack
    const groups = new Map(); // attack -> array of ips
    for (const ip of ipSet){
      const att = primaryAttack.get(ip) || 'unknown';
      if (!groups.has(att)) groups.set(att,[]);
      groups.get(att).push(ip);
    }

    // Sort groups by earliest time, unknown last
    const groupList = Array.from(groups.keys()).sort((a,b)=>{
      if (a==='unknown' && b!=='unknown') return 1;
      if (b==='unknown' && a!=='unknown') return -1;
      const ta = earliest.get(a); const tb = earliest.get(b);
      if (ta===undefined && tb===undefined) return a.localeCompare(b);
      if (ta===undefined) return 1; if (tb===undefined) return -1; return ta - tb;
    });

    // Flatten nodes in group order; within group by simulated y
    const nodes = [];
    for (const g of groupList){
      const arr = groups.get(g) || [];
      arr.sort((a,b)=> (yMap.get(a)||0) - (yMap.get(b)||0));
      for (const ip of arr) nodes.push({ name: ip, group: g });
    }
    return { nodes, simNodes, simLinks, yMap, components, ipToComponent };
  }

  // Wrapper for decodeIp that provides global maps
  const _decodeIp = (value) => decodeIp(value, ipIdToAddr);

  // Wrapper functions for decoders that provide global maps
  const _decodeAttack = (value) => decodeAttack(value, attackIdToName);
  const _decodeAttackGroup = (groupVal, fallbackVal) => decodeAttackGroup(groupVal, fallbackVal, attackGroupIdToName, attackIdToName);
  const _lookupAttackColor = (name) => lookupAttackColor(name, rawColorByAttack, colorByAttack);
  const _lookupAttackGroupColor = (name) => lookupAttackGroupColor(name, rawColorByAttackGroup, colorByAttackGroup);
})();
