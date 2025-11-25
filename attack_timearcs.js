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

  const margin = { top: 40, right: 20, bottom: 30, left: 110 };
  let width = 1200; // updated on render
  let height = 600; // updated on render

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

  // Default protocol colors
  const protocolColors = new Map([
    ['TCP', '#1f77b4'],
    ['UDP', '#2ca02c'],
    ['ICMP', '#ff7f0e'],
    ['GRE', '#9467bd'],
    ['ARP', '#8c564b'],
    ['DNS', '#17becf'],
  ]);
  const defaultColor = '#6c757d';

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
      await Promise.all([
        loadIpMap(),
        loadEventTypeMap(),
        loadColorMapping(),
        loadAttackGroupMap(),
        loadAttackGroupColorMapping(),
      ]);
    } catch (_) { /* non-fatal */ }
    // After maps are ready (or failed gracefully), try default CSV
    tryLoadDefaultCsv();
  })();

  // Stream-parse a CSV file incrementally to avoid loading entire file into memory
  // Pushes transformed rows directly into combinedData, returns {totalRows, validRows}
  async function processCsvFile(file, combinedData, options = { hasHeader: true, delimiter: ',' }) {
    const hasHeader = options.hasHeader !== false;
    const delimiter = options.delimiter || ',';

    let header = null;
    let totalRows = 0;
    let validRows = 0;

    // Incremental line splitter handling CR/CRLF/LF boundaries
    let carry = '';
    const decoder = new TextDecoder();
    const reader = file.stream().getReader();
    function emitLinesFromChunk(txt, onLine) {
      carry += txt;
      let idx;
      while ((idx = findNextBreak(carry)) >= 0) {
        const line = carry.slice(0, idx);
        onLine(line);
        carry = stripBreakPrefix(carry.slice(idx));
      }
    }
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
    function parseCsvLine(line) {
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
              if (i + 1 < n && line[i + 1] === '"') { val += line.slice(start, i) + '"'; i += 2; start = i; continue; }
              val += line.slice(start, i); i++; break;
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

    function toNum(v) { const n = +v; return isFinite(n) ? n : NaN; }

    function handleRow(cols) {
      if (!cols || cols.length === 0) return;
      totalRows++;
      const obj = header ? Object.fromEntries(header.map((h, i) => [h, cols[i]]))
                         : Object.fromEntries(cols.map((v, i) => [String(i), v]));
      const attackName = decodeAttack(obj.attack);
      const attackGroupName = decodeAttackGroup(obj.attack_group, obj.attack);
      const rec = {
        idx: combinedData.length,
        timestamp: toNum(obj.timestamp),
        length: toNum(obj.length),
        src_ip: decodeIp(obj.src_ip),
        dst_ip: decodeIp(obj.dst_ip),
        protocol: (obj.protocol || '').toUpperCase() || 'OTHER',
        count: toNum(obj.count) || 1,
        attack: attackName,
        attack_group: attackGroupName,
      };
      const hasValidTimestamp = isFinite(rec.timestamp);
      const hasValidSrcIp = rec.src_ip && rec.src_ip !== 'N/A' && !String(rec.src_ip).startsWith('IP_');
      const hasValidDstIp = rec.dst_ip && rec.dst_ip !== 'N/A' && !String(rec.dst_ip).startsWith('IP_');
      if (hasValidTimestamp && hasValidSrcIp && hasValidDstIp) {
        combinedData.push(rec);
        validRows++;
      }
    }

    // Read stream in chunks
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      const txt = decoder.decode(value, { stream: true });
      emitLinesFromChunk(txt, (line) => {
        const s = line.trim();
        if (!s) return;
        if (!header && hasHeader) { header = parseCsvLine(s); return; }
        const cols = parseCsvLine(s);
        handleRow(cols);
      });
    }
    // flush remainder
    if (carry.trim()) {
      const s = carry.trim();
      if (!header && hasHeader) header = parseCsvLine(s); else handleRow(parseCsvLine(s));
    }
    return { fileName: file.name, totalRows, validRows };
  }

  // Transform raw CSV rows to processed data
  function transformRows(rows, startIdx = 0) {
    return rows.map((d, i) => {
      const attackName = decodeAttack(d.attack);
      const attackGroupName = decodeAttackGroup(d.attack_group, d.attack);
      const srcIp = decodeIp(d.src_ip);
      const dstIp = decodeIp(d.dst_ip);
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
      status(`Loading ${files[0].name} …`);
    } else {
      status(`Loading ${files.length} files…`);
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
        status('Warning: IP map not loaded. Some data may be filtered out.');
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
          status(`Failed to load files. ${errors.length} error(s) occurred.`);
        } else {
          status('No valid rows found. Ensure CSV files have required columns and IP mappings are available.');
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
      
      status(statusMsg);
      
      render(combinedData);
    } catch (err) {
      console.error(err);
      status('Failed to read CSV file(s).');
      clearChart();
    }
  });


  // Allow user to upload a custom ip_map JSON (expected format: { "1.2.3.4": 123, ... } OR reverse { "123": "1.2.3.4" })
  ipMapInput?.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    status(`Loading IP map ${file.name} …`);
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
      status(`Custom IP map loaded (${rev.size} entries). Re-rendering…`);
      if (lastRawCsvRows) {
        // rebuild to decode IP ids again
        render(rebuildDataFromRawRows(lastRawCsvRows));
      }
    } catch (err) {
      console.error(err);
      status('Failed to parse IP map JSON.');
    }
  });

  // Allow user to upload a custom event_type_mapping JSON (expected format: { "attack_name": 123, ... } OR reverse { "123": "attack_name" })
  eventMapInput?.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    status(`Loading event type map ${file.name} …`);
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
      status(`Custom event type map loaded (${rev.size} entries). Re-rendering…`);
      if (lastRawCsvRows) {
        // rebuild to decode attack IDs again
        render(rebuildDataFromRawRows(lastRawCsvRows));
      }
    } catch (err) {
      console.error(err);
      status('Failed to parse event type map JSON.');
    }
  });

  // Keep last raw CSV rows so we can rebuild when mappings change
  let lastRawCsvRows = null; // array of raw objects from csvParse

  function rebuildDataFromRawRows(rows){
    return rows.map((d, i) => {
      const attackName = decodeAttack(d.attack);
      const attackGroupName = decodeAttackGroup(d.attack_group, d.attack);
      return {
        idx: i,
        timestamp: toNumber(d.timestamp),
        length: toNumber(d.length),
        src_ip: decodeIp(d.src_ip),
        dst_ip: decodeIp(d.dst_ip),
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
        const attackName = decodeAttack(d.attack);
        const attackGroupName = decodeAttackGroup(d.attack_group, d.attack);
        return {
          idx: i,
          timestamp: toNumber(d.timestamp),
          length: toNumber(d.length),
          src_ip: decodeIp(d.src_ip),
          dst_ip: decodeIp(d.dst_ip),
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
        status('Default CSV loaded but no valid rows found. Check IP mappings.');
        return;
      }
      
      // Report how many rows were filtered out
      const totalRows = rows.length;
      const filteredRows = totalRows - data.length;
      if (filteredRows > 0) {
        status(`Loaded default: set1_first90_minutes.csv (${data.length} valid rows, ${filteredRows} filtered due to missing IP mappings)`);
      } else {
        status(`Loaded default: set1_first90_minutes.csv (${data.length} rows)`);
      }
      
      render(data);
    } catch (err) {
      // ignore if file isn't present; keep waiting for upload
    }
  }

  function toNumber(v) {
    const n = +v; return isFinite(n) ? n : 0;
  }

  function status(msg) { if (statusEl) statusEl.textContent = msg; }

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

  // Function to update all legend items' visual state
  function updateLegendVisualState() {
    const legendItems = legendEl.querySelectorAll('.legend-item');
    legendItems.forEach(item => {
      const attackName = item.getAttribute('data-attack');
      const isVisible = visibleAttacks.has(attackName);
      if (isVisible) {
        item.style.opacity = '1';
        item.style.textDecoration = 'none';
      } else {
        item.style.opacity = '0.3';
        item.style.textDecoration = 'line-through';
      }
    });
  }

  // Function to isolate a single attack (hide all others)
  // If the attack is already isolated (only one visible), show all attacks instead
  function isolateAttack(attackName) {
    // Check if this attack is already isolated (only one visible and it's this one)
    if (visibleAttacks.size === 1 && visibleAttacks.has(attackName)) {
      // Show all attacks (toggle back to showing all)
      const legendItems = legendEl.querySelectorAll('.legend-item');
      visibleAttacks.clear();
      legendItems.forEach(item => {
        visibleAttacks.add(item.getAttribute('data-attack'));
      });
    } else {
      // Clear all visible attacks
      visibleAttacks.clear();
      // Add only the isolated attack
      visibleAttacks.add(attackName);
    }
    // Update arc visibility
    updateArcVisibility();
    // Update all legend items' visual state
    updateLegendVisualState();
  }

  function buildLegend(items, colorFn) {
    legendEl.innerHTML = '';
    const frag = document.createDocumentFragment();
    
    // Initialize all attacks as visible if set is empty
    if (visibleAttacks.size === 0) {
      items.forEach(item => visibleAttacks.add(item));
    }
    
    items.forEach(p => {
      const item = document.createElement('div');
      item.className = 'legend-item';
      item.style.cursor = 'pointer';
      item.style.userSelect = 'none';
      item.setAttribute('data-attack', p);
      
      // Add visual indicator for hidden items
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
      
      // Handle click vs double-click timing
      let lastClickTime = 0;
      let clickTimeout = null;
      
      // Add click handler to toggle visibility (delayed to allow double-click detection)
      item.addEventListener('click', function(e) {
        const attackName = this.getAttribute('data-attack');
        const now = Date.now();
        
        // If this click happened very recently (within 300ms), it's likely part of a double-click
        // Wait a bit to see if dblclick fires
        if (now - lastClickTime < 300) {
          // Likely part of a double-click, ignore this click
          if (clickTimeout) {
            clearTimeout(clickTimeout);
            clickTimeout = null;
          }
          lastClickTime = now;
          return;
        }
        
        lastClickTime = now;
        
        // Clear any pending single-click action
        if (clickTimeout) {
          clearTimeout(clickTimeout);
        }
        
        // Delay single-click action to detect double-click
        clickTimeout = setTimeout(() => {
          clickTimeout = null;
          if (visibleAttacks.has(attackName)) {
            visibleAttacks.delete(attackName);
          } else {
            visibleAttacks.add(attackName);
          }
          updateArcVisibility();
          updateLegendVisualState();
        }, 300); // 300ms delay to detect double-click
      });
      
      // Add double-click handler to isolate attack
      item.addEventListener('dblclick', function(e) {
        e.preventDefault();
        // Clear pending single-click action
        if (clickTimeout) {
          clearTimeout(clickTimeout);
          clickTimeout = null;
        }
        const attackName = this.getAttribute('data-attack');
        isolateAttack(attackName);
        lastClickTime = Date.now();
      });
      
      // Add hover effect
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
    legendEl.appendChild(frag);
  }

  function render(data) {
    // Determine timestamp handling
    const tsMin = d3.min(data, d => d.timestamp);
    const tsMax = d3.max(data, d => d.timestamp);
    // Heuristic timestamp unit detection by magnitude:
    // - Microseconds: > 1e15
    // - Milliseconds: > 1e12 and <= 1e15
    // - Seconds: > 1e9 and <= 1e12
    // - Minutes: > 1e7 and <= 1e9
    // - Hours: > 1e5 and <= 1e7
    // Otherwise: treat as relative values (default unit minutes to preserve legacy)
    const looksLikeMicroseconds = tsMin > 1e15;
    const looksLikeMilliseconds = tsMin > 1e12 && tsMin <= 1e15;
    const looksLikeSeconds = tsMin > 1e9 && tsMin <= 1e12;
    const looksLikeMinutesAbs = tsMin > 1e7 && tsMin <= 1e9;
    const looksLikeHoursAbs = tsMin > 1e5 && tsMin <= 1e7;
    const looksAbsolute = looksLikeMicroseconds || looksLikeMilliseconds || looksLikeSeconds || looksLikeMinutesAbs || looksLikeHoursAbs;
    
    let unit = 'minutes'; // one of: microseconds|milliseconds|seconds|minutes|hours
    if (looksLikeMicroseconds) unit = 'microseconds';
    else if (looksLikeMilliseconds) unit = 'milliseconds';
    else if (looksLikeSeconds) unit = 'seconds';
    else if (looksLikeMinutesAbs) unit = 'minutes';
    else if (looksLikeHoursAbs) unit = 'hours';
    
    const base = looksAbsolute ? 0 : tsMin; // normalize relative timelines to start at 0
    const unitMs = unit === 'microseconds' ? 0.001
                  : unit === 'milliseconds' ? 1
                  : unit === 'seconds' ? 1000
                  : unit === 'minutes' ? 60_000
                  : 3_600_000; // hours
    const unitSuffix = unit === 'seconds' ? 's' : unit === 'hours' ? 'h' : 'm';
    
    console.log('Timestamp debug:', {
      tsMin,
      tsMax,
      looksLikeMicroseconds,
      looksLikeMilliseconds,
      looksAbsolute,
      inferredUnit: unit,
      base,
      sampleTimestamps: data.slice(0, 5).map(d => d.timestamp)
    });

    const toDate = (m) => {
      if (m === undefined || m === null || !isFinite(m)) {
        console.warn('Invalid timestamp in toDate:', m);
        return new Date(0); // Return epoch as fallback
      }
      
      // Convert using detected unit; for absolute series use m as-is, otherwise offset by base
      const val = looksAbsolute ? m : (m - base);
      const ms = unit === 'microseconds' ? (val / 1000)
               : unit === 'milliseconds' ? (val)
               : (val * unitMs);
      const result = new Date(ms);
      
      if (!isFinite(result.getTime())) {
        console.warn('Invalid date result in toDate:', { m, looksAbsolute, unit, base, computedMs: ms });
        return new Date(0); // Return epoch as fallback
      }
      return result;
    };

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
    const simulation = nodeData.simulation;
    const simNodes = nodeData.simNodes;
    const yMap = nodeData.yMap;
    
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
    // main.js uses: height = 780 - margin.top - margin.bottom = 780 (since margin.top=0, margin.bottom=5)
    // Match main.js: use fixed height instead of scaling with number of IPs
    const innerHeight = 780;
    // Fit width to container - like main.js: width accounts for margins
    const availableWidth = container.clientWidth || 1200;
    const viewportWidth = Math.max(availableWidth, 800);
    // Calculate width accounting for margins (like main.js: width = clientWidth - margin.left - margin.right)
    width = viewportWidth - margin.left - margin.right;
    height = margin.top + innerHeight + margin.bottom;

    // Initial SVG size - will be updated after calculating actual arc extents
    svg.attr('width', width + margin.left + margin.right).attr('height', height);

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
    
    // Timeline width is the available width after accounting for left margin offset
    // Like main.js, we use the full width (after margins) for the timeline
    const timelineWidth = width;
    
    console.log('Timeline fitting:', {
      containerWidth: container.clientWidth,
      viewportWidth,
      timelineWidth,
      marginLeft: margin.left,
      marginRight: margin.right
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
    const estimatedStep = allIps.length > 1 ? innerHeight / allIps.length : innerHeight;
    const maxArcRadius = (maxIpIndexDist * estimatedStep) / 2;

    const svgWidth = width + margin.left + margin.right;
    const xStart = margin.left;
    const xEnd = svgWidth - margin.right - maxArcRadius;

    const x = d3.scaleTime()
      .domain([xMinDate, xMaxDate])
      .range([xStart, xEnd]);

    // Calculate base gap for lens calculations
    XGAP_BASE = timelineWidth / (tsMax - tsMin);

    // Initialize lens center to middle of data range
    if (lensCenter === 0 || lensCenter < tsMin || lensCenter > tsMax) {
      lensCenter = (tsMin + tsMax) / 2;
    }

    // Generic 1D lens transform that:
    //  - expands a band around lensCenterNorm by lensingMul
    //  - compresses everything outside that band
    //  - keeps the overall [0,1] interval fixed (0 -> 0, 1 -> 1)
    function applyLens1D(normalized, lensCenterNorm, bandRadiusNorm, magnification) {
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
        // Before lens band: compressed towards 0
        return n * scale;
      } else if (n > b) {
        // After lens band: compressed towards 1
        const base = scale * (a + insideLength * magnification);
        return base + (n - b) * scale;
      } else {
        // Inside lens band: expanded around center
        const base = scale * a;
        return base + (n - a) * magnification * scale;
      }
    }

    // Lens-aware x scale function
    function xScaleLens(timestamp) {
      const minX = xStart;
      const maxX = xEnd;

      // Use horizontal fisheye if enabled
      if (fisheyeEnabled && horizontalFisheyeScale) {
        const fisheyeX = horizontalFisheyeScale.apply(timestamp);
        return Math.max(minX, Math.min(fisheyeX, maxX));
      }

      if (!isLensing) {
        // Even when lensing is off, clamp to ensure arcs don't go out of bounds
        const rawX = x(toDate(timestamp));
        return Math.max(minX, Math.min(rawX, maxX));
      }

      // Safety check for zero range
      if (tsMax === tsMin) {
        const rawX = x(toDate(timestamp));
        return Math.max(minX, Math.min(rawX, maxX));
      }

      // Convert timestamp to normalized position (0 to 1)
      const normalized = (timestamp - tsMin) / (tsMax - tsMin);
      const totalWidth = xEnd - xStart;

      // Lens parameters (matching main.js: numLens = 5 months on each side)
      // For continuous time, approximate 5 months out of ~108 months = ~4.6% on each side
      const lensCenterNorm = (lensCenter - tsMin) / (tsMax - tsMin);
      const bandRadiusNorm = 0.045; // ~4.5% on each side (matching main.js's 5 months out of ~108)

      const position = applyLens1D(normalized, lensCenterNorm, bandRadiusNorm, lensingMul);
      // Map into screen coordinates and clamp to visible timeline so arcs
      // never extend beyond the right edge of the chart.
      const rawX = minX + position * totalWidth;
      return Math.max(minX, Math.min(rawX, maxX));
    }

    // Use allIps for the y scale to ensure all IPs referenced in arcs are included
    const y = d3.scalePoint()
      .domain(allIps)
      .range([margin.top, margin.top + innerHeight])
      .padding(0.5);
    
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
    let minLinkCount = d3.min(links, d => Math.max(1, d.count)) || 1;
    let maxLinkCount = d3.max(links, d => Math.max(1, d.count)) || 1;
    // Guard: log scale requires domain > 0 and non-degenerate
    minLinkCount = Math.max(1, minLinkCount);
    if (maxLinkCount <= minLinkCount) maxLinkCount = minLinkCount + 1;
    const widthScale = d3.scaleLog().domain([minLinkCount, maxLinkCount]).range([1, 4]);
    // Keep lengthScale (unused) for completeness
    const maxLen = d3.max(data, d => d.length || 0) || 0;
    const lengthScale = d3.scaleLinear().domain([0, Math.max(1, maxLen)]).range([0.6, 2.2]);

    const colorForAttack = (name) => {
      if (labelMode === 'attack_group') return lookupAttackGroupColor(name) || lookupAttackColor(name) || defaultColor;
      return lookupAttackColor(name) || lookupAttackGroupColor(name) || defaultColor;
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
      .attr('width', width + margin.left + margin.right)
      .attr('height', 36);
    axisSvg.selectAll('*').remove();
    
    // Create axis group
    const axisGroup = axisSvg.append('g')
      .attr('transform', `translate(${xStart}, 28)`)
      .call(xAxis);

    // Utility for safe gradient IDs per link
    // Use original IP strings (sourceIp/targetIp) for gradient IDs
    const sanitizeId = (s) => (s || '').toString().replace(/[^a-zA-Z0-9_-]+/g, '-');
    const gradIdForLink = (d) => {
      // Use sourceIp/targetIp if available (from linksWithNodes), otherwise fall back to source/target
      const src = d.sourceIp || (typeof d.source === 'string' ? d.source : d.source?.name);
      const tgt = d.targetIp || (typeof d.target === 'string' ? d.target : d.target?.name);
      return `grad-${sanitizeId(`${src}__${tgt}__${d.minute}`)}`;
    };

    // Row labels and span lines: draw per-IP line only from first to last activity
    const rows = svg.append('g');
    // compute first/last minute per IP based on aggregated links
    const ipSpans = new Map(); // ip -> {min, max}
    for (const l of links) {
      for (const ip of [l.source, l.target]) {
        const span = ipSpans.get(ip) || { min: l.minute, max: l.minute };
        if (l.minute < span.min) span.min = l.minute;
        if (l.minute > span.max) span.max = l.minute;
        ipSpans.set(ip, span);
      }
    }
    // Use allIps to ensure all IPs have row lines, matching the labels and arcs
    const spanData = allIps.map(ip => ({ ip, span: ipSpans.get(ip) }));

    rows.selectAll('line')
      .data(spanData)
      .join('line')
      .attr('class', 'row-line')
      .attr('x1', margin.left)
      .attr('x2', margin.left)
      .attr('y1', d => yScaleLens(d.ip))
      .attr('y2', d => yScaleLens(d.ip))
      .style('opacity', 0); // Hidden during force simulation

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
    const ipLabels = rows.selectAll('text')
      .data(allIps)
      .join('text')
      .attr('class', 'ip-label')
      .attr('data-ip', d => d)
      .attr('x', d => {
        // Match main.js: position at xConnected (text-anchor="end" means text ends at this position)
        // In main.js, text has no x offset, it's positioned by group transform at xConnected
        const node = ipToNode.get(d);
        return node && node.xConnected !== undefined ? node.xConnected : margin.left;
      })
      .attr('y', d => {
        // Match main.js: use node's Y position (n.y)
        const node = ipToNode.get(d);
        return node && node.y !== undefined ? node.y : yScaleLens(d);
      })
      .attr('text-anchor', 'end')
      .attr('dominant-baseline', 'middle')
      .style('cursor', 'pointer')
      .text(d => d);

    // Arc path generator matching main.js linkArc function
    // Takes a link object d with d.source and d.target having x/y properties
    function linkArc(d) {
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

    // Create per-link gradients from grey (source) to attack color (destination)
    const defs = svg.append('defs');

    const neutralGrey = '#9e9e9e';
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
        .attr('stop-color', neutralGrey);
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
      })
      .on('mouseover', function (event, d) {
        // Calculate current arc endpoint positions (matching main.js pattern)
        // These positions match exactly how the arc is rendered in attr('d')
        const xp = xScaleLens(d.minute);
        const y1 = yScaleLens(d.sourceNode.name);
        const y2 = yScaleLens(d.targetNode.name);

        // Validate positions
        if (!isFinite(xp) || !isFinite(y1) || !isFinite(y2)) {
          console.warn('Invalid positions for hover:', { xp, y1, y2, minute: d.minute, source: d.sourceNode.name, target: d.targetNode.name });
          return;
        }

        // Highlight hovered arc at 100% opacity, others at 30% (override CSS with inline style)
        arcPaths.style('stroke-opacity', p => (p === d ? 1 : 0.3));
        const baseW = widthScale(Math.max(1, d.count));
        d3.select(this).attr('stroke-width', Math.max(3, baseW < 2 ? baseW * 3 : baseW * 1.5)).raise();

        const active = new Set([d.sourceNode.name, d.targetNode.name]);
        svg.selectAll('.row-line')
          .attr('stroke-opacity', s => s && s.ip && active.has(s.ip) ? 0.8 : 0.1)
          .attr('stroke-width', s => s && s.ip && active.has(s.ip) ? 1 : 0.4);
        const attackCol = colorForAttack((labelMode==='attack_group'? d.attack_group : d.attack) || 'normal');
        const labelSelection = svg.selectAll('.ip-label');
        labelSelection
          .attr('font-weight', s => active.has(s) ? 'bold' : null)
          .style('font-size', s => active.has(s) ? '14px' : null)
          .style('fill', s => active.has(s) ? attackCol : '#343a40')
          // Ensure endpoint labels are visible even if baseline labels are hidden
          .style('opacity', s => {
            if (active.has(s)) return 1;
            // Preserve compressed/normal mode for non-active labels (matching main.js: no vertical lensing)
            if (!labelsCompressedMode) return 1;
            return 0; // Hide labels in compressed mode
          });

        // Move the two endpoint labels close to the hovered link's time and align to arc ends
        // Match main.js line 1042-1043: xStep+xScale(year) for X, n.y for Y
        // In main.js: labels move to link's time X position but keep node's Y position
        svg.selectAll('.ip-label')
          .filter(s => active.has(s))
          .transition()
          .duration(200)
          .attr('x', xp) // xp = xScaleLens(d.minute), equivalent to xStep+xScale(year) in main.js
          .attr('y', s => {
            // Match main.js line 1043: use node's Y position (n.y)
            // Get node object and use its y property (maintained by updateNodePositions)
            const node = ipToNode.get(s);
            if (node && node.y !== undefined) {
              return node.y; // Match main.js: n.y
            }
            // Fallback to scale if node not found
            return yScaleLens(s);
          });

        const dt = toDate(d.minute);
        const timeStr = looksAbsolute ? utcTick(dt) : `t=${d.minute - base} ${unitSuffix}`;
        const content = `${d.sourceNode.name} → ${d.targetNode.name}<br>` +
          (labelMode==='attack_group' ? `Attack Group: ${d.attack_group || 'normal'}<br>` : `Attack: ${d.attack || 'normal'}<br>`) +
          `${timeStr}<br>` +
          `count=${d.count}`;
        showTooltip(event, content);
      })
      .on('mousemove', function (event) {
        // keep tooltip following cursor
        if (tooltip && tooltip.style.display !== 'none') {
          const pad = 10;
          tooltip.style.left = (event.clientX + pad) + 'px';
          tooltip.style.top = (event.clientY + pad) + 'px';
        }
      })
      .on('mouseout', function () {
        hideTooltip();
        // Restore default opacity (use style to override CSS)
        arcPaths.style('stroke-opacity', 0.6)
                .attr('stroke-width', d => widthScale(Math.max(1, d.count)));
        svg.selectAll('.row-line').attr('stroke-opacity', 1).attr('stroke-width', 0.4);
        const labelSelection = svg.selectAll('.ip-label');
        labelSelection
          .attr('font-weight', null)
          .style('font-size', null)
          .style('fill', '#343a40')
          .transition()
          .duration(200)
          .attr('x', s => {
            // Match main.js line 1072-1073: restore to xConnected (strongest connection position)
            const node = ipToNode.get(s);
            return node && node.xConnected !== undefined ? node.xConnected : margin.left;
          })
          .attr('y', s => {
            // Match main.js: use node's Y position (n.y)
            const node = ipToNode.get(s);
            return node && node.y !== undefined ? node.y : yScaleLens(s);
          });

        // Restore opacity according to compressed mode (matching main.js: no vertical lensing)
        labelSelection.style('opacity', s => {
          if (!labelsCompressedMode) return 1;
          return 0; // Hide labels in compressed mode
        });
      });
    
    // Store arcPaths reference for legend filtering (after all handlers are attached)
    currentArcPaths = arcPaths;
    
    // Apply initial visibility based on visibleAttacks
    updateArcVisibility();

    // Add hover handlers to IP labels to highlight connected arcs
    ipLabels
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
        showTooltip(event, content);
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
        hideTooltip();
        // Restore default state
        arcPaths.style('stroke-opacity', 0.6)
                .attr('stroke-width', d => widthScale(Math.max(1, d.count)));
        svg.selectAll('.row-line').attr('stroke-opacity', 1).attr('stroke-width', 0.4);
        svg.selectAll('.ip-label')
          .attr('font-weight', null)
          .style('font-size', null)
          .style('fill', '#343a40');
      });

    // Phase 1: Run force simulation for natural clustering with component separation
    status('Stabilizing network layout...');
    
    // Run simulation to completion immediately (not visually)
    const centerX = (margin.left + width - margin.right) / 2;
    const components = simulation._components || [];
    const ipToComponent = simulation._ipToComponent || new Map();
    
    // Calculate degree (number of connections) for each IP from links
    const ipDegree = new Map();
    linksWithNodes.forEach(l => {
      ipDegree.set(l.sourceNode.name, (ipDegree.get(l.sourceNode.name) || 0) + 1);
      ipDegree.set(l.targetNode.name, (ipDegree.get(l.targetNode.name) || 0) + 1);
    });
    
    // Find the IP with highest degree in each component
    const componentHubIps = new Map(); // compIdx -> ip with highest degree
    components.forEach((comp, compIdx) => {
      let maxDegree = -1;
      let hubIp = null;
      comp.forEach(ip => {
        const degree = ipDegree.get(ip) || 0;
        if (degree > maxDegree) {
          maxDegree = degree;
          hubIp = ip;
        }
      });
      if (hubIp) {
        componentHubIps.set(compIdx, hubIp);
        console.log(`Component ${compIdx} hub IP: ${hubIp} (degree: ${maxDegree})`);
      }
    });

    // Helper: run simulation until kinetic energy stabilizes
    function runUntilConverged(sim, maxIterations = 300, threshold = 0.001) {
      let prevEnergy = Infinity;
      let stableCount = 0;

      for (let i = 0; i < maxIterations; i++) {
        sim.tick();

        // Calculate total kinetic energy
        const energy = sim.nodes().reduce((sum, n) =>
          sum + (n.vx * n.vx + n.vy * n.vy), 0);

        // Check for convergence
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

    // Initialize nodes based on component membership for better separation
    if (components.length > 1) {
      console.log(`Applying force layout separation for ${components.length} components`);
      
      // Calculate component centers and sizes for better spacing
      const componentSizes = components.map(comp => comp.length);
      const totalNodes = componentSizes.reduce((a, b) => a + b, 0);
      const componentSpacing = innerHeight / components.length;
      const minGap = 40; // Minimum gap between components
      
      // Log component sizes for debugging
      components.forEach((comp, idx) => {
        console.log(`Component ${idx}: ${comp.length} nodes`);
      });
      
      // Calculate target Y positions for each component center
      const componentCenters = new Map();
      components.forEach((comp, compIdx) => {
        const componentStart = margin.top + compIdx * componentSpacing;
        const componentCenter = componentStart + componentSpacing / 2;
        componentCenters.set(compIdx, componentCenter);
      });
      
      // Initialize node positions deterministically: place nodes near their component center
      // Sort nodes within each component by degree (descending) for consistent ordering
      const nodesByComponent = new Map();
      simNodes.forEach(n => {
        const compIdx = ipToComponent.get(n.id) || 0;
        if (!nodesByComponent.has(compIdx)) {
          nodesByComponent.set(compIdx, []);
        }
        nodesByComponent.get(compIdx).push(n);
      });
      
      // Sort nodes within each component by degree (descending), then by IP string for stability
      nodesByComponent.forEach((nodeList, compIdx) => {
        nodeList.sort((a, b) => {
          const degreeA = ipDegree.get(a.id) || 0;
          const degreeB = ipDegree.get(b.id) || 0;
          if (degreeB !== degreeA) return degreeB - degreeA; // Higher degree first
          return a.id.localeCompare(b.id); // Then by IP string for consistency
        });
      });
      
      // Initialize positions deterministically based on sorted order
      nodesByComponent.forEach((nodeList, compIdx) => {
        const targetY = componentCenters.get(compIdx) || (margin.top + innerHeight / 2);
        const spread = Math.min(componentSpacing * 0.3, 30);
        const step = nodeList.length > 1 ? spread / (nodeList.length - 1) : 0;
        
        nodeList.forEach((n, idx) => {
          n.x = centerX;
          // Distribute nodes evenly around component center, with hub (first) at center
          if (nodeList.length === 1) {
            n.y = targetY;
          } else {
            const offset = (idx - (nodeList.length - 1) / 2) * step;
            n.y = targetY + offset;
          }
          // Initialize velocities
          n.vx = 0;
          n.vy = 0;
        });
      });
      
      // Stage 1: Strong component separation - push components apart
      // Use a stronger Y force to position components in their vertical regions
      simulation.force('y', d3.forceY()
        .y(n => {
          const compIdx = ipToComponent.get(n.id) || 0;
          return componentCenters.get(compIdx) || (margin.top + innerHeight / 2);
        })
        .strength(1.0) // Very strong to enforce component separation
      );
      
      // Enhanced component separation force: repels nodes from different components
      // This uses a stronger, more effective approach
      const componentSeparationForce = (alpha) => {
        const separationStrength = 1.2; // Increased strength
        const minDistance = 80; // Minimum distance between components
        
        // Compute component centroids for more efficient separation
        const componentCentroids = new Map();
        const componentCounts = new Map();
        simNodes.forEach(n => {
          const compIdx = ipToComponent.get(n.id) || -1;
          if (!componentCentroids.has(compIdx)) {
            componentCentroids.set(compIdx, { x: 0, y: 0 });
            componentCounts.set(compIdx, 0);
          }
          const centroid = componentCentroids.get(compIdx);
          centroid.x += n.x || 0;
          centroid.y += n.y || 0;
          componentCounts.set(compIdx, componentCounts.get(compIdx) + 1);
        });
        
        // Normalize centroids
        componentCentroids.forEach((centroid, compIdx) => {
          const count = componentCounts.get(compIdx);
          if (count > 0) {
            centroid.x /= count;
            centroid.y /= count;
          }
        });
        
        // Apply separation between component centroids
        const compIndices = Array.from(componentCentroids.keys());
        for (let i = 0; i < compIndices.length; i++) {
          for (let j = i + 1; j < compIndices.length; j++) {
            const compA = compIndices[i];
            const compB = compIndices[j];
            const centroidA = componentCentroids.get(compA);
            const centroidB = componentCentroids.get(compB);
            
            const dx = centroidB.x - centroidA.x;
            const dy = centroidB.y - centroidA.y;
            const distance = Math.sqrt(dx * dx + dy * dy) || 1;
            
            // Push components apart if too close
            if (distance < minDistance * 2) {
              const force = (minDistance * 2 - distance) / distance * separationStrength * alpha;
              const fx = (dx / distance) * force;
              const fy = (dy / distance) * force;
              
              // Apply force to all nodes in each component
              simNodes.forEach(n => {
                const compIdx = ipToComponent.get(n.id) || -1;
                if (compIdx === compA) {
                  n.vx = (n.vx || 0) - fx / componentCounts.get(compA);
                  n.vy = (n.vy || 0) - fy * 3.0 / componentCounts.get(compA); // Stronger vertical separation
                } else if (compIdx === compB) {
                  n.vx = (n.vx || 0) + fx / componentCounts.get(compB);
                  n.vy = (n.vy || 0) + fy * 3.0 / componentCounts.get(compB);
                }
              });
            }
          }
        }
        
        // Also apply individual node-level separation for nodes near component boundaries
        for (let i = 0; i < simNodes.length; i++) {
          const nodeA = simNodes[i];
          const compA = ipToComponent.get(nodeA.id) || -1;
          
          for (let j = i + 1; j < simNodes.length; j++) {
            const nodeB = simNodes[j];
            const compB = ipToComponent.get(nodeB.id) || -1;
            
            // Only apply separation force between nodes in different components
            if (compA !== compB) {
              const dx = (nodeB.x || 0) - (nodeA.x || 0);
              const dy = (nodeB.y || 0) - (nodeA.y || 0);
              const distanceSquared = dx * dx + dy * dy;
              const distance = Math.sqrt(distanceSquared) || 1;
              
              // Stronger repulsion for nodes in different components
              if (distance < minDistance * 1.5 && distance > 0) {
                const force = (minDistance * 1.5 - distance) / distance * separationStrength * alpha * 0.5;
                const fx = (dx / distance) * force;
                const fy = (dy / distance) * force;
                
                // Apply stronger vertical separation
                const verticalBoost = 4.0;
                nodeA.vx = (nodeA.vx || 0) - fx;
                nodeA.vy = (nodeA.vy || 0) - fy * verticalBoost;
                nodeB.vx = (nodeB.vx || 0) + fx;
                nodeB.vy = (nodeB.vy || 0) + fy * verticalBoost;
              }
            }
          }
        }
      };
      
      // Component cohesion force: keeps nodes within their component together
      const componentCohesionForce = (alpha) => {
        const cohesionStrength = 0.3;
        
        // Compute component centroids
        const componentCentroids = new Map();
        const componentCounts = new Map();
        simNodes.forEach(n => {
          const compIdx = ipToComponent.get(n.id) || -1;
          if (!componentCentroids.has(compIdx)) {
            componentCentroids.set(compIdx, { x: 0, y: 0 });
            componentCounts.set(compIdx, 0);
          }
          const centroid = componentCentroids.get(compIdx);
          centroid.x += n.x || 0;
          centroid.y += n.y || 0;
          componentCounts.set(compIdx, componentCounts.get(compIdx) + 1);
        });
        
        // Normalize centroids
        componentCentroids.forEach((centroid, compIdx) => {
          const count = componentCounts.get(compIdx);
          if (count > 0) {
            centroid.x /= count;
            centroid.y /= count;
          }
        });
        
        // Attract nodes to their component centroid
        simNodes.forEach(n => {
          const compIdx = ipToComponent.get(n.id) || -1;
          const centroid = componentCentroids.get(compIdx);
          if (centroid) {
            const dx = centroid.x - (n.x || 0);
            const dy = centroid.y - (n.y || 0);
            const distance = Math.sqrt(dx * dx + dy * dy) || 1;
            
            // Only apply if node is far from centroid (to allow internal structure)
            if (distance > 20) {
              const force = Math.min(distance / 50, 1) * cohesionStrength * alpha;
              n.vx = (n.vx || 0) + (dx / distance) * force;
              n.vy = (n.vy || 0) + (dy / distance) * force;
            }
          }
        });
      };
      
      // Hub centering force: pulls the highest-degree IP in each component to the vertical center
      const hubCenteringForce = (alpha) => {
        const hubStrength = 2.0; // Strong force to center hubs
        
        componentHubIps.forEach((hubIp, compIdx) => {
          const hubNode = simNodes.find(n => n.id === hubIp);
          if (!hubNode) return;
          
          const targetY = componentCenters.get(compIdx);
          if (targetY === undefined) return;
          
          // Calculate current Y position
          const currentY = hubNode.y || targetY;
          const dy = targetY - currentY;
          
          // Apply strong vertical force to pull hub toward component center
          // Use a stronger force that scales with distance for better convergence
          const distance = Math.abs(dy);
          if (distance > 0.1) { // Only apply if not already centered
            const force = hubStrength * alpha * Math.min(distance / 50, 1);
            hubNode.vy = (hubNode.vy || 0) + (dy > 0 ? force : -force);
          }
        });
      };
      
      // Register the custom forces with the simulation
      simulation.force('componentSeparation', componentSeparationForce);
      simulation.force('componentCohesion', componentCohesionForce);
      simulation.force('hubCentering', hubCenteringForce);

      // Stage 1: Run simulation with strong component separation
      simulation.alpha(0.3).restart();
      runUntilConverged(simulation, 300, 0.001);
      
      // Stage 2: Reduce component forces and allow internal optimization
      simulation.force('y').strength(0.4); // Reduce Y force strength
      simulation.force('componentSeparation', (alpha) => {
        // Weaker separation in stage 2
        const separationStrength = 0.3;
        const minDistance = 50;
        
        for (let i = 0; i < simNodes.length; i++) {
          const nodeA = simNodes[i];
          const compA = ipToComponent.get(nodeA.id) || -1;
          
          for (let j = i + 1; j < simNodes.length; j++) {
            const nodeB = simNodes[j];
            const compB = ipToComponent.get(nodeB.id) || -1;
            
            if (compA !== compB) {
              const dx = (nodeB.x || 0) - (nodeA.x || 0);
              const dy = (nodeB.y || 0) - (nodeA.y || 0);
              const distance = Math.sqrt(dx * dx + dy * dy) || 1;
              
              if (distance < minDistance && distance > 0) {
                const force = (minDistance - distance) / distance * separationStrength * alpha;
                const fx = (dx / distance) * force;
                const fy = (dy / distance) * force;
                
                const verticalBoost = 2.0;
                nodeA.vx = (nodeA.vx || 0) - fx;
                nodeA.vy = (nodeA.vy || 0) - fy * verticalBoost;
                nodeB.vx = (nodeB.vx || 0) + fx;
                nodeB.vy = (nodeB.vy || 0) + fy * verticalBoost;
              }
            }
          }
        }
      });
      
      // Continue simulation for internal optimization
      simulation.alpha(0.15).restart();
      runUntilConverged(simulation, 200, 0.0005);
    } else {
      // Single component: use original positioning
      const componentCenter = (margin.top + innerHeight) / 2;
      
      // Find hub IP for single component
      let hubIp = null;
      if (components.length === 1 && components[0]) {
        let maxDegree = -1;
        components[0].forEach(ip => {
          const degree = ipDegree.get(ip) || 0;
          if (degree > maxDegree) {
            maxDegree = degree;
            hubIp = ip;
          }
        });
        if (hubIp) {
          console.log(`Single component hub IP: ${hubIp} (degree: ${maxDegree})`);
        }
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
          const spread = Math.min(innerHeight * 0.3, 50);
          const step = spread / (sortedNodes.length - 1);
          const offset = (idx - (sortedNodes.length - 1) / 2) * step;
          n.y = componentCenter + offset;
        }
        n.vx = 0;
        n.vy = 0;
      });
      
      // Add hub centering force for single component
      if (hubIp) {
        const hubCenteringForce = (alpha) => {
          const hubStrength = 1.0;
          const hubNode = simNodes.find(n => n.id === hubIp);
          if (hubNode) {
            const currentY = hubNode.y || componentCenter;
            const dy = componentCenter - currentY;
            const distance = Math.abs(dy);
            if (distance > 0.1) {
              const force = hubStrength * alpha * Math.min(distance / 50, 1);
              hubNode.vy = (hubNode.vy || 0) + (dy > 0 ? force : -force);
            }
          }
        };
        simulation.force('hubCentering', hubCenteringForce);
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
        yMap.set(n.id, (margin.top + innerHeight) / 2);
      }
    });

    // Compact IP positions to eliminate gaps (inspired by detactTimeSeries in main.js)
    // This redistributes IPs evenly across the vertical space while:
    //  - preserving connected-component separation when multiple components exist
    //  - maintaining each component's internal ordering from the force layout
    compactIPPositions(simNodes, yMap, margin.top, innerHeight, components, ipToComponent);

    // Ensure all IPs in allIps have positions in yMap (safety check for any edge cases)
    // This handles any IPs that might not be in simNodes
    let maxY = margin.top + 12;
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
    status('Animating to timeline...');

    // Sort all IPs by their Y positions from force simulation (like main.js)
    const sortedIps = [...allIps];
    sortedIps.sort((a, b) => {
      return (yMap.get(a) || 0) - (yMap.get(b) || 0);
    });

    // Distribute evenly across available height (matching main.js detactTimeSeries)
    // main.js uses: step = Math.min((height-25)/(numNode+1), 15) and y = 12 + i*step
    // In main.js, 'height' is innerHeight (780 - margin.top - margin.bottom) and margin.top=0
    // Match main.js exactly: use fixed max step of 15px, start at y=12 (relative to SVG, so add margin.top)
    const finalYMap = new Map();
    const step = Math.min((innerHeight - 25) / (sortedIps.length + 1), 15);
    for (let i = 0; i < sortedIps.length; i++) {
      finalYMap.set(sortedIps[i], margin.top + 12 + i * step);
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
    const actualXEnd = svgWidth - margin.right - actualMaxArcRadius;
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

    const finalSpanData = sortedIps.map(ip => ({ ip, span: ipSpans.get(ip) }));
    
    // Animate everything to timeline (with correct final alignment)
    // Update lines - rebind to sorted data
    rows.selectAll('line')
      .data(finalSpanData, d => d.ip)
      .transition().duration(1200)
      .attr('x1', d => d.span ? xScaleLens(d.span.min) : margin.left)
      .attr('x2', d => d.span ? xScaleLens(d.span.max) : margin.left)
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
        showTooltip(event, content);
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
        hideTooltip();
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
        return node && node.xConnected !== undefined ? node.xConnected : margin.left;
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

          status(`${data.length} records • ${sortedIps.length} IPs • ${attacks.length} ${labelMode==='attack_group' ? 'attack groups' : 'attack types'}`);

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
      const availableHeight = Math.max(60, height - margin.top - margin.bottom - 25);
      const maxStep = 12; // tighter maximum spacing between rows
      const padding = 0.3;
      const domainSpan = Math.max(1, autoFitDomain.length - 1);
      const desiredSpan = Math.min(availableHeight, domainSpan * maxStep);
      const rangeStart = margin.top + 12;
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
          return node && node.xConnected !== undefined ? node.xConnected : margin.left;
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
          status(`Auto-fit: ${sortedIps.length} IPs${compMsg} with ${(spacingSample || maxStep).toFixed(1)}px spacing`);

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

      // Create custom fisheye scale since D3 fisheye plugin may not be compatible with v7
      // We'll implement a simple Cartesian distortion function
      fisheyeScale = {
        _focus: margin.top + innerHeight / 2,
        _distortion: fisheyeDistortion,
        _domain: [0, ipsToUse.length - 1],
        _range: [margin.top, margin.top + innerHeight],
        _sortedIps: ipsToUse, // Store the sorted order

        focus: function(f) {
          this._focus = f;
          return this;
        },

        distortion: function(d) {
          if (arguments.length === 0) return this._distortion;
          this._distortion = d;
          return this;
        },

        // Apply fisheye distortion to an IP address
        // This implementation maintains monotonicity (order preservation)
        apply: function(ip) {
          const sortedList = this._sortedIps;
          if (!sortedList || sortedList.length === 0) return margin.top;

          // Find index of this IP in the sorted list
          const idx = sortedList.indexOf(ip);
          if (idx === -1) {
            // IP not in sorted list, return original position
            return originalRowPositions.get(ip) || margin.top;
          }

          // Get original Y position from stored positions
          const originalY = originalRowPositions.get(ip);
          if (!originalY) return margin.top;

          // Normalize original Y position to [0, 1] based on actual screen position
          const t = (originalY - margin.top) / innerHeight;

          // Normalize focus to [0, 1]
          const focusY = this._focus;
          const focusT = (focusY - margin.top) / innerHeight;

          const distortion = this._distortion;

          // Calculate the distorted position using a smooth fisheye function
          // that preserves monotonicity
          const distortedT = this.fisheyeDistortion(t, focusT, distortion);

          return margin.top + distortedT * innerHeight;
        },

        // Fisheye distortion function that keeps the focus point fixed
        // Simple formula: multiply distance by distortion factor near focus
        fisheyeDistortion: function(t, focus, distortion) {
          if (distortion <= 1) return t;

          // Distance from focus point
          const delta = t - focus;
          const distance = Math.abs(delta);
          const sign = delta < 0 ? -1 : 1;

          if (distance < 0.0001) {
            // At the focus point, no distortion
            return t;
          }

          // Fisheye effect: points near focus expand, far points compress
          // Use a smooth falloff based on distance
          const effectRadius = 0.5; // Half the range is affected

          // Calculate how much to magnify based on distance from focus
          // Close to focus: multiply by distortion (expand)
          // Far from focus: divide by distortion (compress)
          let scale;
          if (distance < effectRadius) {
            // Inside radius: interpolate from distortion (at focus) to 1 (at radius edge)
            const normalized = distance / effectRadius;
            // Use cosine for smooth interpolation
            const blend = (1 - Math.cos(normalized * Math.PI)) / 2;
            scale = distortion - (distortion - 1) * blend;
          } else {
            // Outside radius: compress more as we go further
            const excessDistance = distance - effectRadius;
            const compressionFactor = 1 / distortion;
            scale = 1 - (1 - compressionFactor) * Math.min(1, excessDistance / (1 - effectRadius));
          }

          // Apply the scale to the distance
          const distorted = focus + sign * distance * scale;
          return Math.max(0, Math.min(1, distorted));
        }
      };

      console.log('Fisheye initialized:', {
        numIps: ipsToUse.length,
        focus: fisheyeScale._focus,
        distortion: fisheyeDistortion,
        sampleOriginalPositions: Array.from(originalRowPositions.entries()).slice(0, 3)
      });

      // Create horizontal fisheye scale for timeline distortion
      horizontalFisheyeScale = {
        _focus: xStart + (xEnd - xStart) / 2, // Middle of timeline
        _distortion: fisheyeDistortion,
        _xStart: xStart,
        _xEnd: xEnd,
        _tsMin: tsMin,
        _tsMax: tsMax,

        focus: function(f) {
          this._focus = f;
          return this;
        },

        distortion: function(d) {
          if (arguments.length === 0) return this._distortion;
          this._distortion = d;
          return this;
        },

        // Apply horizontal fisheye distortion to a timestamp
        apply: function(timestamp) {
          const xStart = this._xStart;
          const xEnd = this._xEnd;
          const tsMin = this._tsMin;
          const tsMax = this._tsMax;
          const totalWidth = xEnd - xStart;

          if (totalWidth <= 0 || tsMax === tsMin) {
            return xStart;
          }

          // Convert timestamp to normalized position [0, 1]
          const t = (timestamp - tsMin) / (tsMax - tsMin);

          // Apply fisheye distortion
          const focusX = this._focus;
          const focusT = (focusX - xStart) / totalWidth;
          const distortion = this._distortion;

          const distortedT = this.fisheyeDistortion(t, focusT, distortion);

          return xStart + distortedT * totalWidth;
        },

        // Fisheye distortion function that keeps the focus point fixed
        // Simple formula: multiply distance by distortion factor near focus
        fisheyeDistortion: function(t, focus, distortion) {
          if (distortion <= 1) return t;

          // Distance from focus point
          const delta = t - focus;
          const distance = Math.abs(delta);
          const sign = delta < 0 ? -1 : 1;

          if (distance < 0.0001) {
            // At the focus point, no distortion
            return t;
          }

          // Fisheye effect: points near focus expand, far points compress
          // Use a smooth falloff based on distance
          const effectRadius = 0.5; // Half the range is affected

          // Calculate how much to magnify based on distance from focus
          // Close to focus: multiply by distortion (expand)
          // Far from focus: divide by distortion (compress)
          let scale;
          if (distance < effectRadius) {
            // Inside radius: interpolate from distortion (at focus) to 1 (at radius edge)
            const normalized = distance / effectRadius;
            // Use cosine for smooth interpolation
            const blend = (1 - Math.cos(normalized * Math.PI)) / 2;
            scale = distortion - (distortion - 1) * blend;
          } else {
            // Outside radius: compress more as we go further
            const excessDistance = distance - effectRadius;
            const compressionFactor = 1 / distortion;
            scale = 1 - (1 - compressionFactor) * Math.min(1, excessDistance / (1 - effectRadius));
          }

          // Apply the scale to the distance
          const distorted = focus + sign * distance * scale;
          return Math.max(0, Math.min(1, distorted));
        }
      };

      console.log('Horizontal fisheye initialized:', {
        xStart,
        xEnd,
        tsMin,
        tsMax,
        distortion: fisheyeDistortion
      });
    }

    // Apply fisheye distortion based on mouse position
    function applyFisheye(mouseX, mouseY) {
      if (!fisheyeEnabled || !fisheyeScale) return;

      // Debug: log focus positions and ranges
      console.log('Applying fisheye:', {
        mouseX,
        mouseY,
        verticalRange: `${margin.top} to ${margin.top + innerHeight}`,
        horizontalRange: `${xStart} to ${xEnd}`,
        verticalFocusNormalized: (mouseY - margin.top) / innerHeight,
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
        .attr('x1', d => d.span ? xScaleLens(d.span.min) : margin.left)
        .attr('x2', d => d.span ? xScaleLens(d.span.max) : margin.left)
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
          return node && node.xConnected !== undefined ? node.xConnected : margin.left;
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

  function showTooltip(evt, html) {
    if (!tooltip) return;
    tooltip.style.display = 'block';
    if (html !== undefined) tooltip.innerHTML = html;
    const pad = 10;
    const x = (evt.pageX != null ? evt.pageX : evt.clientX) + pad;
    const y = (evt.pageY != null ? evt.pageY : evt.clientY) + pad;
    tooltip.style.left = x + 'px';
    tooltip.style.top = y + 'px';
  }
  function hideTooltip() {
    if (!tooltip) return;
    tooltip.style.display = 'none';
  }

  // Build pairwise relationships with per-minute aggregation
  function buildRelationships(data) {
    const pairKey = (a, b) => (a < b ? `${a}__${b}` : `${b}__${a}`);
    const rel = new Map(); // key -> { counts: Map(minute -> sum), max, maxTime, a, b }
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

  // Legacy-style connectivity computation from relationships
  function computeConnectivityFromRelationships(relationships, threshold, allIps) {
    const res = new Map(); // ip -> {max, time}
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

  // Compute links: aggregate per (src_ip -> dst_ip, minute), sum counts, pick dominant attack label
  function computeLinks(data) {
    const keyOf = (src, dst, m) => `${src}__${dst}__${m}`; // keep direction
    const agg = new Map(); // key -> {source, target, minute, count, attackCounts, attackGroupCounts}
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
    // Choose dominant attack per aggregated link
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
    // Sort chronologically then by strength for deterministic rendering
    links.sort((a, b) => (a.minute - b.minute) || (b.count - a.count) || a.source.localeCompare(b.source));
    return links;
  }

  // Detect connected components in the network
  function findConnectedComponents(nodes, links) {
    const ipToIndex = new Map();
    nodes.forEach((n, i) => ipToIndex.set(n.id, i));
    
    // Build adjacency list
    const adj = Array(nodes.length).fill(0).map(() => []);
    for (const link of links) {
      const srcIdx = ipToIndex.get(link.source);
      const tgtIdx = ipToIndex.get(link.target);
      if (srcIdx !== undefined && tgtIdx !== undefined) {
        adj[srcIdx].push(tgtIdx);
        adj[tgtIdx].push(srcIdx);
      }
    }
    
    // DFS to find components
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

  // Compact IP positions to eliminate vertical gaps and minimize arc crossing.
  // When information about connected components is available, we keep each
  // disconnected component in its own contiguous vertical block so that
  // isolated clusters of IPs/links do not get interleaved visually.
  // Similar in spirit to detactTimeSeries() in main.js.
  function compactIPPositions(simNodes, yMap, topMargin, innerHeight, components, ipToComponent) {
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
    const step = Math.min((innerHeight - 25) / (numIPs + 1), 15);

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

    // Don't run simulation here - we'll run it visually during render
    // Just initialize the simulation with parameters similar to main.js for natural clustering
    // The simulation will be configured during render with component-specific forces
    // Note: We set initial positions during render to ensure deterministic behavior
    // Using weaker parameters like main.js: charge(-12), linkDistance(0), gravity(0.01), alpha(0.05)
    // Friction 0.9 in main.js => velocityDecay(0.1) in d3 v4+
    const sim = d3.forceSimulation(simNodes)
      .force('link', d3.forceLink(simLinks).id(d=>d.id).strength(1.0).distance(0)) // Match main.js: Strong links, distance 0
      .force('charge', d3.forceManyBody().strength(-12)) // Match main.js: charge(-12)
      .force('x', d3.forceX(0).strength(0.01)) // Match main.js: gravity(0.01)
      //.force('collision', d3.forceCollide().radius(12).strength(0.5)) // Match main.js: No collision
      .alpha(0.05) // Match main.js: alpha(0.05)
      .alphaDecay(0.02) 
      .velocityDecay(0.1) // Match main.js: friction 0.9 => velocityDecay 0.1
      .stop();
    
    // Initialize all nodes with deterministic positions to avoid D3's random initialization
    // These will be overridden during render, but this ensures no randomness
    simNodes.forEach((n, i) => {
      if (n.x === undefined) n.x = 0;
      if (n.y === undefined) n.y = 0;
      if (n.vx === undefined) n.vx = 0;
      if (n.vy === undefined) n.vy = 0;
    });
    
    // Store component info for use during render
    sim._components = components;
    sim._ipToComponent = ipToComponent;
    
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
    return { nodes, simulation: sim, simNodes, yMap };
  }

  function decodeIp(value) {
    const v = (value ?? '').toString().trim();
    if (!v) return 'N/A';
    // If already looks like dotted quad, return as-is
    if (/^\d+\.\d+\.\d+\.\d+$/.test(v)) return v;
    // If numeric and ip map available, map id -> ip
    const n = Number(v);
    if (Number.isFinite(n) && ipIdToAddr) {
      const ip = ipIdToAddr.get(n);
      if (ip) return ip;
      // If IP ID not found in map, log it and return a placeholder
      console.warn(`IP ID ${n} not found in mapping. Available IDs: ${ipIdToAddr ? ipIdToAddr.size : 0} entries`);
      return `IP_${n}`;
    }
    return v; // fallback to original string
  }

  async function loadIpMap() {
    try {
      const res = await fetch('./full_ip_map.json', { cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const obj = await res.json();
      // obj: { ipString: idNumber }
      const rev = new Map();
      let count = 0;
      for (const [ip, id] of Object.entries(obj)) {
        const num = Number(id);
        if (Number.isFinite(num)) {
          rev.set(num, ip);
          count++;
        }
      }
      ipIdToAddr = rev;
      ipMapLoaded = true;
      status(`IP map loaded (${count} entries). Upload CSV to render.`);
    } catch (err) {
      console.warn('Failed to load full_ip_map.json; will display raw values.', err);
      ipIdToAddr = null;
      ipMapLoaded = false;
      // Leave status untouched if user is already loading data; otherwise hint.
      if (statusEl && (!statusEl.textContent || /Waiting/i.test(statusEl.textContent))) {
        status('full_ip_map.json not loaded. Raw src/dst will be shown.');
      }
    }
  }

  // Decode attack name from CSV value using event_type_mapping.json
  function decodeAttack(value) {
    const v = (value ?? '').toString().trim();
    if (!v) return 'normal';
    // If numeric id and mapping loaded
    const n = Number(v);
    if (Number.isFinite(n) && attackIdToName) {
      return attackIdToName.get(n) || 'normal';
    }
    // If string name, return canonicalized original
    return v;
  }

  function decodeAttackGroup(groupVal, fallbackAttackVal) {
    // If the CSV column missing (undefined/null/empty), gracefully fall back to decoded attack.
    const raw = (groupVal ?? '').toString().trim();
    if (!raw) {
      // fallback: attempt to map via attack->group if we have a mapping of attack ids? (Not specified) just reuse attack
      return decodeAttack(fallbackAttackVal);
    }
    const n = Number(raw);
    if (Number.isFinite(n) && attackGroupIdToName) {
      return attackGroupIdToName.get(n) || decodeAttack(fallbackAttackVal);
    }
    return raw; // assume already a name
  }

  function canonicalizeName(s) {
    return s
      .toLowerCase()
      .replace(/\s+/g, ' ') // collapse spaces
      .replace(/\s*\+\s*/g, ' + ') // normalize plus spacing
      .trim();
  }

  function lookupAttackColor(name) {
    if (!name) return null;
    if (rawColorByAttack && rawColorByAttack.has(name)) return rawColorByAttack.get(name);
    const key = canonicalizeName(name);
    if (colorByAttack && colorByAttack.has(key)) return colorByAttack.get(key);
    // best-effort partial match
    if (colorByAttack) {
      for (const [k, col] of colorByAttack.entries()) {
        if (k.includes(key) || key.includes(k)) return col;
      }
    }
    return null;
  }

  function lookupAttackGroupColor(name) {
    if (!name) return null;
    if (rawColorByAttackGroup && rawColorByAttackGroup.has(name)) return rawColorByAttackGroup.get(name);
    const key = canonicalizeName(name);
    if (colorByAttackGroup && colorByAttackGroup.has(key)) return colorByAttackGroup.get(key);
    if (colorByAttackGroup) {
      for (const [k,col] of colorByAttackGroup.entries()) {
        if (k.includes(key) || key.includes(k)) return col;
      }
    }
    return null;
  }

  async function loadEventTypeMap() {
    try {
      const res = await fetch('./event_type_mapping.json', { cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const obj = await res.json(); // name -> id
      const rev = new Map();
      for (const [name, id] of Object.entries(obj)) {
        const num = Number(id);
        if (Number.isFinite(num)) rev.set(num, name);
      }
      attackIdToName = rev;
    } catch (err) {
      console.warn('Failed to load event_type_mapping.json; attacks will show raw values.', err);
      attackIdToName = null;
    }
  }

  async function loadColorMapping() {
    try {
      const res = await fetch('./color_mapping.json', { cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const obj = await res.json(); // name -> color
      rawColorByAttack = new Map(Object.entries(obj));
      colorByAttack = new Map();
      for (const [name, col] of Object.entries(obj)) {
        colorByAttack.set(canonicalizeName(name), col);
      }
    } catch (err) {
      console.warn('Failed to load color_mapping.json; default colors will be used.', err);
      colorByAttack = null;
      rawColorByAttack = null;
    }
  }

  async function loadAttackGroupMap() {
    try {
      const res = await fetch('./attack_group_mapping.json', { cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const obj = await res.json(); // name -> id or id -> name
      const entries = Object.entries(obj);
      const rev = new Map();
      if (entries.length) {
        let nameToId = 0, idToName = 0;
        for (const [k,v] of entries.slice(0,10)) {
          if (typeof v === 'number') nameToId++;
          if (!isNaN(+k) && typeof v === 'string') idToName++;
        }
        if (nameToId >= idToName) {
          for (const [name,id] of entries) {
            const num = Number(id); if (Number.isFinite(num)) rev.set(num, name);
          }
        } else {
          for (const [idStr,name] of entries) {
            const num = Number(idStr); if (Number.isFinite(num) && typeof name === 'string') rev.set(num, name);
          }
        }
      }
      attackGroupIdToName = rev;
    } catch (err) {
      console.warn('Failed to load attack_group_mapping.json; attack groups may show raw values.', err);
      attackGroupIdToName = null;
    }
  }

  async function loadAttackGroupColorMapping() {
    try {
      const res = await fetch('./attack_group_color_mapping.json', { cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const obj = await res.json(); // name -> color
      rawColorByAttackGroup = new Map(Object.entries(obj));
      colorByAttackGroup = new Map();
      for (const [name,col] of Object.entries(obj)) {
        colorByAttackGroup.set(canonicalizeName(name), col);
      }
    } catch (err) {
      console.warn('Failed to load attack_group_color_mapping.json; default colors will be used for groups.', err);
      colorByAttackGroup = null; rawColorByAttackGroup = null;
    }
  }
})();
