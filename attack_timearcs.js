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

  // User-selected labeling mode: 'attack' or 'attack_group'
  let labelMode = 'attack';
  labelModeRadios.forEach(r => r.addEventListener('change', () => {
    const sel = Array.from(labelModeRadios).find(r=>r.checked);
    labelMode = sel ? sel.value : 'attack';
    if (lastRawCsvRows) {
      render(rebuildDataFromRawRows(lastRawCsvRows));
    }
  }));

  const margin = { top: 40, right: 20, bottom: 30, left: 110 };
  let width = 1200; // updated on render
  let height = 600; // updated on render

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
    const defaultPath = './90min_day1_grouped_attacks.csv';
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
        status(`Loaded default: 90min_day1_attacks.csv (${data.length} valid rows, ${filteredRows} filtered due to missing IP mappings)`);
      } else {
        status(`Loaded default: 90min_day1_attacks.csv (${data.length} rows)`);
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

    // Sizing based on number of IPs (use allIps to ensure enough space)
    const rowHeight = 18;
    const innerHeight = Math.max(allIps.length * rowHeight + 20, 200);
    // Fit width to container
    const availableWidth = container.clientWidth - 16;
    const viewportWidth = Math.max(availableWidth, 800);
    width = viewportWidth;
    height = margin.top + innerHeight + margin.bottom;
    svg.attr('width', width).attr('height', height);

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
    
    // Calculate timeline width to fit container
    const timelineWidth = width - margin.left - margin.right - 16;
    
    console.log('Timeline fitting:', {
      containerWidth: container.clientWidth,
      viewportWidth,
      timelineWidth,
      marginLeft: margin.left,
      marginRight: margin.right
    });
    
    // X scale for timeline that fits in container
    const x = d3.scaleTime()
      .domain([xMinDate, xMaxDate])
      .range([margin.left + 8, margin.left + 8 + timelineWidth]);

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
      .range([0, timelineWidth]);
    
    const utcTick = d3.utcFormat('%Y-%m-%d %H:%M');
    const xAxis = d3.axisTop(axisScale).ticks(looksAbsolute ? 7 : 7).tickFormat(d => {
      if (looksAbsolute) return utcTick(d);
      const relUnits = Math.round((d.getTime()) / unitMs);
      return `t=${relUnits}${unitSuffix}`;
    });
    
    // Create axis SVG that matches the viewport width
    const axisSvg = d3.select('#axis-top')
      .attr('width', width)
      .attr('height', 36);
    axisSvg.selectAll('*').remove();
    
    // Create axis group
    const axisGroup = axisSvg.append('g')
      .attr('transform', `translate(${margin.left + 8}, 28)`)
      .call(xAxis);

    // Utility for safe gradient IDs per link
    const sanitizeId = (s) => (s || '').toString().replace(/[^a-zA-Z0-9_-]+/g, '-');
    const gradIdForLink = (d) => `grad-${sanitizeId(`${d.source}__${d.target}__${d.minute}`)}`;

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
      .attr('y1', d => y(d.ip))
      .attr('y2', d => y(d.ip))
      .style('opacity', 0); // Hidden during force simulation

    // Create labels for all IPs to ensure alignment with arcs
    const ipLabels = rows.selectAll('text')
      .data(allIps)
      .join('text')
      .attr('class', 'ip-label')
      .attr('data-ip', d => d)
      .attr('x', margin.left - 8)
      .attr('y', d => y(d))
      .attr('text-anchor', 'end')
      .attr('dominant-baseline', 'middle')
      .style('cursor', 'pointer')
      .text(d => d);

    // Build legend (attack types)
    buildLegend(attacks, colorForAttack);

    // Arc path generator between two points sharing same x
    function verticalArcPath(xp, y1, y2) {
      // Validate inputs to prevent undefined values in SVG path
      if (xp === undefined || y1 === undefined || y2 === undefined) {
        console.warn('Invalid arc path parameters:', { xp, y1, y2 });
        return 'M0,0 L0,0'; // Return a minimal valid path
      }
      const yTop = Math.min(y1, y2);
      const yBot = Math.max(y1, y2);
      const dr = Math.max(1, (yBot - yTop) / 2);
      if (y1 <= y2) {
        return `M${xp},${y1} A${dr},${dr} 0 0,1 ${xp},${y2}`;
      } else {
        return `M${xp},${y1} A${dr},${dr} 0 0,0 ${xp},${y2}`;
      }
    }

    // Create per-link gradients from grey (source) to attack color (destination)
    const defs = svg.append('defs');
    const neutralGrey = '#9e9e9e';
    const gradients = defs.selectAll('linearGradient')
      .data(links)
      .join('linearGradient')
      .attr('id', d => gradIdForLink(d))
      .attr('gradientUnits', 'userSpaceOnUse')
      .attr('x1', d => x(toDate(d.minute)))
      .attr('x2', d => x(toDate(d.minute)))
      .attr('y1', d => y(d.source))
      .attr('y2', d => y(d.target));

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

    // Draw arcs
    const arcs = svg.append('g');
    const arcPaths = arcs.selectAll('path')
      .data(links)
      .join('path')
      .attr('class', 'arc')
      .attr('data-attack', d => (labelMode === 'attack_group' ? d.attack_group : d.attack) || 'normal')
      .attr('stroke', d => `url(#${gradIdForLink(d)})`)
      .attr('stroke-width', d => widthScale(Math.max(1, d.count)))
      .attr('d', d => {
        const dateFromMinute = toDate(d.minute);
        const xp = x(dateFromMinute);
        const y1 = y(d.source);
        const y2 = y(d.target);
        
        // Validate that x-scale returned valid values
        if (xp === undefined || !isFinite(xp)) {
          console.warn('Invalid x-coordinate for arc:', { 
            minute: d.minute,
            dateFromMinute,
            xp,
            xDomain: [xMinDate, xMaxDate],
            xRange: [margin.left, width - margin.right]
          });
          return 'M0,0 L0,0'; // Return minimal valid path
        }
        
        // Validate that y-scale returned valid values
        if (y1 === undefined || y2 === undefined) {
          console.warn('Invalid y-coordinates for arc:', { 
            source: d.source, 
            target: d.target, 
            y1, 
            y2,
            xp,
            minute: d.minute,
            yDomain: ips,
            sourceInDomain: ips.includes(d.source),
            targetInDomain: ips.includes(d.target)
          });
          return 'M0,0 L0,0'; // Return minimal valid path
        }
        
        return verticalArcPath(xp, y1, y2);
      })
      .on('mouseover', function (event, d) {
        // Highlight hovered arc at 100% opacity, others at 30% (override CSS with inline style)
        arcPaths.style('stroke-opacity', p => (p === d ? 1 : 0.3));
        const baseW = widthScale(Math.max(1, d.count));
        d3.select(this).attr('stroke-width', Math.max(3, baseW < 2 ? baseW * 3 : baseW * 1.5)).raise();

        const active = new Set([d.source, d.target]);
        svg.selectAll('.row-line')
          .attr('stroke-opacity', s => s && s.ip && active.has(s.ip) ? 0.8 : 0.1)
          .attr('stroke-width', s => s && s.ip && active.has(s.ip) ? 1 : 0.4);
        const attackCol = colorForAttack((labelMode==='attack_group'? d.attack_group : d.attack) || 'normal');
        svg.selectAll('.ip-label')
          .attr('font-weight', s => active.has(s) ? 'bold' : null)
          .style('fill', s => active.has(s) ? attackCol : '#343a40');

        // Draw a dot at the source node to indicate direction
        const xpDot = x(toDate(d.minute));
        // Get current Y position of source (works during and after animation)
        const ySource = y(d.source);
        svg.selectAll('.direction-dot').remove();
        svg.append('circle')
          .attr('class', 'direction-dot')
          .attr('cx', xpDot)
          .attr('cy', ySource)
          .attr('r', 3.2)
          .attr('fill', colorForAttack(d.attack || 'normal'))
          .attr('stroke', '#000')
          .attr('stroke-width', 0.6)
          .style('pointer-events', 'none');

        // Move the two endpoint labels close to the hovered link's time and align to arc ends
        const xp = x(toDate(d.minute));
        svg.selectAll('.ip-label')
          .filter(s => active.has(s))
          .transition()
          .duration(200)
          .attr('x', xp - 8)
          .attr('y', s => {
            if (s === d.source) return y(d.source);
            if (s === d.target) return y(d.target);
            return y(s);
          });

        const dt = toDate(d.minute);
        const timeStr = looksAbsolute ? utcTick(dt) : `t=${d.minute - base} ${unitSuffix}`;
        const content = `${d.source} → ${d.target}<br>` +
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
        svg.selectAll('.ip-label')
          .attr('font-weight', null)
          .style('fill', '#343a40')
          .transition()
          .duration(200)
          .attr('x', margin.left - 8)
          .attr('y', s => y(s));
        svg.selectAll('.direction-dot').remove();
      });
    
    // Store arcPaths reference for legend filtering (after all handlers are attached)
    currentArcPaths = arcPaths;
    
    // Apply initial visibility based on visibleAttacks
    updateArcVisibility();

    // Add hover handlers to IP labels to highlight connected arcs
    ipLabels
      .on('mouseover', function (event, hoveredIp) {
        // Find all arcs connected to this IP (as source or target)
        const connectedArcs = links.filter(l => l.source === hoveredIp || l.target === hoveredIp);
        const connectedIps = new Set();
        connectedArcs.forEach(l => {
          connectedIps.add(l.source);
          connectedIps.add(l.target);
        });

        // Highlight connected arcs: full opacity for connected, dim others
        arcPaths.style('stroke-opacity', d => {
          const isConnected = d.source === hoveredIp || d.target === hoveredIp;
          return isConnected ? 1 : 0.2;
        })
        .attr('stroke-width', d => {
          const isConnected = d.source === hoveredIp || d.target === hoveredIp;
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
          .style('fill', s => {
            if (s === hoveredIp) return hoveredColor;
            return connectedIps.has(s) ? '#007bff' : '#343a40';
          });

        // Show tooltip with IP information
        const arcCount = connectedArcs.length;
        const uniqueConnections = new Set();
        connectedArcs.forEach(l => {
          if (l.source === hoveredIp) uniqueConnections.add(l.target);
          if (l.target === hoveredIp) uniqueConnections.add(l.source);
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
          .style('fill', '#343a40');
      });

    // Phase 1: Run force simulation for natural clustering (stabilizes in background)
    status('Stabilizing network layout...');
    
    // Run simulation to completion immediately (not visually)
    const centerX = (margin.left + width - margin.right) / 2;
    const components = simulation._components || [];
    const ipToComponent = simulation._ipToComponent || new Map();
    
    // Initialize nodes based on component membership for better separation
    if (components.length > 1) {
      // Multiple components: space them vertically
      const componentHeight = innerHeight / components.length;
      simNodes.forEach(n => {
        n.x = centerX;
        const compIdx = ipToComponent.get(n.id) || 0;
        // Position each component in its own vertical region
        const componentCenter = margin.top + (compIdx + 0.5) * componentHeight;
        n.y = componentCenter;
        
        // Add a Y force to keep components separated
        simulation.force('y', d3.forceY()
          .y(n => {
            const idx = ipToComponent.get(n.id) || 0;
            return margin.top + (idx + 0.5) * componentHeight;
          })
          .strength(0.2) // Moderate strength to separate components but allow local clustering
        );
      });
    } else {
      // Single component: use original positioning
      simNodes.forEach(n => {
        n.x = centerX;
        const yPos = y(n.id);
        // Ensure we have a valid position - fallback to middle if not in scale
        n.y = (yPos !== undefined && isFinite(yPos)) ? yPos : (margin.top + innerHeight) / 2;
      });
    }
    
    // Run 300 ticks to stabilize
    for (let i = 0; i < 300; i++) {
      simulation.tick();
    }
    simulation.stop();
    
    // Remove the Y force after simulation (it was temporary for component separation)
    simulation.force('y', null);
    
    // Store final positions in yMap, ensuring all are valid
    simNodes.forEach(n => {
      if (n.y !== undefined && isFinite(n.y)) {
        yMap.set(n.id, n.y);
      } else {
        console.warn('Invalid Y position for node:', n.id, n.y);
        yMap.set(n.id, (margin.top + innerHeight) / 2);
      }
    });
    
    // Phase 2: Animate from current positions to sorted timeline positions
    status('Animating to timeline...');
    
    // Ensure sortedIps contains ALL IPs from allIps (same set, just sorted)
    // Sort IPs by their simulated Y positions (only those in nodes have positions)
    const sortedNodes = [...nodes];
    sortedNodes.sort((a, b) => (yMap.get(a.name) || 0) - (yMap.get(b.name) || 0));
    const sortedIpsFromNodes = sortedNodes.map(n => n.name);
    
    // Create a set of all IPs that have simulated positions
    const ipsWithPositions = new Set(sortedIpsFromNodes);
    
    // Build sortedIps: start with sorted nodes, then add remaining IPs from allIps
    // For IPs not in nodes, maintain their original order from allIps
    const sortedIps = [...sortedIpsFromNodes];
    allIps.forEach(ip => {
      if (!ipsWithPositions.has(ip)) {
        sortedIps.push(ip);
      }
    });
    
    // Verify sortedIps contains all IPs from allIps
    const sortedIpsSet = new Set(sortedIps);
    const allIpsSet = new Set(allIps);
    if (sortedIpsSet.size !== allIpsSet.size || ![...allIpsSet].every(ip => sortedIpsSet.has(ip))) {
      console.warn('sortedIps does not match allIps. sortedIps:', sortedIps.length, 'allIps:', allIps.length);
      // Fallback: use allIps in sorted order
      const missingIps = allIps.filter(ip => !sortedIpsSet.has(ip));
      sortedIps.push(...missingIps);
    }
    
    // Create new Y scale for final positions (includes all IPs)
    const finalY = d3.scalePoint()
      .domain(sortedIps)
      .range([margin.top, margin.top + innerHeight])
      .padding(0.5);
    
    const finalSpanData = sortedIps.map(ip => ({ ip, span: ipSpans.get(ip) }));
    
    // Animate everything to timeline (with correct final alignment)
    // Update lines - rebind to sorted data
    rows.selectAll('line')
      .data(finalSpanData, d => d.ip)
      .transition().duration(1200)
      .attr('x1', d => d.span ? x(toDate(d.span.min)) : margin.left)
      .attr('x2', d => d.span ? x(toDate(d.span.max)) : margin.left)
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
        const connectedArcs = links.filter(l => l.source === hoveredIp || l.target === hoveredIp);
        const connectedIps = new Set();
        connectedArcs.forEach(l => {
          connectedIps.add(l.source);
          connectedIps.add(l.target);
        });

        // Highlight connected arcs: full opacity for connected, dim others
        arcPaths.style('stroke-opacity', d => {
          const isConnected = d.source === hoveredIp || d.target === hoveredIp;
          return isConnected ? 1 : 0.2;
        })
        .attr('stroke-width', d => {
          const isConnected = d.source === hoveredIp || d.target === hoveredIp;
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
          .style('fill', s => {
            if (s === hoveredIp) return hoveredColor;
            return connectedIps.has(s) ? '#007bff' : '#343a40';
          });

        // Show tooltip with IP information
        const arcCount = connectedArcs.length;
        const uniqueConnections = new Set();
        connectedArcs.forEach(l => {
          if (l.source === hoveredIp) uniqueConnections.add(l.target);
          if (l.target === hoveredIp) uniqueConnections.add(l.source);
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
          .style('fill', '#343a40');
      });
    
    // Animate labels to final positions
    finalIpLabelsSelection
      .transition().duration(1200)
      .tween('y-text', function(d) {
        const yStart = y(d);
        const yEnd = finalY(d);
        const interp = d3.interpolateNumber(yStart, yEnd);
        const self = d3.select(this);
        return function(t) { self.attr('y', interp(t)); };
      })
      .text(d => d); // Re-apply text in case order changed
    
    // Animate arcs with proper interpolation to final positions
    arcPaths.transition().duration(1200)
      .attrTween('d', function(d) {
        const xp = x(toDate(d.minute));
        // Start at current scale positions; end at finalY
        const y1Start = y(d.source);
        const y2Start = y(d.target);
        const y1End = finalY(d.source) ?? y1Start;
        const y2End = finalY(d.target) ?? y2Start;
        if (!isFinite(xp) || !isFinite(y1End) || !isFinite(y2End)) {
          return function() { return 'M0,0 L0,0'; };
        }
        return function(t) {
          const y1t = y1Start + (y1End - y1Start) * t;
          const y2t = y2Start + (y2End - y2Start) * t;
          return verticalArcPath(xp, y1t, y2t);
        };
      })
      .on('end', (d, i) => {
        // Update gradient to final positions so grey->attack aligns with endpoints
        const xp = x(toDate(d.minute));
        const y1f = finalY(d.source);
        const y2f = finalY(d.target);
        svg.select(`#${gradIdForLink(d)}`)
          .attr('x1', xp)
          .attr('x2', xp)
          .attr('y1', y1f)
          .attr('y2', y2f);
        if (i === 0) {
          // Sync working y scale to finalY and recompute arc paths to lock alignment
          y.domain(sortedIps)
           .range(finalY.range())
           .padding(0.5);
          arcPaths.attr('d', dd => {
            const xp2 = x(toDate(dd.minute));
            const a = y(dd.source);
            const b = y(dd.target);
            return (isFinite(xp2) && isFinite(a) && isFinite(b)) ? verticalArcPath(xp2, a, b) : 'M0,0 L0,0';
          });
          status(`${data.length} records • ${sortedIps.length} IPs • ${attacks.length} ${labelMode==='attack_group' ? 'attack groups' : 'attack types'}`);
        }
      });
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

  // Order nodes like the TSX component:
  // 1) Build force-simulated y for natural local ordering
  // 2) Determine each IP's primary (most frequent) non-normal attack type
  // 3) Order attack groups by earliest time they appear
  // 4) Within each group, order by simulated y; then assign evenly spaced positions later via scale
  function computeNodesByAttackGrouping(links) {
    const ipSet = new Set();
    for (const l of links) { ipSet.add(l.source); ipSet.add(l.target); }

    // Build pair weights ignoring minute to feed simulation
    const pairKey = (a,b)=> a<b?`${a}__${b}`:`${b}__${a}`;
    const pairWeights = new Map();
    for (const l of links) {
      const k = pairKey(l.source,l.target);
      pairWeights.set(k,(pairWeights.get(k)||0)+ (l.count||1));
    }
    const simNodes = Array.from(ipSet).map(id=>({id}));
    const simLinks = Array.from(pairWeights.entries()).map(([k,w])=>{
      const [a,b]=k.split('__'); return {source:a,target:b,value:w};
    });

    // Detect connected components for better separation
    const components = findConnectedComponents(simNodes, simLinks);
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
    // Just initialize the simulation with parameters for visible stabilization
    // Add component-based Y force to separate disconnected components
    const sim = d3.forceSimulation(simNodes)
      .force('link', d3.forceLink(simLinks).id(d=>d.id).strength(0.3).distance(80))
      .force('charge', d3.forceManyBody().strength(-120))
      .force('x', d3.forceX(0).strength(0.02))
      .force('collision', d3.forceCollide().radius(15).strength(0.7)) // Prevent overlap
      .alpha(0.3)
      .alphaDecay(0.02)
      .velocityDecay(0.4)
      .stop();
    
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
