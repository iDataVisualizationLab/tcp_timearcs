// Network TimeArcs visualization
// Input CSV schema: timestamp,length,src_ip,dst_ip,protocol,count
// - timestamp: integer absolute minutes. If very large (>1e6), treated as minutes since Unix epoch.
//   Otherwise treated as relative minutes and displayed as t=.. labels.

(function () {
  const fileInput = document.getElementById('fileInput');
  const statusEl = document.getElementById('status');
  const svg = d3.select('#chart');
  const container = document.getElementById('chart-container');
  const legendEl = document.getElementById('legend');
  const tooltip = document.getElementById('tooltip');

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

  // Initialize mappings, then try a default CSV load
  (async function init() {
    try {
      await Promise.all([
        loadIpMap(),
        loadEventTypeMap(),
        loadColorMapping(),
      ]);
    } catch (_) { /* non-fatal */ }
    // After maps are ready (or failed gracefully), try default CSV
    tryLoadDefaultCsv();
  })();

  // Handle CSV upload
  fileInput?.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    status(`Loading ${file.name} …`);
    try {
      const text = await file.text();
      const rows = d3.csvParse(text.trim());
      const data = rows.map((d, i) => {
        const attackName = decodeAttack(d.attack);
        return {
          idx: i,
          timestamp: toNumber(d.timestamp),
          length: toNumber(d.length),
          src_ip: decodeIp(d.src_ip),
          dst_ip: decodeIp(d.dst_ip),
          protocol: (d.protocol || '').toUpperCase() || 'OTHER',
          count: toNumber(d.count) || 1,
          attack: attackName,
        };
      }).filter(d => isFinite(d.timestamp) && d.src_ip && d.dst_ip);

      if (data.length === 0) {
        status('No valid rows found. Ensure CSV has required columns.');
        clearChart();
        return;
      }
      render(data);
    } catch (err) {
      console.error(err);
      status('Failed to read CSV file.');
      clearChart();
    }
  });

  async function tryLoadDefaultCsv() {
    const defaultPath = './90min_day1_attacks.csv';
    try {
      const res = await fetch(defaultPath, { cache: 'no-store' });
      if (!res.ok) return; // quietly exit if not found
      const text = await res.text();
      const rows = d3.csvParse((text || '').trim());
      const data = rows.map((d, i) => {
        const attackName = decodeAttack(d.attack);
        return {
          idx: i,
          timestamp: toNumber(d.timestamp),
          length: toNumber(d.length),
          src_ip: decodeIp(d.src_ip),
          dst_ip: decodeIp(d.dst_ip),
          protocol: (d.protocol || '').toUpperCase() || 'OTHER',
          count: toNumber(d.count) || 1,
          attack: attackName,
        };
      }).filter(d => isFinite(d.timestamp) && d.src_ip && d.dst_ip);

      if (!data.length) return;
      status(`Loaded default: 90min_day1_attacks.csv (${data.length} rows)`);
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

  function buildLegend(items, colorFn) {
    legendEl.innerHTML = '';
    const frag = document.createDocumentFragment();
    items.forEach(p => {
      const item = document.createElement('div');
      item.className = 'legend-item';
      const sw = document.createElement('div');
      sw.className = 'swatch';
      sw.style.background = colorFn(p);
      const label = document.createElement('span');
      label.textContent = p;
      item.appendChild(sw);
      item.appendChild(label);
      frag.appendChild(item);
    });
    legendEl.appendChild(frag);
  }

  function render(data) {
    // Determine timestamp handling
    const tsMin = d3.min(data, d => d.timestamp);
    const tsMax = d3.max(data, d => d.timestamp);
    const looksAbsolute = tsMin > 1e6; // heuristic: minutes since epoch
    const base = looksAbsolute ? 0 : tsMin; // for relative minutes, normalize to 0

    const toDate = (m) => new Date((looksAbsolute ? m : (m - base)) * 60_000);

    // Aggregate links; then order IPs using the React component's approach:
    // primary-attack grouping, groups ordered by earliest time, nodes within group by force-simulated y
    const links = computeLinks(data); // aggregated per pair per minute
    const nodes = computeNodesByAttackGrouping(links);
    const ips = nodes.map(n => n.name);
    const attacks = Array.from(new Set(links.map(l => l.attack || 'normal'))).sort();

    // Sizing based on number of IPs
    const rowHeight = 18;
    const innerHeight = Math.max(ips.length * rowHeight + 20, 200);
    width = Math.max(container.clientWidth - 16, 800);
    height = margin.top + innerHeight + margin.bottom;
    svg.attr('width', width).attr('height', height);

    const x = d3.scaleTime()
      .domain([toDate(tsMin), toDate(tsMax)])
      .range([margin.left, width - margin.right]);

    const y = d3.scalePoint()
      .domain(ips)
      .range([margin.top, margin.top + innerHeight])
      .padding(0.5);

    // Compute a right-side padding so the largest arc does not get clipped.
    // The horizontal reach of an arc equals its radius = |y2 - y1|/2.
    const maxRadius = d3.max(links, d => {
      const y1 = y(d.source);
      const y2 = y(d.target);
      return Math.abs((y2 - y1) / 2);
    }) || 0;
    const leftPad = 8; // slight offset from the labels
    const rightPad = Math.max(100, maxRadius + 20);
    x.range([margin.left + leftPad, width - margin.right - rightPad]);

    // Width scale by count (fallback to length)
    const maxCount = d3.max(data, d => d.count || 1) || 1;
    const maxLen = d3.max(data, d => d.length || 0) || 0;
    const widthScale = d3.scaleSqrt().domain([1, Math.max(2, maxCount)]).range([0.6, 2.2]);
    const lengthScale = d3.scaleSqrt().domain([0, Math.max(1, maxLen)]).range([0.6, 2.2]);

    const colorForAttack = (name) => lookupAttackColor(name) || defaultColor;

    // Clear
    svg.selectAll('*').remove();

    // Axes — render to sticky top SVG instead of scrolling chart SVG
    const utcTick = d3.utcFormat('%Y-%m-%d %H:%M');
    const xAxis = d3.axisTop(x).ticks(looksAbsolute ? 7 : 7).tickFormat(d => {
      if (looksAbsolute) return utcTick(d);
      const mins = Math.round((d.getTime()) / 60000);
      return `t=${mins}m`;
    });
    const axisSvg = d3.select('#axis-top').attr('width', width).attr('height', 36);
    axisSvg.selectAll('*').remove();
    axisSvg.append('g')
      .attr('transform', 'translate(0,28)')
      .call(xAxis);

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
    const spanData = ips.map(ip => ({ ip, span: ipSpans.get(ip) }));

    rows.selectAll('line')
      .data(spanData)
      .join('line')
      .attr('class', 'row-line')
      .attr('x1', d => d.span ? x(toDate(d.span.min)) : margin.left)
      .attr('x2', d => d.span ? x(toDate(d.span.max)) : margin.left)
      .attr('y1', d => y(d.ip))
      .attr('y2', d => y(d.ip));

    rows.selectAll('text')
      .data(ips)
      .join('text')
      .attr('class', 'ip-label')
      .attr('data-ip', d => d)
      .attr('x', margin.left - 8)
      .attr('y', d => y(d))
      .attr('text-anchor', 'end')
      .attr('dominant-baseline', 'middle')
      .text(d => d);

    // Build legend (attack types)
    buildLegend(attacks, colorForAttack);

    // Arc path generator between two points sharing same x
    function verticalArcPath(xp, y1, y2) {
      const yTop = Math.min(y1, y2);
      const yBot = Math.max(y1, y2);
      const dr = Math.max(1, (yBot - yTop) / 2);
      if (y1 <= y2) {
        return `M${xp},${y1} A${dr},${dr} 0 0,1 ${xp},${y2}`;
      } else {
        return `M${xp},${y1} A${dr},${dr} 0 0,0 ${xp},${y2}`;
      }
    }

    // Draw arcs
    const arcs = svg.append('g');
    const arcPaths = arcs.selectAll('path')
      .data(links)
      .join('path')
      .attr('class', 'arc')
      .attr('stroke', d => colorForAttack(d.attack || 'normal'))
      .attr('stroke-width', d => widthScale(Math.max(1, d.count)))
      .attr('d', d => {
        const xp = x(toDate(d.minute));
        const y1 = y(d.source);
        const y2 = y(d.target);
        return verticalArcPath(xp, y1, y2);
      })
      .on('mouseover', function (event, d) {
        // Highlight hovered arc and endpoints; dim others
        arcPaths.attr('stroke-opacity', p => (p === d ? 1 : 0.05));
        const baseW = widthScale(Math.max(1, d.count));
        d3.select(this).attr('stroke-width', Math.max(3, baseW < 2 ? baseW * 3 : baseW * 1.5)).raise();

        const active = new Set([d.source, d.target]);
        svg.selectAll('.row-line')
          .attr('stroke-opacity', s => s && s.ip && active.has(s.ip) ? 0.8 : 0.1)
          .attr('stroke-width', s => s && s.ip && active.has(s.ip) ? 1 : 0.4);
        svg.selectAll('.ip-label')
          .attr('font-weight', s => active.has(s) ? 'bold' : null)
          .attr('fill', s => active.has(s) ? '#2563eb' : '#343a40');

        // Move the two endpoint labels close to the hovered link's time
        const xp = x(toDate(d.minute));
        svg.selectAll('.ip-label')
          .filter(s => active.has(s))
          .transition()
          .duration(200)
          .attr('x', xp - 8);

        const dt = toDate(d.minute);
        const timeStr = looksAbsolute ? utcTick(dt) : `t=${d.minute - base} min`;
        const content = `${d.source} → ${d.target}<br>` +
          `Attack: ${d.attack || 'normal'}<br>` +
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
        arcPaths.attr('stroke-opacity', 0.8).attr('stroke-width', d => widthScale(Math.max(1, d.count)));
        svg.selectAll('.row-line').attr('stroke-opacity', 1).attr('stroke-width', 0.4);
        svg.selectAll('.ip-label')
          .attr('font-weight', null)
          .attr('fill', '#343a40')
          .transition()
          .duration(200)
          .attr('x', margin.left - 8);
      });

    status(`${data.length} records • ${ips.length} IPs • ${attacks.length} attack types`);
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

  // Compute links: aggregate per (source, target, minute), sum counts, pick dominant attack label
  function computeLinks(data) {
    const keyOf = (a, b, m) => (a < b ? `${a}__${b}__${m}` : `${b}__${a}__${m}`);
    const agg = new Map(); // key -> {source, target, minute, count, attackCounts}
    for (const row of data) {
      const a = row.src_ip, b = row.dst_ip, m = row.timestamp;
      const k = keyOf(a, b, m);
      let rec = agg.get(k);
      if (!rec) {
        rec = { source: a < b ? a : b, target: a < b ? b : a, minute: m, count: 0, attackCounts: new Map() };
        agg.set(k, rec);
      }
      const c = (row.count || 1);
      rec.count += c;
      const att = (row.attack || 'normal');
      rec.attackCounts.set(att, (rec.attackCounts.get(att) || 0) + c);
    }
    // Choose dominant attack per aggregated link
    const links = [];
    for (const rec of agg.values()) {
      let bestAttack = 'normal', bestCnt = -1;
      for (const [att, c] of rec.attackCounts.entries()) {
        if (c > bestCnt) { bestCnt = c; bestAttack = att; }
      }
      links.push({ source: rec.source, target: rec.target, minute: rec.minute, count: rec.count, attack: bestAttack });
    }
    // Sort chronologically then by strength for deterministic rendering
    links.sort((a, b) => (a.minute - b.minute) || (b.count - a.count) || a.source.localeCompare(b.source));
    return links;
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

    // Run a small force simulation to get a natural vertical ordering
    const sim = d3.forceSimulation(simNodes)
      .force('link', d3.forceLink(simLinks).id(d=>d.id).strength(0.1))
      .force('charge', d3.forceManyBody().strength(-40))
      .force('y', d3.forceY(0).strength(0.05))
      .stop();
    for (let i=0;i<200;i++) sim.tick();
    const yMap = new Map(simNodes.map(n=>[n.id, n.y||0]));

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
    return nodes;
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
    }
    return v; // fallback to original string
  }

  async function loadIpMap() {
    try {
      const res = await fetch('./ip_map.json', { cache: 'no-store' });
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
      console.warn('Failed to load ip_map.json; will display raw values.', err);
      ipIdToAddr = null;
      ipMapLoaded = false;
      // Leave status untouched if user is already loading data; otherwise hint.
      if (statusEl && (!statusEl.textContent || /Waiting/i.test(statusEl.textContent))) {
        status('ip_map.json not loaded. Raw src/dst will be shown.');
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
})();
