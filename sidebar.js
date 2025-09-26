// Sidebar logic for IP Connection Analysis
// This file contains all logic for the sidebar UI and its event handlers
import { getFlowColors, getInvalidLabels, getInvalidReason, getFlowColor } from './legends.js';

export function initSidebar(options) {
    // options: { onResetView, ... }
    const sidebar = document.getElementById('sidebar');
    if (!sidebar) return;

    const desiredWidth = 340; // px

    // Ensure sidebar fills viewport and scrolls
    sidebar.style.position = 'fixed';
    sidebar.style.top = '0';
    sidebar.style.right = '0';
    sidebar.style.height = '100vh';
    sidebar.style.overflowY = 'auto';
    sidebar.style.width = `${desiredWidth}px`;
    sidebar.style.boxSizing = 'border-box';
    sidebar.style.background = '#fff';
    sidebar.style.borderLeft = '1px solid #e6e6e6';
    sidebar.style.display = 'flex';
    sidebar.style.flexDirection = 'column';
    sidebar.style.zIndex = '100';
    // Leave space for fixed footer button
    sidebar.style.paddingBottom = '72px';

    // Push main content so it doesn't hide behind fixed sidebar
    const applyBodyPadding = () => {
        document.body.style.paddingRight = `${sidebar.getBoundingClientRect().width}px`;
    };
    applyBodyPadding();
    window.addEventListener('resize', applyBodyPadding);

    // Make Reset View button sticky at the bottom
    const resetBtn = document.getElementById('resetView');
    if (resetBtn) {
        // Fix to viewport bottom aligned with sidebar
        resetBtn.style.position = 'fixed';
        resetBtn.style.right = '0';
        resetBtn.style.bottom = '0';
        resetBtn.style.width = `${desiredWidth}px`;
        resetBtn.style.zIndex = '110';
        resetBtn.style.background = '#fff';
        resetBtn.style.borderTop = '1px solid #eee';
        resetBtn.style.padding = '12px 0';
        resetBtn.style.margin = '0';
        resetBtn.style.display = 'block';
        resetBtn.style.textAlign = 'center';
        if (options && typeof options.onResetView === 'function') {
            resetBtn.onclick = options.onResetView;
        }
    }
}

// Sidebar render and update helpers (moved from main file)
export function createIPCheckboxes(uniqueIPs, onChange) {
    const container = document.getElementById('ipCheckboxes');
    if (!container) return;
    container.innerHTML = '';
    uniqueIPs.forEach(ip => {
        const div = document.createElement('div');
        div.style.marginBottom = '5px';
        div.className = 'ip-item';
        div.dataset.ip = ip;
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.id = `ip-${ip.replace(/\./g, '-')}`;
        checkbox.value = ip;
        checkbox.checked = false;
        if (typeof onChange === 'function') {
            checkbox.addEventListener('change', onChange);
        }
        const label = document.createElement('label');
        label.htmlFor = checkbox.id;
        label.textContent = ip;
        label.style.marginLeft = '5px';
        label.style.fontSize = '12px';
        label.style.cursor = 'pointer';
        div.appendChild(checkbox);
        div.appendChild(label);
        container.appendChild(div);
    });
}

export function filterIPList(searchTerm) {
    document.querySelectorAll('.ip-item').forEach(item => {
        const ip = item.dataset.ip || '';
        const matches = ip.toLowerCase().includes((searchTerm || '').toLowerCase());
        item.style.display = matches ? 'block' : 'none';
    });
}

export function filterFlowList(searchTerm) {
    const items = document.querySelectorAll('#flowList .flow-item');
    const term = (searchTerm || '').toLowerCase();
    items.forEach(item => {
        const text = (item.innerText || item.textContent || '').toLowerCase();
        item.style.display = text.includes(term) ? '' : 'none';
    });
}

export function wireSidebarControls(opts) {
    const on = (id, type, handler) => { const el = document.getElementById(id); if (el && handler) el.addEventListener(type, handler); };
    on('ipSearch', 'input', (e) => { if (opts.onIpSearch) opts.onIpSearch(e.target.value); });
    on('selectAllIPs', 'click', () => { if (opts.onSelectAllIPs) opts.onSelectAllIPs(); });
    on('clearAllIPs', 'click', () => { if (opts.onClearAllIPs) opts.onClearAllIPs(); });

    on('flowSearch', 'input', (e) => { if (opts.onFlowSearch) opts.onFlowSearch(e.target.value); });
    on('selectAllFlows', 'click', () => { if (opts.onSelectAllFlows) opts.onSelectAllFlows(); });
    on('clearAllFlows', 'click', () => { if (opts.onClearAllFlows) opts.onClearAllFlows(); });
    on('selectEstablishedFlows', 'click', () => { if (opts.onSelectEstablishedFlows) opts.onSelectEstablishedFlows(); });

    on('showTcpFlows', 'change', (e) => { if (opts.onToggleShowTcpFlows) opts.onToggleShowTcpFlows(e.target.checked); });
    on('showEstablishment', 'change', (e) => { if (opts.onToggleEstablishment) opts.onToggleEstablishment(e.target.checked); });
    on('showDataTransfer', 'change', (e) => { if (opts.onToggleDataTransfer) opts.onToggleDataTransfer(e.target.checked); });
    on('showClosing', 'change', (e) => { if (opts.onToggleClosing) opts.onToggleClosing(e.target.checked); });
    on('showGroundTruth', 'change', (e) => { if (opts.onToggleGroundTruth) opts.onToggleGroundTruth(e.target.checked); });
    on('toggleBinning', 'change', (e) => { if (opts.onToggleBinning) opts.onToggleBinning(e.target.checked); });

    // Render mode radios
    const modeCircles = document.getElementById('renderModeCircles');
    const modeBars = document.getElementById('renderModeBars');
    if (modeCircles && modeBars && opts.onToggleRenderMode) {
        const handler = () => {
            const mode = modeBars.checked ? 'bars' : 'circles';
            opts.onToggleRenderMode(mode);
        };
        modeCircles.addEventListener('change', handler);
        modeBars.addEventListener('change', handler);
    }
}

export function updateFlagStats(packets, classifyFlags, flagColors) {
    const container = document.getElementById('flagStats');
    if (!container) return;
    if (!packets || packets.length === 0) {
        container.innerHTML = '<div style="color: #666;">No data to display</div>';
        return;
    }
    const flagCounts = {};
    packets.forEach(packet => {
        const ft = classifyFlags(packet.flags);
        flagCounts[ft] = (flagCounts[ft] || 0) + 1;
    });
    const sortedFlags = Object.entries(flagCounts).sort(([,a],[,b]) => b - a);
    let html = '';
    sortedFlags.forEach(([flag, count]) => {
        const color = flagColors[flag] || '#95a5a6';
        const hasDefinedColor = Object.prototype.hasOwnProperty.call(flagColors, flag);
        html += `
            <div style="display:flex; align-items:center; margin-bottom:3px; cursor:pointer;" data-flag="${flag}">
                <div style="width:12px; height:12px; background-color:${color}; margin-right:8px; border-radius:2px; ${hasDefinedColor ? '' : 'border:1px solid #666;'}"></div>
                <span>${flag}: ${count.toLocaleString()}</span>
                ${hasDefinedColor ? '' : '<span style="color:#666; font-size:10px; margin-left:5px;">(no color)</span>'}
            </div>`;
    });
    container.innerHTML = html || '<div style="color:#666;">No TCP packets found</div>';
}

export function updateIPStats(packets, flagColors, formatBytes) {
    const container = document.getElementById('ipStats');
    if (!container) return;
    if (!packets || packets.length === 0) {
        container.innerHTML = '<div style="color: #666;">Select IPs to view statistics</div>';
        return;
    }
    const selectedIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')).map(cb => cb.value);
    if (selectedIPs.length === 0) {
        container.innerHTML = '<div style="color: #666;">Select IPs to view statistics</div>';
        return;
    }
    const ipStats = {};
    selectedIPs.forEach(ip => {
        ipStats[ip] = { sent:0, received:0, total:0, bytes_sent:0, bytes_received:0, total_bytes:0, connections:new Set(), flags_sent:{}, flags_received:{} };
        Object.keys(flagColors).forEach(flag => { ipStats[ip].flags_sent[flag]=0; ipStats[ip].flags_received[flag]=0; });
    });
    packets.forEach(p => {
        const flagType = p.flag_type || p.flags;
        const fStr = typeof flagType === 'string' ? flagType : (p.flag_type || '');
        const size = p.length || 0;
        if (ipStats[p.src_ip]) { const s=ipStats[p.src_ip]; s.sent++; s.total++; s.bytes_sent+=size; s.total_bytes+=size; s.connections.add(p.dst_ip); if (s.flags_sent[fStr]!==undefined) s.flags_sent[fStr]++; }
        if (ipStats[p.dst_ip]) { const s=ipStats[p.dst_ip]; s.received++; s.total++; s.bytes_received+=size; s.total_bytes+=size; s.connections.add(p.src_ip); if (s.flags_received[fStr]!==undefined) s.flags_received[fStr]++; }
    });
    const flagsToHtml = (m) => {
        const arr = Object.entries(m).filter(([,c])=>c>0).sort(([,a],[,b])=>b-a);
        if (!arr.length) return '<span style="color:#999; font-style:italic;">None</span>';
        return arr.map(([flag,count])=>`<span style="display:inline-flex; align-items:center; gap:4px; padding:2px 4px; border:1px solid #e9ecef; border-radius:3px; background:#fff;"><span style="width:10px; height:10px; background:${flagColors[flag]||'#bdc3c7'}; border-radius:2px;"></span><span style="font-size:10px; color:#555;">${flag} (${count})</span></span>`).join(' ');
    };
    let html = '<div style="font-weight:bold; margin-bottom:10px; border-bottom:1px solid #eee; padding-bottom:5px;">Selected IP Statistics</div>';
    selectedIPs.forEach(ip=>{
        const s = ipStats[ip];
        const connectionCount = s.connections.size;
        html += `
          <div style="margin-bottom:15px; padding:8px; border:1px solid #e9ecef; border-radius:3px;">
            <div style="font-weight:bold; color:#495057; margin-bottom:8px;">${ip}</div>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:5px; font-size:11px; margin-bottom:8px;">
              <div>Sent: ${s.sent.toLocaleString()}</div>
              <div>Received: ${s.received.toLocaleString()}</div>
              <div>Total: ${s.total.toLocaleString()}</div>
              <div>Connections: ${connectionCount}</div>
              <div>Bytes Sent: ${formatBytes(s.bytes_sent)}</div>
              <div>Bytes Recv: ${formatBytes(s.bytes_received)}</div>
            </div>
            <div style="margin-bottom:5px;"><div style="font-size:10px; color:#666; margin-bottom:3px;">Flags Sent:</div><div style="display:flex; flex-wrap:wrap; gap:3px;">${flagsToHtml(s.flags_sent)}</div></div>
            <div><div style="font-size:10px; color:#666; margin-bottom:3px;">Flags Received:</div><div style="display:flex; flex-wrap:wrap; gap:3px;">${flagsToHtml(s.flags_received)}</div></div>
          </div>`;
    });
    container.innerHTML = html;
}

export function createFlowList(flows, selectedFlowIds, formatBytes, formatTimestamp, exportFlowToCSV, zoomToFlow, updateTcpFlowPacketsGlobal, flowColors = {}) {
    const container = document.getElementById('flowList');
    if (!container) return;
    if (!flows || flows.length === 0) {
        container.innerHTML = '<div style="color:#666; text-align:center; padding:20px;">No flows to display</div>';
        return;
    }
    const sorted = [...flows].sort((a,b)=>a.startTime - b.startTime);

    // Use flow legend helpers from legends.js
    const closeColors = getFlowColors(flowColors);
    const invalidLabels = getInvalidLabels();
    let html = '';
    sorted.forEach(flow => {
        const duration = Math.round((flow.endTime - flow.startTime) / 1000000);
        const { utcTime: startTime } = formatTimestamp(flow.startTime);
        const { utcTime: endTime } = formatTimestamp(flow.endTime);
        const reason = getInvalidReason(flow);
        const color = getFlowColor(flow, flowColors);
        let closeTypeText = '';
        if (reason) {
            const label = invalidLabels[reason] || 'Invalid';
            closeTypeText = `
                <span style="display:inline-flex; align-items:center; gap:6px;">
                    <span style="display:inline-block; width:10px; height:10px; border-radius:2px; background:${color}; border:1px solid #fff; box-shadow:0 0 0 1px rgba(0,0,0,0.08);"></span>
                    <span style="color:#333;">${label}</span>
                </span>`;
        } else if (flow.closeType === 'graceful' || flow.closeType === 'abortive') {
            const label = flow.closeType === 'graceful' ? 'Graceful close' : 'Abortive close';
            closeTypeText = `
                <span style="display:inline-flex; align-items:center; gap:6px;">
                    <span style="display:inline-block; width:10px; height:10px; border-radius:2px; background:${color}; border:1px solid #fff; box-shadow:0 0 0 1px rgba(0,0,0,0.08);"></span>
                    <span style="color:#333;">${label}</span>
                </span>`;
        } else if (flow.establishmentComplete) {
            closeTypeText = '• Still open';
        } else {
            closeTypeText = '• Incomplete';
        }
        html += `
          <div class="flow-item" data-flow-id="${flow.id}" style="border-left: 4px solid ${color};">
            <input type="checkbox" class="flow-checkbox" id="flow-${flow.id}" ${selectedFlowIds.has(String(flow.id)) ? 'checked' : ''}>
            <div class="flow-info">
              <div class="flow-connection">${flow.initiator}:${flow.initiatorPort} ↔ ${flow.responder}:${flow.responderPort}</div>
              <div class="flow-details">
                <span class="flow-status ${flow.state}">${flow.state.replace('_',' ')}</span>
                <span>${flow.totalPackets} packets</span>
                <span>${formatBytes(flow.totalBytes)}</span>
                <span>${duration}s duration</span>
                <span>${closeTypeText}</span>
                <button class="flow-zoom-btn" data-flow-id="${flow.id}" title="Zoom timeline to this flow">🔍 Zoom</button>
                <button class="flow-export-btn" data-flow-id="${flow.id}" style="margin-left:auto; padding:2px 6px; font-size:10px; border:1px solid #ced4da; border-radius:3px; background:#fff; cursor:pointer;">Export CSV</button>
              </div>
              <div style="font-size:10px; color:#999; margin-top:3px;">Start: ${startTime} • End: ${endTime}</div>
            </div>
          </div>`;
    });
    container.innerHTML = html;
    container.querySelectorAll('.flow-export-btn').forEach(btn => btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const flowId = e.currentTarget.dataset.flowId;
        const f = flows.find(x => String(x.id) === String(flowId));
        if (f) exportFlowToCSV(f);
    }));
    container.querySelectorAll('.flow-zoom-btn').forEach(btn => btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const flowId = e.currentTarget.dataset.flowId;
        const f = flows.find(x => String(x.id) === String(flowId));
        if (f) zoomToFlow(f);
    }));
    container.querySelectorAll('.flow-checkbox').forEach(cb => cb.addEventListener('change', (e) => {
        const flowId = e.target.id.replace('flow-','');
        const flowItem = e.target.closest('.flow-item');
        if (e.target.checked) { selectedFlowIds.add(flowId); flowItem.classList.add('selected'); }
        else { selectedFlowIds.delete(flowId); flowItem.classList.remove('selected'); }
        if (typeof updateTcpFlowPacketsGlobal === 'function') updateTcpFlowPacketsGlobal();
    }));
    container.querySelectorAll('.flow-item').forEach(item => item.addEventListener('click', (e) => {
        if (e.target.type !== 'checkbox') item.querySelector('.flow-checkbox').click();
    }));
    selectedFlowIds.forEach(id => { const el = container.querySelector(`[data-flow-id="${id}"]`); if (el) el.classList.add('selected'); });
}

export function updateTcpFlowStats(flows, selectedFlowIds, formatBytes) {
    const container = document.getElementById('tcpFlowStats');
    if (!container) return;
    if (!flows || flows.length === 0) {
        container.innerHTML = 'Select 2 or more IP addresses to view TCP flow statistics';
        container.style.color = '#666';
        return;
    }
    const totalStats = {
        total: flows.length,
        established: flows.filter(f => f.establishmentComplete === true || f.state === 'established' || f.state === 'closed').length,
        withData: flows.filter(f => f.dataTransferStarted === true).length,
        gracefulClose: flows.filter(f => f.closeType === 'graceful').length,
        abortiveClose: flows.filter(f => f.closeType === 'abortive').length,
        invalid: flows.filter(f => f.closeType === 'invalid' || f.state === 'invalid').length,
        totalPackets: flows.reduce((sum, f) => sum + (parseInt(f.totalPackets) || 0), 0),
        totalBytes: flows.reduce((sum, f) => sum + (parseInt(f.totalBytes) || 0), 0)
    };
    const selectedFlows = flows.filter(f => selectedFlowIds.has(String(f.id)));
    const selectedStats = {
        selected: selectedFlows.length,
        established: selectedFlows.filter(f => f.establishmentComplete === true || f.state === 'established' || f.state === 'closed').length,
        withData: selectedFlows.filter(f => f.dataTransferStarted === true).length,
        gracefulClose: selectedFlows.filter(f => f.closeType === 'graceful').length,
        abortiveClose: selectedFlows.filter(f => f.closeType === 'abortive').length,
        invalid: selectedFlows.filter(f => f.closeType === 'invalid' || f.state === 'invalid').length,
        totalPackets: selectedFlows.reduce((sum, f) => sum + (parseInt(f.totalPackets) || 0), 0),
        totalBytes: selectedFlows.reduce((sum, f) => sum + (parseInt(f.totalBytes) || 0), 0)
    };
    let statsHTML = `<strong>${totalStats.total} TCP flow(s) for selected IPs (${selectedStats.selected} checked)</strong><br>`;
    if (totalStats.total > 0) {
        statsHTML += `<div style="margin-top:8px;">`;
        statsHTML += `• Fully established: ${totalStats.established}<br>`;
        statsHTML += `• With data transfer: ${totalStats.withData}<br>`;
        statsHTML += `• Graceful close: ${totalStats.gracefulClose}<br>`;
        statsHTML += `• Abortive close: ${totalStats.abortiveClose}<br>`;
        if (totalStats.invalid > 0) statsHTML += `• <span style="color:#e74c3c;">Invalid connections: ${totalStats.invalid}</span><br>`;
        statsHTML += `• Total packets: ${totalStats.totalPackets.toLocaleString()}<br>`;
        statsHTML += `• Total bytes: ${formatBytes(totalStats.totalBytes)}`;
        statsHTML += `</div>`;
        if (selectedStats.selected > 0) {
            statsHTML += `<div style=\"margin-top:8px; padding-top:8px; border-top:1px solid #eee; color:#007bff;\">`;
            statsHTML += `<strong>Checked flows (${selectedStats.selected}):</strong><br>`;
            statsHTML += `• Packets: ${selectedStats.totalPackets.toLocaleString()}, Bytes: ${formatBytes(selectedStats.totalBytes)}`;
            statsHTML += `</div>`;
        }
    } else {
        statsHTML += `<div style="color:#999; font-style:italic; margin-top:5px;">No flows match selected IP addresses</div>`;
    }
    container.innerHTML = statsHTML;
    container.style.color = '#27ae60';
}

export function updateGroundTruthStatsUI(html, ok=true) {
    const container = document.getElementById('groundTruthStats');
    if (!container) return;
    container.innerHTML = html;
    container.style.color = ok ? '#27ae60' : '#e74c3c';
}

