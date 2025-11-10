/**
 * Integration module for folder-based loading with existing visualization
 * Bridges the FolderLoader with the ip_bar_diagram visualization
 */

import { folderLoader } from './folder_loader.js';

// Store current state
let currentMode = 'csv'; // 'csv' or 'folder'
let selectedIPs = [];
let currentFlowsIndex = [];

/**
 * Initialize folder integration
 */
export function initFolderIntegration() {
    console.log('Initializing folder integration...');
    
    // Wire up data source radio buttons
    const csvRadio = document.getElementById('dataSourceCSV');
    const folderRadio = document.getElementById('dataSourceFolder');
    const csvSection = document.getElementById('csvSourceSection');
    const folderSection = document.getElementById('folderSourceSection');
    
    csvRadio.addEventListener('change', () => {
        if (csvRadio.checked) {
            currentMode = 'csv';
            csvSection.style.display = 'block';
            folderSection.style.display = 'none';
        }
    });
    
    folderRadio.addEventListener('change', () => {
        if (folderRadio.checked) {
            currentMode = 'folder';
            csvSection.style.display = 'none';
            folderSection.style.display = 'block';
        }
    });
    
    // Wire up open folder button
    const openFolderBtn = document.getElementById('openFolderBtn');
    openFolderBtn.addEventListener('click', handleOpenFolder);
    
    console.log('Folder integration initialized');
}

/**
 * Handle opening a folder
 */
async function handleOpenFolder() {
    try {
        showProgress('Opening folder...', 0);
        
        const result = await folderLoader.openFolder();
        
        if (!result.success) {
            hideProgress();
            if (!result.cancelled) {
                alert('Failed to open folder. Please try again.');
            }
            return;
        }
        
        // Update UI with folder info
        const folderInfo = document.getElementById('folderInfo');
        folderInfo.innerHTML = `
            <strong>Folder:</strong> ${result.folderName}<br>
            <strong>Packets:</strong> ${result.manifest.total_packets.toLocaleString()}<br>
            <strong>Flows:</strong> ${result.manifest.total_flows.toLocaleString()}<br>
            <strong>IPs:</strong> ${result.manifest.unique_ips}
        `;
        
        // Load packets for visualization
        showProgress('Loading packets...', 10);
        const packets = await folderLoader.loadPackets((progress, current, total) => {
            showProgress(`Loading packets: ${current.toLocaleString()} / ${total.toLocaleString()}`, 10 + (progress * 0.6));
        });
        
        // Load flows index
        showProgress('Loading flows index...', 70);
        const flowsIndex = await folderLoader.loadFlowsIndex();
        currentFlowsIndex = flowsIndex;
        
        // Load statistics
        showProgress('Loading statistics...', 80);
        const ipStats = await folderLoader.loadIPStats();
        const flagStats = await folderLoader.loadFlagStats();
        
        hideProgress();
        
        // Trigger visualization with loaded data
        console.log('Triggering visualization with folder data...');
        triggerVisualizationFromFolder(packets, flowsIndex, ipStats, flagStats, result.manifest);
        
    } catch (err) {
        hideProgress();
        console.error('Error loading folder:', err);
        alert(`Error loading folder: ${err.message}`);
    }
}

/**
 * Show progress indicator
 */
function showProgress(message, percent) {
    const progressDiv = document.getElementById('csvProgress');
    const progressLabel = document.getElementById('csvProgressLabel');
    const progressBar = document.getElementById('csvProgressBar');
    
    progressDiv.style.display = 'block';
    progressLabel.textContent = message;
    progressBar.style.width = `${Math.min(100, Math.max(0, percent))}%`;
}

/**
 * Hide progress indicator
 */
function hideProgress() {
    const progressDiv = document.getElementById('csvProgress');
    progressDiv.style.display = 'none';
}

/**
 * Trigger visualization from folder data
 * This function bridges folder data to the existing visualization
 */
function triggerVisualizationFromFolder(packets, flowsIndex, ipStats, flagStats, manifest) {
    console.log('Setting up visualization with folder data...');
    
    // Create synthetic event-like object to mimic file upload
    const syntheticData = {
        packets: packets,
        flowsIndex: flowsIndex,
        ipStats: ipStats,
        flagStats: flagStats,
        manifest: manifest,
        sourceType: 'folder'
    };
    
    // Dispatch custom event that the visualization can listen to
    const event = new CustomEvent('folderDataLoaded', { 
        detail: syntheticData 
    });
    document.dispatchEvent(event);
    
    console.log('Folder data loaded event dispatched');
}

/**
 * Handle IP selection change (called by visualization)
 * Filters flows by selected IPs
 */
export function onIPSelectionChange(newSelectedIPs) {
    selectedIPs = newSelectedIPs;
    
    if (currentMode !== 'folder' || !currentFlowsIndex.length) {
        return null;
    }
    
    // Filter flows by selected IPs
    const filteredFlows = folderLoader.filterFlowsByIPs(selectedIPs);
    console.log(`Filtered ${filteredFlows.length} flows for selected IPs`);
    
    return filteredFlows;
}

/**
 * Handle time range click on bar chart
 * Shows flow list modal for flows in that time range
 */
export async function onTimeRangeClick(startTime, endTime, selectedIPs) {
    if (currentMode !== 'folder' || !currentFlowsIndex.length) {
        return;
    }
    
    try {
        console.log(`Time range clicked: ${startTime} - ${endTime}`);
        
        // Filter flows by time range AND selected IPs
        let flows = folderLoader.filterFlowsByTimeRange(startTime, endTime);
        
        if (selectedIPs && selectedIPs.length > 0) {
            const ipSet = new Set(selectedIPs);
            flows = flows.filter(flow => 
                ipSet.has(flow.initiator) && ipSet.has(flow.responder)
            );
        }
        
        console.log(`Found ${flows.length} flows in time range`);
        
        if (flows.length === 0) {
            alert('No flows found in the selected time range');
            return;
        }
        
        // Show flow list modal
        showFlowListModal(flows, startTime, endTime);
        
    } catch (err) {
        console.error('Error handling time range click:', err);
        alert(`Error: ${err.message}`);
    }
}

/**
 * Show flow list modal for a time range
 */
function showFlowListModal(flows, startTime, endTime) {
    // Get or create modal elements
    let modal = document.getElementById('timeRangeFlowModal');
    if (!modal) {
        createTimeRangeFlowModal();
        modal = document.getElementById('timeRangeFlowModal');
    }
    
    const modalOverlay = document.getElementById('timeRangeFlowModalOverlay');
    const modalTitle = document.getElementById('timeRangeFlowModalTitle');
    const modalList = document.getElementById('timeRangeFlowModalList');
    const modalCount = document.getElementById('timeRangeFlowModalCount');
    
    // Update title with time range
    const startStr = new Date(startTime / 1000).toLocaleString();
    const endStr = new Date(endTime / 1000).toLocaleString();
    modalTitle.textContent = `Flows in Time Range`;
    modalCount.textContent = `${flows.length} flow(s) • ${startStr} - ${endStr}`;
    
    // Populate flow list
    modalList.innerHTML = '';
    flows.forEach(flow => {
        const flowItem = createFlowListItem(flow);
        modalList.appendChild(flowItem);
    });
    
    // Show modal
    modalOverlay.style.display = 'flex';
    
    // Setup search
    const searchInput = document.getElementById('timeRangeFlowModalSearch');
    searchInput.value = '';
    searchInput.oninput = () => {
        const term = searchInput.value.toLowerCase();
        const items = modalList.querySelectorAll('.flow-item');
        items.forEach(item => {
            const text = item.textContent.toLowerCase();
            item.style.display = text.includes(term) ? '' : 'none';
        });
    };
}

/**
 * Create flow list item element
 */
function createFlowListItem(flow) {
    const div = document.createElement('div');
    div.className = 'flow-item';
    div.style.cssText = 'padding: 10px; margin-bottom: 8px; border: 1px solid #e9ecef; border-radius: 4px; background: #f8f9fa; cursor: pointer;';
    
    const startTime = new Date(flow.startTime / 1000).toLocaleTimeString();
    const duration = ((flow.endTime - flow.startTime) / 1000000).toFixed(2);
    
    div.innerHTML = `
        <div style="font-weight: bold; margin-bottom: 4px; color: #2c3e50;">
            ${flow.initiator}:${flow.initiatorPort} ↔ ${flow.responder}:${flow.responderPort}
        </div>
        <div style="font-size: 11px; color: #666; display: flex; gap: 15px; flex-wrap: wrap;">
            <span>⏱ ${startTime}</span>
            <span>⏳ ${duration}s</span>
            <span>📦 ${flow.totalPackets} pkts</span>
            <span>📊 ${formatBytes(flow.totalBytes)}</span>
            <span class="flow-status ${flow.state}">${flow.state}</span>
        </div>
    `;
    
    // Click to load and show flow details
    div.onclick = async () => {
        await loadAndShowFlowDetails(flow);
    };
    
    return div;
}

/**
 * Format bytes for display
 */
function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

/**
 * Load and show detailed flow information
 */
async function loadAndShowFlowDetails(flowSummary) {
    try {
        console.log(`Loading flow details: ${flowSummary.id}`);
        
        // Show loading indicator
        const loadingDiv = document.createElement('div');
        loadingDiv.style.cssText = 'position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); padding: 20px; background: white; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); z-index: 10000;';
        loadingDiv.textContent = 'Loading flow details...';
        document.body.appendChild(loadingDiv);
        
        // Load full flow data
        const flow = await folderLoader.loadFlow(flowSummary.id);
        
        document.body.removeChild(loadingDiv);
        
        // Show flow details in a new modal or panel
        showFlowDetailsModal(flow);
        
    } catch (err) {
        console.error('Error loading flow details:', err);
        alert(`Error loading flow: ${err.message}`);
    }
}

/**
 * Show detailed flow modal
 */
function showFlowDetailsModal(flow) {
    // Create or get flow details modal
    let modal = document.getElementById('flowDetailsModal');
    if (!modal) {
        createFlowDetailsModal();
        modal = document.getElementById('flowDetailsModal');
    }
    
    const modalOverlay = document.getElementById('flowDetailsModalOverlay');
    const modalContent = document.getElementById('flowDetailsModalContent');
    
    // Build detailed view
    const startTime = new Date(flow.startTime / 1000).toLocaleString();
    const endTime = new Date(flow.endTime / 1000).toLocaleString();
    const duration = ((flow.endTime - flow.startTime) / 1000000).toFixed(3);
    
    modalContent.innerHTML = `
        <h3 style="margin-top: 0; color: #2c3e50;">Flow Details</h3>
        
        <div style="margin-bottom: 20px;">
            <h4>Connection</h4>
            <div style="font-family: monospace; background: #f8f9fa; padding: 10px; border-radius: 4px;">
                ${flow.initiator}:${flow.initiatorPort} ↔ ${flow.responder}:${flow.responderPort}
            </div>
        </div>
        
        <div style="margin-bottom: 20px;">
            <h4>Summary</h4>
            <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="padding: 4px;"><strong>State:</strong></td><td>${flow.state}</td></tr>
                <tr><td style="padding: 4px;"><strong>Close Type:</strong></td><td>${flow.closeType || 'N/A'}</td></tr>
                <tr><td style="padding: 4px;"><strong>Start Time:</strong></td><td>${startTime}</td></tr>
                <tr><td style="padding: 4px;"><strong>End Time:</strong></td><td>${endTime}</td></tr>
                <tr><td style="padding: 4px;"><strong>Duration:</strong></td><td>${duration} seconds</td></tr>
                <tr><td style="padding: 4px;"><strong>Total Packets:</strong></td><td>${flow.totalPackets}</td></tr>
                <tr><td style="padding: 4px;"><strong>Total Bytes:</strong></td><td>${formatBytes(flow.totalBytes)}</td></tr>
            </table>
        </div>
        
        <div style="margin-bottom: 20px;">
            <h4>Phases</h4>
            <div style="display: flex; gap: 20px;">
                <div>
                    <strong>Establishment:</strong> ${flow.phases.establishment.length} packets
                </div>
                <div>
                    <strong>Data Transfer:</strong> ${flow.phases.dataTransfer.length} packets
                </div>
                <div>
                    <strong>Closing:</strong> ${flow.phases.closing.length} packets
                </div>
            </div>
        </div>
        
        <div style="margin-bottom: 20px;">
            <h4>Packets (${flow.packets.length})</h4>
            <div style="max-height: 300px; overflow-y: auto; border: 1px solid #dee2e6; border-radius: 4px;">
                <table style="width: 100%; font-size: 11px; border-collapse: collapse;">
                    <thead style="background: #f8f9fa; position: sticky; top: 0;">
                        <tr>
                            <th style="padding: 6px; text-align: left;">Time</th>
                            <th style="padding: 6px; text-align: left;">Source</th>
                            <th style="padding: 6px; text-align: left;">Dest</th>
                            <th style="padding: 6px; text-align: left;">Flags</th>
                            <th style="padding: 6px; text-align: right;">Length</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${flow.packets.map(pkt => `
                            <tr style="border-bottom: 1px solid #e9ecef;">
                                <td style="padding: 6px;">${new Date(pkt.timestamp / 1000).toLocaleTimeString()}</td>
                                <td style="padding: 6px;">${pkt.src_ip}:${pkt.src_port}</td>
                                <td style="padding: 6px;">${pkt.dst_ip}:${pkt.dst_port}</td>
                                <td style="padding: 6px;">${pkt.flag_type}</td>
                                <td style="padding: 6px; text-align: right;">${pkt.length}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
    
    // Show modal
    modalOverlay.style.display = 'flex';
}

/**
 * Create time range flow modal
 */
function createTimeRangeFlowModal() {
    const overlay = document.createElement('div');
    overlay.id = 'timeRangeFlowModalOverlay';
    overlay.className = 'modal-overlay';
    overlay.style.cssText = 'position: fixed; inset: 0; background: rgba(0,0,0,0.5); display: none; align-items: center; justify-content: center; z-index: 2000;';
    
    const modal = document.createElement('div');
    modal.id = 'timeRangeFlowModal';
    modal.className = 'modal';
    modal.style.cssText = 'background: white; width: min(600px, 90vw); max-height: 80vh; border-radius: 8px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); display: flex; flex-direction: column; overflow: hidden;';
    
    modal.innerHTML = `
        <div class="modal-header" style="padding: 15px; border-bottom: 1px solid #e9ecef;">
            <h3 id="timeRangeFlowModalTitle" style="margin: 0; font-size: 16px; color: #2c3e50;">Flows</h3>
            <div id="timeRangeFlowModalCount" style="margin-top: 4px; color: #6c757d; font-size: 12px;"></div>
        </div>
        <div class="modal-body" style="padding: 15px; overflow: auto; flex: 1;">
            <input type="text" id="timeRangeFlowModalSearch" placeholder="Search flows..." style="width: 100%; padding: 8px; margin-bottom: 10px; border: 1px solid #ced4da; border-radius: 4px;">
            <div id="timeRangeFlowModalList"></div>
        </div>
        <div class="modal-actions" style="padding: 10px 15px; border-top: 1px solid #e9ecef; display: flex; justify-content: flex-end;">
            <button id="timeRangeFlowModalClose" style="padding: 6px 12px; border: 1px solid #ced4da; background: white; border-radius: 4px; cursor: pointer;">Close</button>
        </div>
    `;
    
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    
    // Close button
    document.getElementById('timeRangeFlowModalClose').onclick = () => {
        overlay.style.display = 'none';
    };
    
    // Click outside to close
    overlay.onclick = (e) => {
        if (e.target === overlay) {
            overlay.style.display = 'none';
        }
    };
}

/**
 * Create flow details modal
 */
function createFlowDetailsModal() {
    const overlay = document.createElement('div');
    overlay.id = 'flowDetailsModalOverlay';
    overlay.style.cssText = 'position: fixed; inset: 0; background: rgba(0,0,0,0.5); display: none; align-items: center; justify-content: center; z-index: 3000;';
    
    const modal = document.createElement('div');
    modal.id = 'flowDetailsModal';
    modal.style.cssText = 'background: white; width: min(800px, 90vw); max-height: 90vh; border-radius: 8px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); display: flex; flex-direction: column; overflow: hidden;';
    
    modal.innerHTML = `
        <div id="flowDetailsModalContent" style="padding: 20px; overflow: auto; flex: 1;"></div>
        <div style="padding: 10px 20px; border-top: 1px solid #e9ecef; display: flex; justify-content: flex-end;">
            <button id="flowDetailsModalClose" style="padding: 8px 16px; border: 1px solid #ced4da; background: white; border-radius: 4px; cursor: pointer;">Close</button>
        </div>
    `;
    
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    
    // Close button
    document.getElementById('flowDetailsModalClose').onclick = () => {
        overlay.style.display = 'none';
    };
    
    // Click outside to close
    overlay.onclick = (e) => {
        if (e.target === overlay) {
            overlay.style.display = 'none';
        }
    };
}

// Export for use by visualization
export { currentMode, folderLoader };
