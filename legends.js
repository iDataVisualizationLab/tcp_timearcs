// Legend rendering helpers extracted from sidebar.js
// Provides simple DOM injection for legend panels with a title + items

export function renderInvalidLegend(panelEl, legendItemsHtml, totalText) {
    if (!panelEl) return;
    panelEl.innerHTML = `<div style="font-weight:600; margin-bottom:6px;">${totalText}</div>${legendItemsHtml}`;
}

export function renderClosingLegend(panelEl, legendItemsHtml, totalText) {
    if (!panelEl) return;
    panelEl.innerHTML = `<div style="font-weight:600; margin-bottom:6px;">${totalText}</div>${legendItemsHtml}`;
}

