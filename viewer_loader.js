// Simple visualization loader
// This file loads the unified bar diagram module which handles both arc and bar views internally

let visualizationModule = null;

async function loadVisualizationModule() {
    try {
        console.log('Loading unified visualization module...');
        
        // Load the bar diagram module (it handles both arcs and bars internally)
        visualizationModule = await import('./ip_bar_diagram.js');
        
        console.log('Successfully loaded visualization module');
        
        // Initialize the module
        if (visualizationModule.init) {
            visualizationModule.init();
        }
        
    } catch (error) {
        console.error('Failed to load visualization module:', error);
    }
}

function initVisualization() {
    loadVisualizationModule();
}

// Wait for DOM to be ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initVisualization);
} else {
    initVisualization();
}

// Export for potential use by other modules
export { loadVisualizationModule };
