import { ingestFiles, getPointsForRange, getManifest } from '../api';

export function wireDemo() {
    const fileInput = document.querySelector<HTMLInputElement>('#files');
    const ingestBtn = document.querySelector<HTMLButtonElement>('#ingest');
    const renderBtn = document.querySelector<HTMLButtonElement>('#render');

    if (!fileInput || !ingestBtn || !renderBtn) return;

    ingestBtn.onclick = async () => {
        const files = Array.from(fileInput.files || []);
        const { manifest } = await ingestFiles(files, {
            tileMs: 60_000,
            hasHeader: true,
            timestampCol: 'timestamp',
            valueCol: 'value',
        });
        console.log('Manifest', manifest);
    };

    renderBtn.onclick = async () => {
        const m = getManifest();
        if (!m) { console.warn('No manifest'); return; }
        // Example visible range: full range
        const arrays = await getPointsForRange(m.tMin, m.tMax);
        console.log('Loaded tiles:', arrays.length, 'first tile len', arrays[0]?.length);
    };
}


