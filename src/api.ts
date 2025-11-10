import type { TileStore } from './storage/tile-store';
import { createTileStore } from './storage/tile-store';
import type { IngestOptions, Manifest } from './ingest/worker-pool';
import { createIngestSession } from './ingest/worker-pool';

let gTileStore: TileStore | null = null;
let gManifest: Manifest | null = null;

export interface InitResult { manifest: Manifest; }

export async function ingestFiles(files: File[], opts?: IngestOptions): Promise<InitResult> {
    const { session, tileStore } = await createIngestSession(opts);
    gTileStore = tileStore;
    await session.start(files);
    const manifest = await session.finalize();
    gManifest = manifest;
    return { manifest };
}

export function getManifest(): Manifest | null { return gManifest; }

export async function clearCache(): Promise<void> {
    if (!gTileStore) gTileStore = await createTileStore();
    await gTileStore.clearAll();
    gManifest = null;
}

export async function getPointsForRange(tStart: number, tEnd: number, merged = false): Promise<Float64Array[] | Float64Array> {
    if (!gManifest) throw new Error('No manifest; call ingestFiles first');
    if (!gTileStore) throw new Error('TileStore not initialized');
    const tileMs = gManifest.tileMs;
    const tileStart = Math.floor(tStart / tileMs);
    const tileEnd = Math.floor(tEnd / tileMs);
    const bufs = await gTileStore.readRange(tileStart, tileEnd);
    const arrays = bufs.map((b) => new Float64Array(b));
    if (!merged) return arrays;
    // Merge preserving order; tiles are already in ascending tileId
    const totalLen = arrays.reduce((s, a) => s + a.length, 0);
    const out = new Float64Array(totalLen);
    let off = 0;
    for (const a of arrays) { out.set(a, off); off += a.length; }
    return out;
}


