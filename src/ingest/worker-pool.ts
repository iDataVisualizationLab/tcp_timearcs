import type { TileStore } from '../storage/tile-store';
import { createTileStore } from '../storage/tile-store';
import type {
    AggregatorConfig,
    AggregatorInit,
    AggregatorFinalize,
    AggregatorManifestMessage,
    ErrorMessage,
    Manifest,
    ParseWorkerOptions,
    ParseWorkerStart,
    PersistAppendAck,
    PersistAppendRequest,
} from './worker-messages';
import { WORKER_PROTOCOL_VERSION } from './worker-messages';

export interface IngestOptions {
    tileMs?: number;                   // default 60000
    maxPointsPerFlush?: number;       // default 50_000
    hasHeader?: boolean;              // default true
    delimiter?: string;               // default ','
    timestampCol?: number | string;   // default 0
    valueCol?: number | string;       // default 1
    rowMap?: (cols: string[]) => { t: number; y: number } | null; // not transferrable to workers; for future extension
    numWorkers?: number;              // default: navigator.hardwareConcurrency-1 or 2
}

export interface IngestSession {
    start(files: File[]): Promise<void>;
    finalize(): Promise<Manifest>;
    onProgress(cb: (p: { fileIndex: number; bytes: number; rows: number }) => void): void;
}

export async function createIngestSession(opts?: IngestOptions): Promise<{ session: IngestSession; tileStore: TileStore; }> {
    const tileStore = await createTileStore();

    const tileMs = opts?.tileMs ?? 60_000;
    const maxPointsPerFlush = opts?.maxPointsPerFlush ?? 50_000;
    const numWorkers = opts?.numWorkers ?? Math.max(2, (navigator.hardwareConcurrency || 4) - 1);

    const aggregator = new Worker(new URL('./aggregate-worker.ts', import.meta.url), { type: 'module' } as any);
    const parseWorkers: Worker[] = Array.from({ length: numWorkers }, () => new Worker(new URL('./parse-worker.ts', import.meta.url), { type: 'module' } as any));

    const progressHandlers = new Set<(p: { fileIndex: number; bytes: number; rows: number }) => void>();

    // Persist proxy port
    const persistChannel = new MessageChannel();
    // main listens on port1 for persist requests
    persistChannel.port1.onmessage = async (evt: MessageEvent<PersistAppendRequest>) => {
        const m = evt.data;
        if (!m || m.type !== 'persistAppend') return;
        try {
            await tileStore.append(m.tileId, m.payload);
            const ack: PersistAppendAck = { type: 'persistAck', requestId: m.requestId };
            persistChannel.port1.postMessage(ack);
        } catch (err) {
            console.warn('[Ingest] persist append failed, this may cause data loss', err);
            const ack: PersistAppendAck = { type: 'persistAck', requestId: m.requestId };
            persistChannel.port1.postMessage(ack);
        }
    };

    // Connect parse workers with aggregator via per-worker channel
    const parserChannels: MessageChannel[] = parseWorkers.map(() => new MessageChannel());

    const initMsg: AggregatorInit = {
        type: 'init',
        config: { tileMs, maxPointsPerFlush, maxPendingWrites: 8 },
        persistPort: persistChannel.port2,
        parserPorts: parserChannels.map((c) => c.port2),
    };
    aggregator.postMessage(initMsg, [persistChannel.port2, ...parserChannels.map((c) => c.port2)]);

    let finalizeResolve: ((m: Manifest) => void) | null = null;
    let finalizeReject: ((e: any) => void) | null = null;
    let manifest: Manifest | null = null;

    aggregator.onmessage = (evt: MessageEvent<AggregatorManifestMessage | ErrorMessage>) => {
        const m = evt.data as any;
        if (!m) return;
        if (m.type === 'manifest') {
            manifest = m.manifest;
            finalizeResolve && finalizeResolve(m.manifest);
            finalizeResolve = finalizeReject = null;
        } else if (m.type === 'error') {
            finalizeReject && finalizeReject(new Error(m.message));
        }
    };

    const session: IngestSession = {
        async start(files: File[]): Promise<void> {
            await tileStore.clearAll();
            // Wire per-worker progress and send start commands round-robin
            parseWorkers.forEach((w, i) => {
                w.onmessage = (evt: MessageEvent<any>) => {
                    const d = evt.data;
                    if (d?.type === 'progress') {
                        for (const cb of progressHandlers) cb({ fileIndex: d.fileIndex, bytes: d.bytes, rows: d.rows });
                    } else if (d?.type === 'error') {
                        console.error('[ParseWorker error]', d.message);
                    }
                };
            });

            const options: ParseWorkerOptions = {
                delimiter: opts?.delimiter ?? ',',
                hasHeader: opts?.hasHeader ?? true,
                timestampCol: opts?.timestampCol ?? 0,
                valueCol: opts?.valueCol ?? 1,
                tileMs,
                batchPoints: 10_000,
            };

            let idx = 0;
            for (const file of files) {
                const workerIdx = idx % parseWorkers.length;
                const w = parseWorkers[workerIdx];
                const ch = parserChannels[workerIdx];
                const startMsg: ParseWorkerStart = {
                    type: 'start',
                    fileIndex: idx,
                    fileName: file.name,
                    file,
                    options,
                    aggregatorPort: ch.port1,
                } as any;
                w.postMessage(startMsg, [ch.port1, file]);
                idx++;
            }
        },
        finalize(): Promise<Manifest> {
            return new Promise<Manifest>((resolve, reject) => {
                finalizeResolve = resolve;
                finalizeReject = reject;
                const f: AggregatorFinalize = { type: 'finalize' };
                aggregator.postMessage(f);
            });
        },
        onProgress(cb) {
            progressHandlers.add(cb);
        },
    };

    return { session, tileStore };
}

export type { Manifest } from './worker-messages';


