/// <reference path="../types/env.d.ts" />
import type {
    AggregatorConfig,
    AggregatorFinalize,
    AggregatorInit,
    AggregatorManifestMessage,
    AggregatorToParser,
    MainToAggregator,
    ParserToAggregator,
    PersistAppendAck,
    PersistAppendRequest,
    PersistPortFromAggregator,
    PersistPortToAggregator,
    RowBatchMessage,
    Manifest,
    ErrorMessage,
} from './worker-messages';
import { WORKER_PROTOCOL_VERSION } from './worker-messages';

// Aggregator worker: collects row batches from parse workers, tiles by time, flushes tiles to persistent storage via main-thread proxy

type TileBuffer = number[]; // staging before flush

const ctx: DedicatedWorkerGlobalScope = self as any;

let config: AggregatorConfig = {
    tileMs: 60_000,
    maxPointsPerFlush: 50_000,
    maxPendingWrites: 8,
};

let persistPort: MessagePort | null = null;
let parserPorts: MessagePort[] = [];

const tileBuffers = new Map<number, TileBuffer>();
let pendingWrites = 0;
let requestIdSeq = 1;
const pendingAcks = new Map<number, (v: void) => void>();

// Stats
let tMin = Number.POSITIVE_INFINITY;
let tMax = Number.NEGATIVE_INFINITY;
let yMin = Number.POSITIVE_INFINITY;
let yMax = Number.NEGATIVE_INFINITY;
let count = 0;

function tileIdFor(t: number): number {
    return Math.floor(t / config.tileMs);
}

async function flushTile(tileId: number): Promise<void> {
    const arr = tileBuffers.get(tileId);
    if (!arr || arr.length === 0) return;
    // Convert to Float64Array for transfer
    const f64 = new Float64Array(arr);
    tileBuffers.set(tileId, []);
    if (!persistPort) return; // shouldn't happen after init
    const reqId = requestIdSeq++;
    const payload = f64.buffer;
    pendingWrites++;
    const p = new Promise<void>((resolve) => pendingAcks.set(reqId, resolve));
    const msg: PersistAppendRequest = { type: 'persistAppend', requestId: reqId, tileId, payload };
    persistPort.postMessage(msg, [payload]);
    // Backpressure control
    maybeThrottleParsers();
    await p;
}

function maybeThrottleParsers(): void {
    if (pendingWrites > (config.maxPendingWrites || 8)) {
        broadcastToParsers({ type: 'throttle' });
    } else if (pendingWrites <= (config.maxPendingWrites || 8) - 2) {
        broadcastToParsers({ type: 'resume' });
    }
}

function broadcastToParsers(msg: AggregatorToParser) {
    for (const port of parserPorts) port.postMessage(msg);
}

async function handleRowBatch(msg: RowBatchMessage) {
    const points = msg.points; // [t0,y0,...]
    const len = points.length;
    for (let i = 0; i < len; i += 2) {
        const t = points[i];
        const y = points[i + 1];
        // stats
        if (t < tMin) tMin = t;
        if (t > tMax) tMax = t;
        if (y < yMin) yMin = y;
        if (y > yMax) yMax = y;
        count++;
        // tile
        const tid = tileIdFor(t);
        let buf = tileBuffers.get(tid);
        if (!buf) {
            buf = [];
            tileBuffers.set(tid, buf);
        }
        buf.push(t, y);
        if (buf.length >= config.maxPointsPerFlush * 2) {
            // flush without awaiting to keep processing fast; however we must sequence acks to control backpressure
            // We queue the flush promise but do not await it here; the pendingWrites accounting + throttle handles pressure
            // eslint-disable-next-line @typescript-eslint/no-floating-promises
            flushTile(tid);
        }
    }
}

async function flushAll(): Promise<void> {
    const toFlush = Array.from(tileBuffers.keys());
    for (const tid of toFlush) {
        await flushTile(tid);
    }
}

function makeManifest(): Manifest {
    return {
        tMin: Number.isFinite(tMin) ? tMin : NaN,
        tMax: Number.isFinite(tMax) ? tMax : NaN,
        yMin: Number.isFinite(yMin) ? yMin : NaN,
        yMax: Number.isFinite(yMax) ? yMax : NaN,
        count,
        tileMs: config.tileMs,
        version: WORKER_PROTOCOL_VERSION,
    };
}

function handleMainMessage(evt: MessageEvent<MainToAggregator | PersistPortToAggregator | any>) {
    const data = evt.data;
    if (!data || typeof data !== 'object') return;
    switch (data.type) {
        case 'init': {
            const d = data as AggregatorInit;
            config = { ...config, ...d.config };
            persistPort = d.persistPort;
            persistPort.onmessage = (e: MessageEvent<PersistPortToAggregator>) => {
                const m = e.data;
                if (m && m.type === 'persistAck') {
                    const resolver = pendingAcks.get(m.requestId);
                    if (resolver) {
                        pendingAcks.delete(m.requestId);
                        pendingWrites = Math.max(0, pendingWrites - 1);
                        resolver();
                        maybeThrottleParsers();
                    }
                }
            };
            if (d.parserPorts && d.parserPorts.length) {
                for (const port of d.parserPorts) attachParserPort(port);
            }
            break;
        }
        case 'addParserPort': {
            attachParserPort((data as any).port as MessagePort);
            break;
        }
        case 'finalize': {
            (async () => {
                try {
                    await flushAll();
                    // Wait for all acks
                    await Promise.all(
                        Array.from(pendingAcks.values()).map(
                            (resolver) => new Promise<void>((resolve) => resolver && resolve())
                        )
                    );
                    const manifest: Manifest = makeManifest();
                    const msg: AggregatorManifestMessage = { type: 'manifest', manifest };
                    ctx.postMessage(msg);
                } catch (err: any) {
                    const emsg: ErrorMessage = { type: 'error', message: String(err?.message || err) };
                    ctx.postMessage(emsg);
                }
            })();
            break;
        }
    }
}

function attachParserPort(port: MessagePort) {
    parserPorts.push(port);
    port.onmessage = (evt: MessageEvent<ParserToAggregator>) => {
        const m = evt.data as any;
        if (!m) return;
        if (m.type === 'rowBatch') {
            handleRowBatch(m as RowBatchMessage);
        }
    };
}

ctx.onmessage = handleMainMessage as any;


