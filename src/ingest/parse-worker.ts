/// <reference path="../types/env.d.ts" />
import type {
    ParseWorkerStart,
    ParseWorkerToMain,
    ParserToAggregator,
    AggregatorToParser,
    RowBatchMessage,
    ParseWorkerOptions,
    ErrorMessage,
} from './worker-messages';

const ctx: DedicatedWorkerGlobalScope = self as any;

let aggregatorPort: MessagePort | null = null;
let throttled = false;

ctx.onmessage = (evt: MessageEvent<ParseWorkerStart>) => {
    const data = evt.data;
    if (!data || data.type !== 'start') return;
    startParsing(data).catch((err) => reportError(err, data.fileIndex, data.file.name));
};

function reportProgress(msg: ParseWorkerToMain) {
    ctx.postMessage(msg);
}

function reportError(err: any, fileIndex?: number, fileName?: string, byteOffset?: number) {
    const emsg: ErrorMessage = {
        type: 'error',
        message: String(err?.message || err),
        fileIndex,
        fileName,
        byteOffset,
    };
    ctx.postMessage(emsg);
}

async function startParsing(cmd: ParseWorkerStart): Promise<void> {
    const { file, fileIndex, options, aggregatorPort: aPort } = cmd;
    aggregatorPort = aPort;
    aggregatorPort.onmessage = (e: MessageEvent<AggregatorToParser>) => {
        const m = e.data;
        if (!m) return;
        if (m.type === 'throttle') throttled = true;
        else if (m.type === 'resume') throttled = false;
    };
    aggregatorPort.start?.();
    // greet
    aggregatorPort.postMessage({ type: 'hello', fileIndex } as ParserToAggregator);

    const delimiter = options.delimiter ?? ',';
    const hasHeader = options.hasHeader ?? true;
    const batchPoints = options.batchPoints ?? 10_000;

    let headerCols: string[] | null = null;
    let rows = 0;
    let bytes = 0;
    let pendingBatches = 0;
    const MAX_OUTSTANDING = 8;

    // line splitting transform that handles CRLF and chunk boundaries
    const lineSplitter = new TransformStream<string, string>({
        start() {},
        transform(chunk, controller) {
            buffer += chunk;
            let idx: number;
            while ((idx = findLineBreak(buffer)) >= 0) {
                const line = buffer.slice(0, idx);
                controller.enqueue(line);
                buffer = stripLineBreak(buffer.slice(idx));
            }
        },
        flush(controller) {
            if (buffer.length) controller.enqueue(buffer);
        },
    });

    let buffer = '';
    function findLineBreak(s: string): number {
        const nIdx = s.indexOf('\n');
        const rIdx = s.indexOf('\r');
        if (nIdx === -1 && rIdx === -1) return -1;
        if (nIdx === -1) return rIdx;
        if (rIdx === -1) return nIdx;
        return Math.min(nIdx, rIdx);
    }
    function stripLineBreak(s: string): string {
        if (s.startsWith('\r\n')) return s.slice(2);
        if (s.startsWith('\n') || s.startsWith('\r')) return s.slice(1);
        return s;
    }

    const decoder = new TextDecoderStream();

    // batch staging
    let batch: number[] = [];

    const reader = file
        .stream()
        .pipeThrough(decoder)
        .pipeThrough(lineSplitter)
        .getReader();

    const textEncoder = new TextEncoder();
    // track bytes via encoded line lengths (approx); better: use stream byte chunks but TextDecoderStream hides it
    function addBytesFromLine(line: string) { bytes += textEncoder.encode(line).byteLength + 1; }

    // Resolve columns mapping once header is known
    function resolveIndices(cols: string[]): { tIdx: number; yIdx: number } {
        const tCol = options.timestampCol ?? 0;
        const yCol = options.valueCol ?? 1;
        let tIdx: number;
        let yIdx: number;
        if (typeof tCol === 'number') tIdx = tCol; else tIdx = cols.indexOf(tCol);
        if (typeof yCol === 'number') yIdx = yCol; else yIdx = cols.indexOf(yCol);
        if (tIdx < 0 || yIdx < 0) throw new Error('timestampCol/valueCol not found in header');
        return { tIdx, yIdx };
    }

    let indices: { tIdx: number; yIdx: number } | null = null;

    async function maybeFlushBatch(force = false) {
        if (batch.length >= batchPoints * 2 || (force && batch.length > 0)) {
            const f64 = new Float64Array(batch);
            batch = [];
            const msg: RowBatchMessage = { type: 'rowBatch', points: f64, fileIndex } as any;
            pendingBatches++;
            aggregatorPort!.postMessage(msg, [f64.buffer]);
            // basic in-worker backpressure: do not post beyond MAX_OUTSTANDING
            while (throttled || pendingBatches >= MAX_OUTSTANDING) {
                await sleep(10);
            }
            pendingBatches = Math.max(0, pendingBatches - 1);
        }
    }

    function sleep(ms: number) { return new Promise((r) => setTimeout(r, ms)); }

    try {
        let seenFirstLine = false;
        while (true) {
            const { value: line, done } = await reader.read();
            if (done) break;
            const s = (line as string).trim();
            if (!s) { addBytesFromLine(line as string); continue; }

            if (!seenFirstLine) {
                seenFirstLine = true;
                if (hasHeader) {
                    headerCols = parseCsvLine(s, delimiter);
                    indices = resolveIndices(headerCols);
                    addBytesFromLine(line as string);
                    continue;
                }
                // no header -> resolve indices against first line count
                const cols0 = parseCsvLine(s, delimiter);
                headerCols = headerCols || cols0.map((_, i) => String(i));
                indices = resolveIndices(headerCols);
                // fallthrough to parse the current line as data
                const rec = cols0;
                const t = parseTimestamp(rec[indices.tIdx]);
                const y = Number(rec[indices.yIdx]);
                if (Number.isFinite(t) && Number.isFinite(y)) {
                    batch.push(t, y);
                    rows++;
                }
                addBytesFromLine(line as string);
                await maybeFlushBatch();
                continue;
            }

            const cols = parseCsvLine(s, delimiter);
            const t = parseTimestamp(cols[indices!.tIdx]);
            const y = Number(cols[indices!.yIdx]);
            if (Number.isFinite(t) && Number.isFinite(y)) {
                batch.push(t, y);
                rows++;
            }
            addBytesFromLine(line as string);
            if ((rows & 0x3fff) === 0) { // progress every ~16k rows
                reportProgress({ type: 'progress', fileIndex, bytes, rows });
            }
            await maybeFlushBatch();
        }
        await maybeFlushBatch(true);
        reportProgress({ type: 'fileDone', fileIndex });
    } catch (err) {
        reportError(err, fileIndex, file.name);
    }
}

// Basic CSV parser with delimiter and quote handling (no escapes besides doubled quotes)
function parseCsvLine(line: string, delimiter: string): string[] {
    const out: string[] = [];
    let i = 0;
    const n = line.length;
    while (i < n) {
        let c = line[i];
        if (c === '"') {
            i++;
            let start = i;
            let val = '';
            while (i < n) {
                const ch = line[i];
                if (ch === '"') {
                    if (i + 1 < n && line[i + 1] === '"') { // escaped quote
                        val += line.slice(start, i) + '"';
                        i += 2; start = i; continue;
                    }
                    val += line.slice(start, i);
                    i++;
                    break;
                }
                i++;
            }
            // consume delimiter if present
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

function parseTimestamp(cell: string): number {
    // If numeric, assume ms since epoch; else Date.parse
    if (/^-?\d+(\.\d+)?$/.test(cell)) return Number(cell);
    const t = Date.parse(cell);
    return Number.isFinite(t) ? t : NaN;
}


