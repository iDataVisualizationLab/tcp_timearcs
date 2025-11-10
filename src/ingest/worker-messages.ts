// Message protocol definitions between parse workers, aggregator worker, and main thread.
// These types are shared across modules to ensure consistent communication contracts.

export const WORKER_PROTOCOL_VERSION = '1.0.0';

// Common
export interface ErrorMessage {
    type: 'error';
    message: string;
    fileIndex?: number;
    fileName?: string;
    byteOffset?: number;
}

// ===================== PARSE WORKER =====================

export interface ParseWorkerStart {
    type: 'start';
    fileIndex: number;
    fileName: string;
    // File is Transferable in postMessage; we only send the File for CSV/Arrow parsing
    file: File;
    options: ParseWorkerOptions;
    // Dedicated port to the aggregator for data batches and control/backpressure
    aggregatorPort: MessagePort;
}

export interface ParseWorkerOptions {
    delimiter?: string;                // default ','
    hasHeader?: boolean;               // default true
    timestampCol?: number | string;    // default 0
    valueCol?: number | string;        // default 1
    tileMs?: number;                   // provided for context (not used directly by parser)
    batchPoints?: number;              // default 10_000 points per batch
    rowMap?: undefined;                // placeholder: cannot send functions; if needed, main should map names->indices
}

export interface ParseWorkerProgress {
    type: 'progress';
    fileIndex: number;
    bytes: number;
    rows: number;
}

export interface ParseWorkerFileDone {
    type: 'fileDone';
    fileIndex: number;
}

export type ParseWorkerToMain = ParseWorkerProgress | ParseWorkerFileDone | ErrorMessage;

// Messages traveling on the aggregatorPort between a specific parse worker and the aggregator

export interface RowBatchMessage {
    type: 'rowBatch';
    // Packed as [t0, y0, t1, y1, ...]
    points: Float64Array;
    // optional for diagnostics
    fileIndex: number;
}

export interface ParserHelloMessage {
    type: 'hello';
    fileIndex: number;
}

export interface ParserThrottleControl {
    type: 'throttle' | 'resume';
}

export type ParserToAggregator = ParserHelloMessage | RowBatchMessage;
export type AggregatorToParser = ParserThrottleControl;

// ===================== AGGREGATOR WORKER =====================

export interface AggregatorInit {
    type: 'init';
    config: AggregatorConfig;
    // Port for persistence requests to main thread TileStore proxy
    persistPort: MessagePort;
    // One port per parse worker, paired by main using MessageChannel
    parserPorts?: MessagePort[]; // optional; aggregator can also receive ports later via addParserPort
}

export interface AggregatorAddParserPort {
    type: 'addParserPort';
    port: MessagePort;
}

export interface AggregatorConfig {
    tileMs: number;                 // default 60_000
    maxPointsPerFlush: number;      // default 50_000
    maxPendingWrites?: number;      // default 8
}

export interface AggregatorFinalize {
    type: 'finalize';
}

export interface AggregatorManifestMessage {
    type: 'manifest';
    manifest: Manifest;
}

export interface Manifest {
    tMin: number;
    tMax: number;
    yMin: number;
    yMax: number;
    count: number;
    tileMs: number;
    version: string;
}

export type MainToAggregator = AggregatorInit | AggregatorAddParserPort | AggregatorFinalize;
export type AggregatorToMain = AggregatorManifestMessage | ErrorMessage;

// ===================== PERSIST PORT (Aggregator <-> Main TileStore proxy) =====================

export interface PersistAppendRequest {
    type: 'persistAppend';
    requestId: number;
    tileId: number;
    payload: ArrayBuffer; // transfer ownership
}

export interface PersistAppendAck {
    type: 'persistAck';
    requestId: number;
}

export type PersistPortFromAggregator = PersistAppendRequest;
export type PersistPortToAggregator = PersistAppendAck;


