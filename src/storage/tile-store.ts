/*
  TileStore backends for persisting time-tiles to browser storage.
  - OPFSTileStore: Uses Origin Private File System (preferred)
  - IDBTileStore: Fallback using IndexedDB

  Each tile is stored as a concatenated Float64Array payload per tileId.
*/

export interface TileStore {
    init(): Promise<void>;
    clearAll(): Promise<void>;
    append(tileId: number, payload: ArrayBuffer): Promise<void>;
    readRange(tileStart: number, tileEnd: number): Promise<ArrayBuffer[]>;
    listAllTiles(): Promise<number[]>;
}

async function tryPersist(): Promise<void> {
    try {
        if (navigator.storage && 'persist' in navigator.storage) {
            await navigator.storage.persist();
        }
    } catch {
        // best-effort
    }
}

// ===================== OPFS BACKEND =====================

class OPFSTileStore implements TileStore {
    private root!: FileSystemDirectoryHandle;
    private tilesDir!: FileSystemDirectoryHandle;

    async init(): Promise<void> {
        await tryPersist();
        // @ts-ignore - getDirectory is still experimental in some TS libs
        this.root = await (navigator.storage as any).getDirectory();
        this.tilesDir = await this.ensureDir(this.root, 'tiles');
    }

    async clearAll(): Promise<void> {
        try {
            await this.root.removeEntry('tiles', { recursive: true } as any);
        } catch {
            // ignore if not present
        }
        this.tilesDir = await this.ensureDir(this.root, 'tiles');
    }

    async append(tileId: number, payload: ArrayBuffer): Promise<void> {
        const name = `${tileId}.f64`;
        const fileHandle = await this.tilesDir.getFileHandle(name, { create: true });
        const file = await fileHandle.getFile();
        const writable = await (fileHandle as any).createWritable({ keepExistingData: true });
        try {
            await writable.seek(file.size);
            await writable.write(new Uint8Array(payload));
        } finally {
            await writable.close();
        }
    }

    async readRange(tileStart: number, tileEnd: number): Promise<ArrayBuffer[]> {
        const results: ArrayBuffer[] = [];
        for (let tileId = tileStart; tileId <= tileEnd; tileId++) {
            const name = `${tileId}.f64`;
            try {
                const fh = await this.tilesDir.getFileHandle(name);
                const file = await fh.getFile();
                const buf = await file.arrayBuffer();
                results.push(buf);
            } catch {
                // missing tile - skip
            }
        }
        return results;
    }

    async listAllTiles(): Promise<number[]> {
        const out: number[] = [];
        // @ts-ignore - TS lib types for async iter may be missing
        for await (const [name] of (this.tilesDir as any).entries()) {
            if (name.endsWith('.f64')) {
                const idStr = name.slice(0, -4);
                const id = Number(idStr);
                if (Number.isFinite(id)) out.push(id);
            }
        }
        out.sort((a, b) => a - b);
        return out;
    }

    private async ensureDir(parent: FileSystemDirectoryHandle, name: string): Promise<FileSystemDirectoryHandle> {
        return await parent.getDirectoryHandle(name, { create: true });
    }
}

// ===================== INDEXEDDB BACKEND =====================

type IDBTileRecord = {
    tileId: number;
    chunks: ArrayBuffer[];
};

class IDBTileStore implements TileStore {
    private db!: IDBDatabase;
    private readonly dbName = 'tile-cache';
    private readonly storeName = 'tiles';

    async init(): Promise<void> {
        await tryPersist();
        this.db = await this.openDb();
    }

    async clearAll(): Promise<void> {
        await new Promise<void>((resolve, reject) => {
            const tx = this.db.transaction(this.storeName, 'readwrite');
            const store = tx.objectStore(this.storeName);
            const req = store.clear();
            req.onsuccess = () => resolve();
            req.onerror = () => reject(req.error || new Error('IDB clear error'));
        });
    }

    async append(tileId: number, payload: ArrayBuffer): Promise<void> {
        const existing = await this.get(tileId);
        const record: IDBTileRecord = existing || { tileId, chunks: [] };
        record.chunks.push(payload);
        await this.put(record);
    }

    async readRange(tileStart: number, tileEnd: number): Promise<ArrayBuffer[]> {
        const buffers: ArrayBuffer[] = [];
        for (let tileId = tileStart; tileId <= tileEnd; tileId++) {
            const rec = await this.get(tileId);
            if (!rec) continue;
            if (rec.chunks.length === 1) {
                buffers.push(rec.chunks[0]);
            } else {
                const total = rec.chunks.reduce((s, b) => s + b.byteLength, 0);
                const out = new Uint8Array(total);
                let offset = 0;
                for (const chunk of rec.chunks) {
                    out.set(new Uint8Array(chunk), offset);
                    offset += chunk.byteLength;
                }
                buffers.push(out.buffer);
            }
        }
        return buffers;
    }

    async listAllTiles(): Promise<number[]> {
        return new Promise<number[]>((resolve, reject) => {
            const tx = this.db.transaction(this.storeName, 'readonly');
            const store = tx.objectStore(this.storeName);
            const req = store.getAllKeys();
            req.onsuccess = () => {
                const keys = (req.result as any[]).map(Number).filter(Number.isFinite).sort((a, b) => a - b);
                resolve(keys);
            };
            req.onerror = () => reject(req.error || new Error('IDB listAllTiles error'));
        });
    }

    // ---- IDB helpers ----
    private openDb(): Promise<IDBDatabase> {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open(this.dbName, 1);
            req.onupgradeneeded = () => {
                const db = req.result;
                if (!db.objectStoreNames.contains(this.storeName)) {
                    db.createObjectStore(this.storeName, { keyPath: 'tileId' });
                }
            };
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error || new Error('IDB open error'));
        });
    }

    private get(tileId: number): Promise<IDBTileRecord | undefined> {
        return new Promise((resolve, reject) => {
            const tx = this.db.transaction(this.storeName, 'readonly');
            const store = tx.objectStore(this.storeName);
            const req = store.get(tileId);
            req.onsuccess = () => resolve(req.result as IDBTileRecord | undefined);
            req.onerror = () => reject(req.error || new Error('IDB get error'));
        });
    }

    private put(record: IDBTileRecord): Promise<void> {
        return new Promise((resolve, reject) => {
            const tx = this.db.transaction(this.storeName, 'readwrite');
            const store = tx.objectStore(this.storeName);
            const req = store.put(record);
            req.onsuccess = () => resolve();
            req.onerror = () => reject(req.error || new Error('IDB put error'));
        });
    }
}

// ===================== FACTORY =====================

export async function createTileStore(): Promise<TileStore> {
    const canUseOPFS = !!(navigator.storage && (navigator.storage as any).getDirectory);
    if (canUseOPFS) {
        const store = new OPFSTileStore();
        try {
            await store.init();
            return store;
        } catch (e) {
            console.warn('[TileStore] OPFS init failed, falling back to IndexedDB', e);
        }
    }
    const idb = new IDBTileStore();
    await idb.init();
    return idb;
}


