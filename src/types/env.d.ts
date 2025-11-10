// Minimal ambient declarations for OPFS and workers

interface FileSystemDirectoryHandle {
    getDirectoryHandle(name: string, options?: { create?: boolean }): Promise<FileSystemDirectoryHandle>;
    getFileHandle(name: string, options?: { create?: boolean }): Promise<FileSystemFileHandle>;
    removeEntry(name: string, options?: { recursive?: boolean }): Promise<void>;
    // async iterator support (experimental in TS libs)
    // eslint-disable-next-line @typescript-eslint/ban-types
    entries(): AsyncIterableIterator<[string, FileSystemHandle]>;
}

interface FileSystemFileHandle {
    getFile(): Promise<File>;
    createWritable(options?: { keepExistingData?: boolean }): Promise<FileSystemWritableFileStream>;
}

interface FileSystemWritableFileStream extends WritableStream {
    write(data: BufferSource | Blob | string): Promise<void>;
    seek(position: number): Promise<void>;
    truncate(size: number): Promise<void>;
    close(): Promise<void>;
}

interface StorageManager {
    persist?(): Promise<boolean>;
    // OPFS root
    getDirectory?(): Promise<FileSystemDirectoryHandle>;
}

interface Navigator {
    storage: StorageManager;
}

// Workers
declare const importMeta: { url: string };

// Allow importing workers via new URL('./worker.ts', import.meta.url)
declare module '*?worker' { const value: any; export default value; }


