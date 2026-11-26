// Encrypted file & image sharing for Null Chat via the Paste bridge.
//
// Rooms stay strictly in memory and text-only on the server. When a member
// attaches a file, it is encrypted in the browser as a standard v2 paste
// (XChaCha20-Poly1305 secretstream + Padme padding, no burn, expiring with
// the room), and its paste ID + 256-bit key travel inside the member's
// end-to-end encrypted, signed chat message.
//
// Security invariants:
// - Never auto-fetch: downloads and image previews run only on explicit click.
// - Never trust chat-card metadata (name/size) for saving or rendering: use
//   only the authenticated paste metadata and magic-byte image inspection
//   (previewInfo: PNG, JPEG, GIF, WebP only — never SVG).
// - Wipe key material and decrypted buffers immediately after use or on abort.
// - Streaming File System Access saves commit only after TAG_FINAL verifies.

import { UPLOAD_CHUNK, createPaste, deletePaste, fetchPaste, finalizePaste, putChunk, rechunk } from './api.ts';
import { MAX_BUFFERED_DOWNLOAD } from './attachments.ts';
import { openPaste, preparePaste } from './crypto.ts';
import { downloadBlob } from './files.ts';
import { ByteReader, PasteError } from './format.ts';
import { MAX_PREVIEW_BYTES, previewInfo } from './image.ts';
import { cleanChatFileName, type ChatFile } from './room-crypto.ts';
import type { Sodium } from './sodium.ts';

interface SaveFilePickerWindow {
  showSaveFilePicker?: (options: { suggestedName?: string }) => Promise<FileSystemFileHandle>;
}

/** Valid paste expiry choices (seconds), matching the server's allowedExpiry up to 1 week (room max). */
const PASTE_EXPIRIES = [300, 1800, 3600, 10800, 43200, 86400, 259200, 604800];

/** Slack so request latency and clock drift never let a file outlive its chat. */
const EXPIRY_MARGIN_SECONDS = 60;

/**
 * The paste lifetimes a chat file may have: only those that end before the
 * chat does, shortest first. Empty when too little time is left (or the end
 * is unknown), in which case nothing may be attached.
 */
export function expiryChoices(remainingSeconds: number): number[] {
  const s = Math.floor(remainingSeconds) - EXPIRY_MARGIN_SECONDS;
  return PASTE_EXPIRIES.filter((choice) => choice <= s);
}

/** Human-readable label for a paste expiry from expiryChoices. */
export function expiryLabel(seconds: number): string {
  const labels: Record<number, string> = {
    300: '5 minutes',
    1800: '30 minutes',
    3600: '1 hour',
    10800: '3 hours',
    43200: '12 hours',
    86400: '1 day',
    259200: '3 days',
    604800: '1 week',
  };
  return labels[seconds] ?? '1 week';
}

/** Likely image by filename extension (display hint only; bytes decide on preview). */
const IMAGE_EXT = /\.(?:png|jpe?g|gif|webp)$/i;
export function looksLikeImage(name: string, size: number): boolean {
  return size > 0 && size <= MAX_PREVIEW_BYTES && IMAGE_EXT.test(name);
}

export interface UploadedRoomFile {
  file: ChatFile;
  deleteToken: string;
}

/**
 * Encrypts `file` as a standard v2 paste and uploads it. The returned
 * ChatFile contains the paste ID, 256-bit key, sanitized name and size.
 */
export async function uploadRoomFile(
  sodium: Sodium,
  file: File,
  expiresIn: number,
  isCancelled: () => boolean = () => false,
  onProgress?: (fraction: number) => void,
  /**
   * Runs just before the upload is finalized, and may throw to stop it. The
   * server starts the paste's lifetime at finalize, not at create, so a slow
   * upload must be checked again here: an unfinalized upload is never
   * published and the server drops it within PendingTTL.
   */
  beforeFinalize?: () => void,
): Promise<UploadedRoomFile> {
  const name = cleanChatFileName(file.name);
  const prepared = preparePaste(sodium, { text: '', file, filename: name, mime: file.type || 'application/octet-stream', password: '', discussion: false });
  const key = prepared.fragmentKey;
  let id: string;
  let deleteToken: string;
  let keyB64: string;
  try {
    if (isCancelled()) throw new PasteError('cancelled', 'Cancelled.');
    const created = await createPaste(expiresIn, false, prepared.totalSize, null, null, 1, null);
    id = created.id;
    deleteToken = created.deleteToken;
    let sent = 0;
    let index = 0;
    for await (const chunk of rechunk(prepared.chunks(), UPLOAD_CHUNK)) {
      if (isCancelled()) throw new PasteError('cancelled', 'Cancelled.');
      await putChunk(id, index++, created.uploadToken, chunk);
      sent += chunk.byteLength;
      onProgress?.(prepared.totalSize > 0 ? Math.min(1, sent / prepared.totalSize) : 1);
    }
    if (isCancelled()) throw new PasteError('cancelled', 'Cancelled.');
    beforeFinalize?.();
    await finalizePaste(id, created.uploadToken);
    if (isCancelled()) {
      void deletePaste(id, deleteToken).catch(() => {});
      throw new PasteError('cancelled', 'Cancelled.');
    }
    keyB64 = sodium.to_base64(key, sodium.base64_variants.URLSAFE_NO_PADDING);
  } finally {
    sodium.memzero(key);
  }
  return {
    file: { id, key: keyB64, name, size: file.size },
    deleteToken,
  };
}

/** Best-effort deletion of pastes uploaded by this tab when the room is self-destructed. */
export async function deleteUploadedRoomFiles(uploads: readonly { id: string; deleteToken: string }[]): Promise<void> {
  await Promise.allSettled(uploads.map((u) => deletePaste(u.id, u.deleteToken)));
}

function decodePasteKey(sodium: Sodium, b64: string): Uint8Array {
  let key: Uint8Array;
  try {
    key = sodium.from_base64(b64, sodium.base64_variants.URLSAFE_NO_PADDING);
  } catch {
    throw new PasteError('format', 'This file link is damaged.');
  }
  if (key.length !== 32) {
    sodium.memzero(key);
    throw new PasteError('format', 'This file link is damaged.');
  }
  return key;
}

/**
 * Downloads, authenticates, and saves a room attachment on explicit user click.
 * Uses File System Access streaming when available; otherwise buffers up to 64 MiB
 * and verifies completely before offering the download.
 */
export async function saveRoomFile(
  sodium: Sodium,
  file: ChatFile,
  isCancelled: () => boolean,
  onProgress?: (fraction: number) => void,
): Promise<void> {
  const key = decodePasteKey(sodium, file.key);
  let reader: ByteReader | null = null;
  let writable: FileSystemWritableFileStream | null = null;
  const chunks: Uint8Array<ArrayBuffer>[] = [];
  const picker = (window as unknown as SaveFilePickerWindow).showSaveFilePicker;
  // Ask for the save destination immediately inside the click gesture if available.
  let handle: FileSystemFileHandle | null = null;
  if (picker) {
    try {
      handle = await picker({ suggestedName: cleanChatFileName(file.name) });
    } catch (e) {
      sodium.memzero(key);
      if (e instanceof DOMException && e.name === 'AbortError') return;
      throw e;
    }
  }
  try {
    if (isCancelled()) throw new PasteError('cancelled', 'Cancelled.');
    const dl = await fetchPaste(file.id);
    if (isCancelled()) {
      await dl.body.cancel();
      throw new PasteError('cancelled', 'Cancelled.');
    }
    reader = new ByteReader(dl.body, (received) => {
      if (dl.size > 0) onProgress?.(Math.min(1, received / dl.size));
    });
    const opened = await openPaste(sodium, reader, key, async () => {
      throw new PasteError('format', 'Password-protected pastes can’t be opened as chat files.');
    });
    if (opened.discussion) sodium.memzero(opened.discussion.key);
    if (!opened.file) throw new PasteError('format', 'This paste does not contain a file.');
    // Verify that the authenticated paste metadata matches the signed chat card,
    // preventing filename or size bait-and-switch by a malicious member.
    const authName = cleanChatFileName(opened.meta.filename ?? 'file');
    if (authName !== file.name || opened.meta.size !== file.size) {
      throw new PasteError('tampered', 'This file’s metadata does not match the message.');
    }
    if (handle) {
      writable = await handle.createWritable();
      for await (const piece of opened.file) {
        if (isCancelled()) throw new PasteError('cancelled', 'Cancelled.');
        await writable.write(piece as Uint8Array<ArrayBuffer>);
      }
      if (isCancelled()) throw new PasteError('cancelled', 'Cancelled.');
      await writable.close();
      writable = null;
    } else {
      if (opened.meta.size > MAX_BUFFERED_DOWNLOAD) {
        throw new PasteError('too-large', 'This file is over 64 MiB. Open it in desktop Chrome or Edge to save large files.');
      }
      let total = 0;
      for await (const piece of opened.file) {
        if (isCancelled()) throw new PasteError('cancelled', 'Cancelled.');
        total += piece.byteLength;
        if (total > MAX_BUFFERED_DOWNLOAD) throw new PasteError('too-large', 'This file is over 64 MiB.');
        chunks.push(piece as Uint8Array<ArrayBuffer>);
      }
      if (isCancelled()) throw new PasteError('cancelled', 'Cancelled.');
      downloadBlob(new Blob(chunks, { type: 'application/octet-stream' }), authName);
    }
  } catch (e) {
    await writable?.abort().catch(() => {});
    throw e;
  } finally {
    sodium.memzero(key);
    for (const c of chunks) c.fill(0);
    chunks.length = 0;
    await reader?.cancel();
  }
}

/**
 * Downloads, authenticates, and validates an image attachment (PNG, JPEG, GIF,
 * WebP only, <= 25 MiB, <= 50 MP, <= 1000 frames) on explicit user click.
 * Returns a same-origin blob: URL and dimensions; caller must revoke the URL.
 */
export async function loadRoomImage(
  sodium: Sodium,
  file: ChatFile,
  isCancelled: () => boolean,
): Promise<{ url: string; width: number; height: number; name: string }> {
  const key = decodePasteKey(sodium, file.key);
  let reader: ByteReader | null = null;
  const chunks: Uint8Array<ArrayBuffer>[] = [];
  let bytes: Uint8Array<ArrayBuffer> | null = null;
  try {
    if (isCancelled()) throw new PasteError('cancelled', 'Cancelled.');
    const dl = await fetchPaste(file.id);
    if (isCancelled()) {
      await dl.body.cancel();
      throw new PasteError('cancelled', 'Cancelled.');
    }
    reader = new ByteReader(dl.body);
    const opened = await openPaste(sodium, reader, key, async () => {
      throw new PasteError('format', 'Password-protected pastes can’t be opened as chat files.');
    });
    if (opened.discussion) sodium.memzero(opened.discussion.key);
    if (!opened.file) throw new PasteError('format', 'This paste does not contain a file.');
    const authName = cleanChatFileName(opened.meta.filename ?? 'file');
    if (authName !== file.name || opened.meta.size !== file.size) {
      throw new PasteError('tampered', 'This file’s metadata does not match the message.');
    }
    if (opened.meta.size > MAX_PREVIEW_BYTES) {
      throw new PasteError('too-large', 'Images over 25 MiB can’t be previewed; use Save file instead.');
    }
    let total = 0;
    for await (const piece of opened.file) {
      if (isCancelled()) throw new PasteError('cancelled', 'Cancelled.');
      total += piece.byteLength;
      if (total > MAX_PREVIEW_BYTES) throw new PasteError('too-large', 'Images over 25 MiB can’t be previewed; use Save file instead.');
      chunks.push(piece as Uint8Array<ArrayBuffer>);
    }
    bytes = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      bytes.set(c, off);
      off += c.byteLength;
    }
    const info = previewInfo(bytes);
    if (!info) {
      throw new PasteError('format', 'This file can’t be shown as an image; use Save file instead.');
    }
    if (isCancelled()) throw new PasteError('cancelled', 'Cancelled.');
    const url = URL.createObjectURL(new Blob([bytes], { type: info.type }));
    return { url, width: info.width, height: info.height, name: authName };
  } finally {
    sodium.memzero(key);
    for (const c of chunks) c.fill(0);
    chunks.length = 0;
    bytes?.fill(0);
    await reader?.cancel();
  }
}
