import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fetchRecords } from '../src/api.ts';

const room = '0123456789abcdef0123456789abcdef';
const token = 'A'.repeat(43);
const record = (size: number) => ({ from: 0, data: Buffer.alloc(size).toString('base64') });

test('room reads enforce total record and per-batch byte limits', async () => {
  const original = globalThis.fetch;
  try {
    for (const [after, records] of [[1000, [record(41)]], [0, [record(16385)]], [0, Array.from({ length: 5 }, () => record(16384))]] as const) {
      globalThis.fetch = async () => new Response(JSON.stringify({ records, next: after + records.length, expires_in: 300 }));
      await assert.rejects(fetchRecords(room, token, after), Error);
    }
    for (const [after, records] of [[999, [record(16384)]], [0, Array.from({ length: 4 }, () => record(16384))], [1000, []]] as const) {
      globalThis.fetch = async () => new Response(JSON.stringify({ records, next: after + records.length, expires_in: 300 }));
      assert.equal((await fetchRecords(room, token, after)).next, after + records.length);
    }
  } finally {
    globalThis.fetch = original;
  }
});

test('a room read is complete only when the server could not have left records out', async () => {
  const original = globalThis.fetch;
  const read = async (records: readonly { from: number; data: string }[]) => {
    globalThis.fetch = async () => new Response(JSON.stringify({ records, next: records.length, expires_in: 300 }));
    return (await fetchRecords(room, token, 0)).complete;
  };
  try {
    assert.equal(await read([]), true);
    assert.equal(await read([record(41)]), true);
    // 48 KiB leaves room for one more record of the largest size (16 KiB).
    assert.equal(await read(Array.from({ length: 3 }, () => record(16384))), true);
    // Past that, the server may have stopped for bytes: read again.
    assert.equal(await read([...Array.from({ length: 3 }, () => record(16384)), record(41)]), false);
    assert.equal(await read(Array.from({ length: 4 }, () => record(16384))), false);
    // A full batch of 200 may have more behind it.
    assert.equal(await read(Array.from({ length: 199 }, () => record(41))), true);
    assert.equal(await read(Array.from({ length: 200 }, () => record(41))), false);
  } finally {
    globalThis.fetch = original;
  }
});

test('room reads cancel oversized streamed JSON before parsing it', async () => {
  const original = globalThis.fetch;
  let cancelled = false;
  let supplied = 0;
  try {
    globalThis.fetch = async () => new Response(new ReadableStream({
      pull(controller) {
        if (supplied === 0) controller.enqueue(new TextEncoder().encode('{"records":[],"next":0,"expires_in":300}'));
        else if (supplied < 1024 * 1024) controller.enqueue(new Uint8Array(8192).fill(32));
        else return controller.close();
        supplied += 8192;
      },
      cancel() { cancelled = true; },
    }));
    await assert.rejects(fetchRecords(room, token, 0), Error);
    assert.equal(cancelled, true);
    assert.ok(supplied < 1024 * 1024);
  } finally {
    globalThis.fetch = original;
  }
});
