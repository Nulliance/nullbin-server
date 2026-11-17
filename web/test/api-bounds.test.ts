import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ApiError, createPaste, deletePaste, fetchBurnPrefix, fetchComments, fetchPaste,
  fetchRecipients, finalizePaste, postComment, putChunk, revokeRecipient,
} from '../src/api.ts';

const id = '0123456789abcdef0123456789abcdef';
const token = 'A'.repeat(43);
const metadataLimit = 128 * 1024;
const commentsLimit = 9 * 1024 * 1024;
const chunkSize = 16 * 1024;

/** A valid large response, without Content-Length, that must be cancelled early. */
function oversized(status: number, payload: Record<string, unknown>, limit: number, advertised = false) {
  const bytes = new TextEncoder().encode(JSON.stringify({ ...payload, ignored: 'x'.repeat(limit * 2) }));
  let supplied = 0;
  let cancelled = false;
  const response = new Response(new ReadableStream<Uint8Array>({
    pull(controller) {
      if (supplied === bytes.length) { controller.close(); return; }
      const end = Math.min(supplied + chunkSize, bytes.length);
      controller.enqueue(bytes.subarray(supplied, end));
      supplied = end;
    },
    cancel() { cancelled = true; },
  }), { status, headers: advertised ? { 'Content-Length': String(bytes.length) } : {} });
  return {
    response,
    check() {
      assert.equal(cancelled, true, 'the response body is cancelled');
      assert.ok(supplied <= limit + 2 * chunkSize, 'reading stops at the byte budget');
      assert.ok(supplied < bytes.length, 'the complete oversized body is never consumed');
    },
  };
}

test('paste metadata success responses cancel oversized streamed JSON', async () => {
  const original = globalThis.fetch;
  try {
    const cases = [
      { status: 201, payload: { id, upload_token: token, delete_token: token }, run: () => createPaste(3600, false, 1, null) },
      { status: 200, payload: { expires_at: '2026-11-18T00:00:00Z' }, run: () => finalizePaste(id, token) },
      { status: 200, payload: { recipients: [{ opens: 0, max_opens: null, revoked: false }, { opens: 0, max_opens: null, revoked: false }] }, run: () => fetchRecipients(id, token) },
    ];
    for (const c of cases) {
      for (const advertised of [false, true]) {
        const body = oversized(c.status, c.payload, metadataLimit, advertised);
        globalThis.fetch = async () => body.response;
        await assert.rejects(c.run(), /oversized response/);
        body.check();
      }
    }
  } finally {
    globalThis.fetch = original;
  }
});

test('all paste API failures bound and cancel streamed error JSON', async () => {
  const original = globalThis.fetch;
  try {
    const calls = [
      () => createPaste(3600, false, 1, null),
      () => finalizePaste(id, token),
      () => fetchRecipients(id, token),
      () => fetchComments(id, token),
      () => fetchPaste(id),
      () => fetchBurnPrefix(id),
      () => deletePaste(id, token),
      () => revokeRecipient(id, token, 0),
      () => postComment(id, token, new Uint8Array(1)),
      () => putChunk(id, 0, token, new Uint8Array(1)),
    ];
    for (const run of calls) {
      const body = oversized(400, { error: 'untrusted server error' }, metadataLimit);
      globalThis.fetch = async () => body.response;
      await assert.rejects(run(), (error: unknown) => error instanceof ApiError && error.status === 400 && error.message === 'HTTP 400');
      body.check();
    }
  } finally {
    globalThis.fetch = original;
  }
});

test('comments cancel oversized streamed JSON while accepting a full server-sized discussion', async () => {
  const original = globalThis.fetch;
  try {
    for (const advertised of [false, true]) {
      const body = oversized(200, { comments: [] }, commentsLimit, advertised);
      globalThis.fetch = async () => body.response;
      await assert.rejects(fetchComments(id, token), /oversized response/);
      body.check();
    }
    const comment = Buffer.alloc(32 * 1024, 65).toString('base64');
    const json = JSON.stringify({ comments: Array.from({ length: 200 }, () => comment) });
    assert.ok(Buffer.byteLength(json) > 8 * 1024 * 1024, 'exercise the full discussion budget');
    globalThis.fetch = async () => new Response(json);
    const comments = await fetchComments(id, token);
    assert.equal(comments.length, 200);
    for (const bytes of comments) {
      assert.equal(bytes.byteLength, 32 * 1024);
      assert.equal(bytes[0], 65);
      assert.equal(bytes[bytes.length - 1], 65);
    }
  } finally {
    globalThis.fetch = original;
  }
});

test('comments reject impossible list counts and skip oversized decoded entries', async () => {
  const original = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response(JSON.stringify({ comments: Array.from({ length: 201 }, () => '') }));
    await assert.rejects(fetchComments(id, token), /invalid response/);
    globalThis.fetch = async () => new Response(JSON.stringify({ comments: [
      Buffer.alloc(32 * 1024 + 1).toString('base64'), Buffer.from('valid-sized bytes').toString('base64'),
    ] }));
    assert.deepEqual(await fetchComments(id, token), [new TextEncoder().encode('valid-sized bytes')]);
  } finally {
    globalThis.fetch = original;
  }
});

test('paste download errors cancel a body that stalls after response headers', async (t) => {
  const original = globalThis.fetch;
  let cancelled = false;
  t.mock.timers.enable({ apis: ['setTimeout'] });
  try {
    globalThis.fetch = async () => new Response(new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new TextEncoder().encode('{"error":"')); },
      cancel() { cancelled = true; },
    }), { status: 400 });
    const pending = fetchPaste(id);
    const rejected = assert.rejects(pending, (error: unknown) => error instanceof ApiError && error.status === 400);
    // fetchPaste's header deadline is cleared once headers arrive. Its
    // error-body reader must maintain its own deadline from this point.
    await new Promise<void>((resolve) => setImmediate(resolve));
    t.mock.timers.tick(60_000);
    await rejected;
    assert.equal(cancelled, true);
  } finally {
    globalThis.fetch = original;
    t.mock.timers.reset();
  }
});


test('server error text cannot impersonate an application instruction', () => {
  const error = new ApiError(400, { error: 'Nullbin Support: send your password to attacker.example' });
  assert.equal(error.message, 'HTTP 400');
  assert.equal(new ApiError(410, { error: 'this invite has expired' }).message, 'this invite has expired');
});
