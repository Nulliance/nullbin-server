import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loadSodium } from '../src/sodium.ts';
import {
  NO_ACK,
  cleanChatFileName,
  encodeKey,
  newChain,
  newRecordId,
  sealMessage,
  validMessage,
  type Ack,
  type ChatFile,
  type MessageRecord,
} from '../src/room-crypto.ts';
import { expiryChoices, looksLikeImage, uploadRoomFile } from '../src/room-files.ts';
import { isProgramFile } from '../src/files.ts';
import { encodeInviteFragment } from '../src/link.ts';
import { qrcodegen } from '../vendor/qrcodegen.js';

const emptyAcks = (): Ack[] => Array.from({ length: 20 }, (_, slot) => ({ slot, gen: 0, index: 0, h: NO_ACK }));

test('validMessage accepts encrypted file attachments with or without caption text', async () => {
  const sodium = await loadSodium();
  const key = encodeKey(sodium, sodium.randombytes_buf(32));
  const id = newRecordId(sodium);
  const file: ChatFile = { id, key, name: 'photo.png', size: 12345 };

  const fileOnly: MessageRecord = {
    t: 'msg', id: newRecordId(sodium), time: Date.now(), prev: null, text: '', reply: null, seen: emptyAcks(), file,
  };
  assert.equal(validMessage(fileOnly), true);

  const withCaption: MessageRecord = {
    t: 'msg', id: newRecordId(sodium), time: Date.now(), prev: null, text: 'Here is the screenshot', reply: null, seen: emptyAcks(), file,
  };
  assert.equal(validMessage(withCaption), true);

  // Without a file, empty text is still rejected.
  const emptyNoFile = {
    t: 'msg', id: newRecordId(sodium), time: Date.now(), prev: null, text: '', reply: null, seen: emptyAcks(),
  };
  assert.equal(validMessage(emptyNoFile), false);
});

test('validMessage rejects malformed, path-traversal, hidden-char, or oversized file metadata', async () => {
  const sodium = await loadSodium();
  const validKey = encodeKey(sodium, sodium.randombytes_buf(32));
  const validId = newRecordId(sodium);
  const base = (file: unknown) => ({
    t: 'msg', id: newRecordId(sodium), time: Date.now(), prev: null, text: '', reply: null, seen: emptyAcks(), file,
  });

  const badCases: unknown[] = [
    null,
    'not-an-object',
    { id: 'short', key: validKey, name: 'a.txt', size: 10 },
    { id: validId, key: 'bad-key', name: 'a.txt', size: 10 },
    { id: validId, key: validKey, name: '../etc/passwd', size: 10 },
    { id: validId, key: validKey, name: '.hidden', size: 10 },
    { id: validId, key: validKey, name: 'a\u202Eb.txt', size: 10 }, // bidi override
    { id: validId, key: validKey, name: '', size: 10 },
    { id: validId, key: validKey, name: 'a'.repeat(256), size: 10 },
    { id: validId, key: validKey, name: 'a.txt', size: -1 },
    { id: validId, key: validKey, name: 'a.txt', size: 1.5 },
    { id: validId, key: validKey, name: 'a.txt', size: 3 * 1024 * 1024 * 1024 },
    { id: validId, key: validKey, name: 'a.txt', size: 10, extra: true },
  ];
  for (const bad of badCases) {
    assert.equal(validMessage(base(bad)), false, `should reject ${JSON.stringify(bad)}`);
  }
});

test('file attachment message seals and fits within room record bounds', async () => {
  const sodium = await loadSodium();
  const roomId = newRecordId(sodium);
  const sign = sodium.crypto_sign_keypair();
  const chain = newChain(sodium, 1);
  const file: ChatFile = {
    id: newRecordId(sodium),
    key: encodeKey(sodium, sodium.randombytes_buf(32)),
    name: 'report.pdf',
    size: 4096,
  };
  const msg: MessageRecord = {
    t: 'msg', id: newRecordId(sodium), time: Date.now(), prev: null, text: 'Attached', reply: null, seen: emptyAcks(), file,
  };
  const sealed = sealMessage(sodium, chain, roomId, 0, sign.privateKey, msg);
  assert.ok(sealed.length > 0 && sealed.length <= 16 * 1024);
});

test('expiryChoices offers only lifetimes that end before the chat does', () => {
  // Too little time left (or an unknown end) allows no attachment at all.
  assert.deepEqual(expiryChoices(0), []);
  assert.deepEqual(expiryChoices(300), []); // 5 minutes left: within the safety margin
  assert.deepEqual(expiryChoices(Number.NaN), []);
  assert.deepEqual(expiryChoices(-5), []);
  assert.deepEqual(expiryChoices(360), [300]);
  // A fresh 1-day chat can no longer get a 1-day file that outlives it.
  assert.deepEqual(expiryChoices(86400), [300, 1800, 3600, 10800, 43200]);
  assert.deepEqual(expiryChoices(86400 + 60), [300, 1800, 3600, 10800, 43200, 86400]);
  assert.deepEqual(expiryChoices(13 * 3600), [300, 1800, 3600, 10800, 43200]);
  assert.deepEqual(expiryChoices(9999999), [300, 1800, 3600, 10800, 43200, 86400, 259200, 604800]);
  // Every choice ends at least a minute before the chat.
  for (const left of [361, 3700, 50000, 86459, 700000]) {
    for (const c of expiryChoices(left)) assert.ok(c + 60 <= left, `${c}s choice with ${left}s left`);
  }
});

test('looksLikeImage only matches safe preview extensions within 25 MiB', () => {
  assert.equal(looksLikeImage('photo.png', 1024), true);
  assert.equal(looksLikeImage('photo.JPG', 1024), true);
  assert.equal(looksLikeImage('anim.webp', 1024), true);
  assert.equal(looksLikeImage('vector.svg', 1024), false);
  assert.equal(looksLikeImage('doc.pdf', 1024), false);
  assert.equal(looksLikeImage('huge.png', 30 * 1024 * 1024), false);
  assert.equal(looksLikeImage('empty.png', 0), false);
});

test('full Null Chat invite link encodes cleanly into a local QR code', async () => {
  const sodium = await loadSodium();
  const roomKey = sodium.randombytes_buf(32);
  const creatorKey = sodium.randombytes_buf(32);
  const secret = sodium.randombytes_buf(32);
  const token = encodeKey(sodium, sodium.randombytes_buf(32));
  const frag = encodeInviteFragment(sodium, roomKey, token, creatorKey, secret, 19, true);
  const url = `https://paste.example.com/r/${'a'.repeat(32)}#${frag}`;
  const qr = qrcodegen.QrCode.encodeText(url, qrcodegen.QrCode.Ecc.MEDIUM);
  assert.ok(qr.size > 20 && qr.size < 180);
});

test('cleanChatFileName strips PUA/surrogates and caps UTF-16 length so validMessage always accepts it', async () => {
  const sodium = await loadSodium();
  const key = encodeKey(sodium, sodium.randombytes_buf(32));
  const id = newRecordId(sodium);
  const hostileNames = [
    'mac\uF8FFscreenshot.png', // Private Use Area (Apple logo)
    '\u{1F600}'.repeat(150) + '.png', // 304 UTF-16 code units of astral emoji
    '../.secret\u202Etxt',
    '   ...   ',
  ];
  for (const raw of hostileNames) {
    const cleaned = cleanChatFileName(raw);
    assert.ok(cleaned.length > 0 && cleaned.length <= 255);
    const msg: MessageRecord = {
      t: 'msg', id: newRecordId(sodium), time: Date.now(), prev: null, text: '', reply: null, seen: emptyAcks(),
      file: { id, key, name: cleaned, size: 123 },
    };
    assert.equal(validMessage(msg), true, `cleaned name ${JSON.stringify(cleaned)} must pass validMessage`);
  }
});

test('an upload whose lifetime no longer ends before the chat is never finalized', async () => {
  const sodium = await loadSodium();
  const calls: string[] = [];
  const g = globalThis as { fetch: typeof fetch };
  const orig = g.fetch;
  g.fetch = (async (url: string, init: RequestInit) => {
    calls.push(`${init.method} ${url}`);
    if (init.method === 'POST' && url === '/api/v1/pastes') {
      return new Response(JSON.stringify({ id: 'a'.repeat(32), upload_token: 'A'.repeat(43), delete_token: 'B'.repeat(43) }), { status: 201, headers: { 'Content-Type': 'application/json' } });
    }
    if (init.method === 'PUT') return new Response(null, { status: 204 });
    return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
  }) as typeof fetch;
  try {
    const slow = new Error('too slow');
    await assert.rejects(
      uploadRoomFile(sodium, new File([new Uint8Array(1000)], 'x.bin'), 300, () => false, undefined, () => { throw slow; }),
      (e) => e === slow,
    );
    assert.ok(calls.some((c) => c.startsWith('PUT ')), 'the data was uploaded');
    assert.equal(calls.some((c) => c.endsWith('/finalize')), false, 'but never published');

    // When the check passes, the upload is finalized as usual.
    calls.length = 0;
    let checked = false;
    await uploadRoomFile(sodium, new File([new Uint8Array(10)], 'y.bin'), 300, () => false, undefined, () => { checked = true; });
    assert.ok(checked && calls.some((c) => c.endsWith('/finalize')));
  } finally {
    g.fetch = orig;
  }
});

test('programs are saved through the browser downloads, documents may go straight to disk', () => {
  // Audit A19: a save written through the save dialog may skip the marks and
  // checks the browser gives its own downloads.
  for (const n of ['setup.exe', 'SETUP.EXE', 'install.msi', 'run.bat', 'script.ps1', 'a.lnk', 'x.js', 'app.dmg', 'tool.sh', 'disk.iso', 'macro.docm', 'invoice.pdf.exe']) assert.ok(isProgramFile(n), n);
  for (const n of ['photo.png', 'report.pdf', 'notes.txt', 'data.csv', 'archive.zip', 'exe', 'my.exe.txt', 'readme']) assert.ok(!isProgramFile(n), n);
});
