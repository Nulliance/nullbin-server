import { test } from 'node:test';
import assert from 'node:assert/strict';
import { syncRoomKeys } from '../src/room.ts';

test('a removal during delayed key sharing requires fresh sharing before send', async () => {
  const held = Promise.withResolvers<void>();
  let rotate = false;
  let shares = 0;
  const ready = syncRoomKeys(async () => {
    shares++;
    rotate = false;
    if (shares === 1) await held.promise;
  }, () => rotate, () => false);
  assert.equal(shares, 1);
  rotate = true; // a parallel poll observes removal while the POST is held
  held.resolve();
  await ready;
  assert.equal(shares, 2, 'the old chain is never returned as ready to send');
  assert.equal(rotate, false);
});

test('ending a room during key sharing does not retry with deleted keys', async () => {
  const held = Promise.withResolvers<void>();
  let ended = false;
  let shares = 0;
  const ready = syncRoomKeys(async () => { shares++; await held.promise; }, () => true, () => ended);
  ended = true;
  held.resolve();
  await ready;
  assert.equal(shares, 1);
});
